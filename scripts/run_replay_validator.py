"""组件 10 Day 4：演化前/后对比报告（含真调 LLM 重判）。

完整端到端：
  1) 读 v1.0 时代的老 judgments（data/judgments.duckdb）
  2) 重建图 + 跑 replay（图谱含 ScheduledTask 节点，异常池 32→10）
  3) 用 v1.1 本体 + 升级后图 重判所有 alerts
  4) 老/新 judgments 做 compare_judgments → ValidatorReport
  5) 落 JSON 报告 `data/replay_reports/validator_<ts>.json`
  6) 重判结果写入 `data/judgments_after_replay.duckdb`（与 v1.0 对照保留）

成本：~10 alerts × ~6.5K tokens = 65K tokens
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import duckdb  # noqa: E402

from core.ontology_service import get_service               # noqa: E402
from detection.engine import Alert                          # noqa: E402
from evolution.replay_engine import ReplayEngine            # noqa: E402
from evolution.replay_validator import (                    # noqa: E402
    compare_judgments, rejudge_alerts,
)
from evolution.signal_hub import get_hub                    # noqa: E402
from graph.cmdb_loader import load_cmdb                     # noqa: E402
from graph.importer import import_parsed_db                 # noqa: E402
from graph.store import GraphStore                          # noqa: E402
from parsers.windows_parser import (                        # noqa: E402
    GENERATED_MAPPINGS_DIR, MAPPINGS_DIR, ParserConfig,
)
from reasoning.judgment_engine import JudgmentEngine        # noqa: E402
from reasoning.llm_client import get_client                 # noqa: E402
from storage.anomaly_pool import AnomalyPool                # noqa: E402
from storage.judgment_store import JudgmentStore            # noqa: E402

ALERTS_DB = ROOT / "data" / "alerts.duckdb"
PARSED_DB = ROOT / "data" / "parsed_events.duckdb"
CMDB_FILE = ROOT / "ontology" / "cmdb.yaml"
OLD_JUDGMENTS_DB = ROOT / "data" / "judgments.duckdb"
NEW_JUDGMENTS_DB = ROOT / "data" / "judgments_after_replay.duckdb"
REPORTS_DIR = ROOT / "data" / "replay_reports"


def _load_alerts(limit: int = 0):
    con = duckdb.connect(str(ALERTS_DB), read_only=True)
    cols = ("alert_id, rule_id, rule_title, severity, event_record_id, event_id, "
            "channel, computer, timestamp, attack_techniques, matched_fields, "
            "ontology_version, raw_event")
    sql = f"SELECT {cols} FROM alerts ORDER BY timestamp"
    if limit > 0:
        sql += f" LIMIT {int(limit)}"
    rows = con.execute(sql).fetchall()
    con.close()

    def _l(v):
        if isinstance(v, str):
            try:
                return json.loads(v)
            except json.JSONDecodeError:
                return v
        return v

    return [
        Alert(
            alert_id=r[0], rule_id=r[1], rule_title=r[2], severity=r[3],
            event_record_id=int(r[4] or 0), event_id=int(r[5] or 0),
            channel=r[6] or "", computer=r[7] or "", timestamp=str(r[8]),
            attack_techniques=_l(r[9]) or [], matched_fields=_l(r[10]) or {},
            ontology_version=r[11] or "1.0", raw_event=_l(r[12]) or {},
        )
        for r in rows
    ]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0,
                    help="最多重判多少条（0=全部）")
    args = ap.parse_args()

    for f in (ALERTS_DB, PARSED_DB, OLD_JUDGMENTS_DB):
        if not f.exists():
            print(f"ERROR: {f} not found. 先跑前置脚本。")
            return 1

    # 1. 加载老 judgments（v1.0 时代）
    old_store = JudgmentStore(db_path=OLD_JUDGMENTS_DB)
    old_judgments = old_store.list_recent(limit=1000)
    old_store.close()
    old_v = old_judgments[0]["ontology_version"] if old_judgments else "1.0"
    print(f"[before] {len(old_judgments)} 老 judgments （v{old_v}）")

    # 2. 升级后本体 + 现 parser 配置（含 generated/）
    svc = get_service()
    onto = svc.get_current()
    cfg = ParserConfig.load_all([MAPPINGS_DIR, GENERATED_MAPPINGS_DIR])
    print(f"[onto] v{onto.version}  nodes={len(onto.nodes)}  edges={len(onto.edges)}")
    print(f"[parser] {len(cfg.rules)} 规则")

    # 3. 重建图 + replay（图谱含 ScheduledTask 节点）
    g = GraphStore(ontology_version=onto.version)
    import_parsed_db(PARSED_DB, g)
    if CMDB_FILE.exists():
        load_cmdb(CMDB_FILE, g)
    print(f"[graph] 初始: {g.node_count()} nodes / {g.edge_count()} edges")

    pool = AnomalyPool()
    # Demo 重跑保护：若昨天已 backfilled 则重置（保证图能拿到 ScheduledTask）
    if pool.size_open() < pool.size_total():
        n = pool.reset_backfilled()
        print(f"[pool] 重置 backfilled 标志（{n} 条全部翻 open）")
    pool_before = pool.size_open()
    eng_replay = ReplayEngine(anomaly_pool=pool, parser_config=cfg,
                              ontology=onto, graph=g)
    rep_replay = eng_replay.replay()
    pool_after = rep_replay.total_open_after
    print(f"[replay] 异常池 {pool_before} → {pool_after}; "
          f"灌图 +{rep_replay.new_entities} new entities")
    print(f"[graph] 回放后: {g.node_count()} nodes / {g.edge_count()} edges")

    # 4. 加载 alerts，重判
    alerts = _load_alerts(args.limit)
    print(f"\n[alerts] {len(alerts)} 条待重判（真调 LLM，约 ~{6500*len(alerts)} tokens）")

    llm = get_client()
    judge_engine = JudgmentEngine(
        llm=llm, graph=g, signal_hub=get_hub(),
        ontology=onto, subgraph_depth=2,
    )
    new_judgments = []
    for i, a in enumerate(alerts, 1):
        try:
            j = judge_engine.judge(a)
            new_judgments.append(j)
            tag = []
            if j.semantic_gap:
                tag.append("[GAP]")
            if j.needs_review:
                tag.append("[REVIEW]")
            print(f"  [{i}/{len(alerts)}] {a.rule_id:40s} "
                  f"→ {j.verdict:10s} conf={j.confidence:.2f} "
                  f"evidence×{len(j.evidence_refs)} {' '.join(tag)}")
        except Exception as exc:
            print(f"  [{i}/{len(alerts)}] {a.rule_id} FAILED: {exc}")

    # 5. 持久化重判结果（v1.1 时代的 after judgments）
    if NEW_JUDGMENTS_DB.exists():
        NEW_JUDGMENTS_DB.unlink()
    new_store = JudgmentStore(db_path=NEW_JUDGMENTS_DB)
    new_store.insert_many(new_judgments)
    new_store.close()
    print(f"\n[after-judgments] 写入 {NEW_JUDGMENTS_DB.name}：{len(new_judgments)} 条")

    # 6. diff
    report = compare_judgments(
        before=old_judgments,
        after=new_judgments,
        pool_open_before=pool_before,
        pool_open_after=pool_after,
        ontology_version_before=old_v,
        ontology_version_after=onto.version,
    )

    print(f"\n=== ValidatorReport ===")
    print(f"  ontology  : v{report.ontology_version_before} → v{report.ontology_version_after}")
    print(f"  pool size : {report.pool_open_before} → {report.pool_open_after}  "
          f"(Δ {report.pool_delta})")
    print(f"  rejudged  : {report.rejudged_count}")
    print(f"    upgraded   : {report.verdict_upgraded}")
    print(f"    downgraded : {report.verdict_downgraded}")
    print(f"    unchanged  : {report.verdict_unchanged}")
    print(f"  semantic_gap : cleared {report.semantic_gap_cleared} / "
          f"persisted {report.semantic_gap_persisted}")
    print(f"  evidence_refs avg : "
          f"{report.avg_evidence_refs_before:.2f} → {report.avg_evidence_refs_after:.2f}")

    # 详细变更
    print(f"\n  详细变更（{len(report.verdict_changes)}）:")
    for c in report.verdict_changes:
        flag = ""
        if c.delta == "upgraded":
            flag = "↑↑"
        elif c.delta == "downgraded":
            flag = "↓↓"
        elif c.delta == "unchanged":
            flag = "  "
        gap_flag = " [GAP-CLEARED]" if c.semantic_gap_cleared else ""
        print(f"    {flag} {c.alert_id[:8]}  "
              f"{c.before_verdict}({c.before_confidence:.2f}) → "
              f"{c.after_verdict}({c.after_confidence:.2f})  "
              f"refs {c.before_evidence_count}→{c.after_evidence_count}"
              f"{gap_flag}")
        if c.new_graph_node_refs:
            for ref in c.new_graph_node_refs:
                print(f"        + new ref: {ref}")

    # 7. 落 JSON
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = REPORTS_DIR / f"validator_{ts}.json"
    out.write_text(
        json.dumps(report.to_dict(), ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )
    print(f"\n[report] {out}")

    print(f"\n[llm] usage: calls={llm.usage.calls} "
          f"prompt={llm.usage.prompt_tokens} "
          f"completion={llm.usage.completion_tokens} "
          f"total={llm.usage.total_tokens}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
