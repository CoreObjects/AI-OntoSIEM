"""运行认知研判：alerts.duckdb + 知识图谱 → LLM 研判 → judgments.duckdb。

运行前需要：
    python scripts/generate_demo_data.py   # events.duckdb
    python scripts/run_parser.py           # parsed_events.duckdb + anomaly_pool + signals
    python scripts/run_detection.py        # alerts.duckdb
    # .env 里配置 DASHSCOPE_API_KEY

用法：
    python scripts/run_judgments.py              # 跑全部告警
    python scripts/run_judgments.py --limit 3    # 仅跑前 3 条（省 token）
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import duckdb  # noqa: E402

from core.ontology_service import get_service  # noqa: E402
from detection.engine import Alert  # noqa: E402
from evolution.signal_hub import get_hub  # noqa: E402
from graph.cmdb_loader import load_cmdb  # noqa: E402
from graph.importer import import_parsed_db  # noqa: E402
from graph.store import GraphStore  # noqa: E402
from reasoning.judgment_engine import JudgmentEngine  # noqa: E402
from reasoning.llm_client import get_client  # noqa: E402
from storage.judgment_store import JudgmentStore  # noqa: E402

ALERTS_DB = ROOT / "data" / "alerts.duckdb"
PARSED_DB = ROOT / "data" / "parsed_events.duckdb"
CMDB_FILE = ROOT / "ontology" / "cmdb.yaml"
JUDGMENTS_DB = ROOT / "data" / "judgments.duckdb"


def _alert_from_row(r: dict) -> Alert:
    return Alert(
        alert_id=r["alert_id"],
        rule_id=r["rule_id"],
        rule_title=r["rule_title"],
        severity=r["severity"],
        event_record_id=int(r["event_record_id"] or 0),
        event_id=int(r["event_id"] or 0),
        channel=r["channel"] or "",
        computer=r["computer"] or "",
        timestamp=r["timestamp"] or "",
        attack_techniques=r["attack_techniques"] or [],
        matched_fields=r["matched_fields"] or {},
        ontology_version=r["ontology_version"] or "1.0",
        raw_event=r["raw_event"] or {},
    )


def _load_alerts(limit: int = 0) -> list[Alert]:
    con = duckdb.connect(str(ALERTS_DB), read_only=True)
    cols = ("alert_id, rule_id, rule_title, severity, event_record_id, event_id, "
            "channel, computer, timestamp, attack_techniques, matched_fields, "
            "ontology_version, raw_event")
    sql = f"SELECT {cols} FROM alerts ORDER BY timestamp"
    if limit > 0:
        sql += f" LIMIT {int(limit)}"
    rows = con.execute(sql).fetchall()
    con.close()

    def _load(v):
        if isinstance(v, str):
            try:
                return json.loads(v)
            except json.JSONDecodeError:
                return v
        return v

    alerts = []
    for r in rows:
        alerts.append(_alert_from_row({
            "alert_id": r[0], "rule_id": r[1], "rule_title": r[2], "severity": r[3],
            "event_record_id": r[4], "event_id": r[5], "channel": r[6], "computer": r[7],
            "timestamp": str(r[8]),
            "attack_techniques": _load(r[9]),
            "matched_fields": _load(r[10]),
            "ontology_version": r[11],
            "raw_event": _load(r[12]),
        }))
    return alerts


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0, help="最多研判多少条告警（0=全部）")
    args = ap.parse_args()

    for f in (ALERTS_DB, PARSED_DB):
        if not f.exists():
            print(f"ERROR: {f} not found. 先跑前置脚本。")
            return 1

    if JUDGMENTS_DB.exists():
        JUDGMENTS_DB.unlink()

    # 建图
    g = GraphStore(ontology_version="1.0")
    import_parsed_db(PARSED_DB, g)
    if CMDB_FILE.exists():
        load_cmdb(CMDB_FILE, g)
    print(f"[graph] nodes={g.node_count()}  edges={g.edge_count()}")

    # 加载告警
    alerts = _load_alerts(args.limit)
    print(f"[alerts] loaded {len(alerts)} alerts")

    # 引擎
    llm = get_client()
    onto = get_service().get_current()
    engine = JudgmentEngine(
        llm=llm, graph=g, signal_hub=get_hub(),
        ontology=onto, subgraph_depth=2,
    )
    store = JudgmentStore(db_path=JUDGMENTS_DB)

    stats = {"judged": 0, "review": 0, "semantic_gap": 0, "failures": 0}
    verdict_count: dict[str, int] = {}
    for i, alert in enumerate(alerts, 1):
        try:
            j = engine.judge(alert)
        except Exception as exc:
            print(f"  [{i}/{len(alerts)}] {alert.rule_id}  FAILED: {exc}")
            stats["failures"] += 1
            continue
        store.insert(j)
        stats["judged"] += 1
        if j.needs_review:
            stats["review"] += 1
        if j.semantic_gap:
            stats["semantic_gap"] += 1
        verdict_count[j.verdict] = verdict_count.get(j.verdict, 0) + 1
        print(f"  [{i}/{len(alerts)}] {alert.rule_id:40s} "
              f"→ {j.verdict:10s} conf={j.confidence:.2f} "
              f"evidence×{len(j.evidence_refs)} "
              f"{'[REVIEW]' if j.needs_review else ''} "
              f"{'[GAP]' if j.semantic_gap else ''}")

    print(f"\n[judgments] {stats}")
    print(f"[judgments] by verdict: {verdict_count}")
    print(f"[llm] usage: {llm.usage}")
    store.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
