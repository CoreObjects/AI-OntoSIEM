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
    ap.add_argument("--limit", type=int, default=0, help="（已弃用，保留兼容）")
    ap.parse_args()

    for f in (ALERTS_DB, PARSED_DB, OLD_JUDGMENTS_DB):
        if not f.exists():
            print(f"ERROR: {f} not found. 先跑前置脚本。")
            return 1

    from evolution.pipeline_ops import rejudge_and_compare

    def _cb(i, n, a, j):
        v = f"{j.verdict} conf={j.confidence:.2f}" if j else "FAILED"
        gap = " [GAP]" if (j and j.semantic_gap) else ""
        print(f"  [{i}/{n}] {a.rule_id:40s} → {v}{gap}")

    print("[rejudge] 重建图 + 回放 + 重判（真调 LLM）...")
    report = rejudge_and_compare(progress_cb=_cb)  # 服务层：CLI 与 UI 共用

    print(f"\n=== ValidatorReport ===")
    print(f"  ontology  : v{report.ontology_version_before} → v{report.ontology_version_after}")
    print(f"  pool size : {report.pool_open_before} → {report.pool_open_after}  "
          f"(Δ {report.pool_delta})")
    print(f"  rejudged  : {report.rejudged_count}  "
          f"upgraded={report.verdict_upgraded}  "
          f"downgraded={report.verdict_downgraded}  "
          f"unchanged={report.verdict_unchanged}")
    print(f"  semantic_gap : cleared {report.semantic_gap_cleared} / "
          f"persisted {report.semantic_gap_persisted}")
    print(f"  evidence_refs avg : "
          f"{report.avg_evidence_refs_before:.2f} → {report.avg_evidence_refs_after:.2f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
