"""组件 10 Day 3：异常池回放脚本。

完整端到端：
  1) 重建知识图谱（从 parsed_events.duckdb + CMDB）
  2) 用升级后本体 v1.X + 现 parser 配置（含 generated/）
  3) ReplayEngine 跑过异常池里所有 backfilled=False 的记录
  4) 输出报告 JSON 到 data/replay_reports/<ts>.json
  5) 渲染回放后图谱 HTML

异常池规模 32 → 期望降到几条（仅留 5140/5145 等本轮没规则的）
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from core.ontology_service import get_service                 # noqa: E402
from evolution.replay_engine import ReplayEngine              # noqa: E402
from graph.cmdb_loader import load_cmdb                       # noqa: E402
from graph.importer import import_parsed_db                   # noqa: E402
from graph.store import GraphStore                            # noqa: E402
from graph.visualizer import render_html                      # noqa: E402
from parsers.windows_parser import (                          # noqa: E402
    GENERATED_MAPPINGS_DIR, MAPPINGS_DIR, ParserConfig,
)
from storage.anomaly_pool import AnomalyPool                  # noqa: E402

PARSED_DB = ROOT / "data" / "parsed_events.duckdb"
CMDB_FILE = ROOT / "ontology" / "cmdb.yaml"
REPORTS_DIR = ROOT / "data" / "replay_reports"
HTML_OUT = ROOT / "graph" / "visualization_replay.html"


def main() -> int:
    if not PARSED_DB.exists():
        print(f"ERROR: {PARSED_DB} not found. Run scripts/run_parser.py first.")
        return 1

    from core.ontology_service import get_service
    from evolution.pipeline_ops import replay_pool

    onto = get_service().get_current()
    print(f"[onto] v{onto.version}  nodes={len(onto.nodes)}  edges={len(onto.edges)}")
    if "ScheduledTask" not in onto.nodes:
        print("[WARN] 当前本体不含 ScheduledTask，回放对 4698/4702 不会有效果。"
              "先在 UI 演化页 approve ScheduledTask 提议。")

    print("\n[replay] 跑中（重建图 + 回放异常池）...")
    res = replay_pool()  # 服务层：CLI 与 UI 共用

    report = res.report
    print(f"\n=== ReplayReport ===")
    print(f"  attempted        : {report.attempted}")
    print(f"  backfilled       : {report.backfilled}  ({report.success_rate*100:.1f}%)")
    print(f"  failed           : {report.failed}")
    print(f"  ↳ 异常池规模 {res.pool_before} → {res.pool_after}  ★")
    print(f"  new_entities     : {report.new_entities}")
    print(f"  by_event_id:")
    for eid, st in sorted(report.by_event_id.items()):
        print(f"    {eid}: backfilled={st['backfilled']}  failed={st['failed']}")
    print(f"\n[graph] ScheduledTask 节点: {res.scheduledtask_count}")
    if res.html_path:
        print(f"[viz]    {res.html_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
