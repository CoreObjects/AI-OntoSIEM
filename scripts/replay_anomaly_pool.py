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

    svc = get_service()
    onto = svc.get_current()
    print(f"[onto] v{onto.version}  nodes={len(onto.nodes)}  edges={len(onto.edges)}")
    if "ScheduledTask" not in onto.nodes:
        print("[WARN] 当前本体不含 ScheduledTask，回放对 4698/4702 不会有效果。"
              "运行 ui/evolution_review.py approve ScheduledTask 提议后再来。")

    cfg = ParserConfig.load_all([MAPPINGS_DIR, GENERATED_MAPPINGS_DIR])
    print(f"[parser] {len(cfg.rules)} 条规则（含 generated）")
    by_eid = {(r.event_id, r.channel): r.name for r in cfg.rules}
    for k, v in sorted(by_eid.items()):
        print(f"  {k}: {v}")

    # 1) 重建图（v1.X 上下文）
    g = GraphStore(ontology_version=onto.version)
    print("\n[graph] 重建初始图（来自 parsed_events.duckdb）...")
    stats = import_parsed_db(PARSED_DB, g)
    for k, v in stats.items():
        print(f"  {k:20s} {v}")
    if CMDB_FILE.exists():
        load_cmdb(CMDB_FILE, g)
    print(f"  → {g.node_count()} nodes / {g.edge_count()} edges (回放前)")

    # 2) 跑回放
    pool = AnomalyPool()
    print(f"\n[pool] open before: {pool.size_open()}  total: {pool.size_total()}")
    print(f"  by event_id (open):")
    for eid, n in sorted(pool.count_by_event_id().items(),
                         key=lambda kv: -kv[1]):
        print(f"    {eid}: {n}")

    eng = ReplayEngine(anomaly_pool=pool, parser_config=cfg,
                       ontology=onto, graph=g)
    print("\n[replay] 跑中...")
    report = eng.replay()

    # 3) 报告
    print(f"\n=== ReplayReport ===")
    print(f"  ontology_version : {report.ontology_version}")
    print(f"  attempted        : {report.attempted}")
    print(f"  backfilled       : {report.backfilled}  ({report.success_rate*100:.1f}%)")
    print(f"  failed           : {report.failed}")
    print(f"  pool open before : {report.total_open_before}")
    print(f"  pool open after  : {report.total_open_after}")
    print(f"  ↳ 异常池规模 {report.total_open_before} → {report.total_open_after}  ★")
    print(f"  new_entities     : {report.new_entities}")
    print(f"  merged_entities  : {report.merged_entities}")
    print(f"  new_relations    : {report.new_relations}")
    print(f"  by_event_id:")
    for eid, st in sorted(report.by_event_id.items()):
        print(f"    {eid}: backfilled={st['backfilled']}  failed={st['failed']}")

    # 4) 灌图后状态
    print(f"\n[graph] 回放后: {g.node_count()} nodes / {g.edge_count()} edges")
    sched = g.list_nodes_by_type("ScheduledTask")
    print(f"  ScheduledTask: {len(sched)}")
    for n in sched[:5]:
        a = n["attrs"]
        flag = "✓" if a.get("backfilled") else " "
        print(f"    [{flag}] {n['node_id']}  task_name={a.get('task_name','?')[:50]}")

    # 5) 落 JSON 报告 + HTML
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_path = REPORTS_DIR / f"replay_{ts}.json"
    report_path.write_text(
        json.dumps(report.to_dict(), ensure_ascii=False, indent=2,
                   default=str),
        encoding="utf-8",
    )
    print(f"\n[report] {report_path}")

    render_html(g, HTML_OUT,
                title=f"AI-OntoSIEM · 回放后图谱 v{onto.version}")
    print(f"[viz]    {HTML_OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
