"""从 parsed_events.duckdb 建知识图谱。

用法：
    python scripts/build_graph.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from graph.cmdb_loader import load_cmdb  # noqa: E402
from graph.importer import import_parsed_db  # noqa: E402
from graph.store import GraphStore  # noqa: E402
from graph.visualizer import render_html  # noqa: E402

PARSED_DB = ROOT / "data" / "parsed_events.duckdb"
CMDB_FILE = ROOT / "ontology" / "cmdb.yaml"
HTML_OUT = ROOT / "graph" / "visualization.html"
HTML_ATTACK = ROOT / "graph" / "visualization_attack.html"


def main() -> int:
    if not PARSED_DB.exists():
        print(f"ERROR: {PARSED_DB} not found. Run scripts/run_parser.py first.")
        return 1

    g = GraphStore(ontology_version="1.0")
    stats = import_parsed_db(PARSED_DB, g)

    print("[graph] import stats:")
    for k, v in stats.items():
        print(f"  {k:20s} {v}")
    print()

    if CMDB_FILE.exists():
        cmdb_stats = load_cmdb(CMDB_FILE, g)
        print("[cmdb] load stats:")
        for k, v in cmdb_stats.items():
            print(f"  {k:20s} {v}")
        print()
    print(f"[graph] final node count: {g.node_count()}")
    print(f"[graph] final edge count: {g.edge_count()}")
    print()
    print("[graph] nodes by type:")
    for t in ["User", "Account", "Host", "Process", "NetworkEndpoint"]:
        nodes = g.list_nodes_by_type(t)
        if nodes:
            print(f"  {t:20s} {len(nodes)}")

    # 打印 owns 关系验证 CMDB 声明生效
    print("\n[graph] owns declarations:")
    for u in g.list_nodes_by_type("User"):
        for e in g.out_edges("User", u["node_id"]):
            if e["edge_type"] == "owns":
                print(f"  {u['node_id']:8s} {u['attrs'].get('display_name','?'):30s} "
                      f"owns  {e['to_id']}")

    # 列出所有 Account（消歧后应为 6-8 个）
    print("\n[graph] all Accounts (post-dedup):")
    for a in g.list_nodes_by_type("Account"):
        print(f"  {a['node_id']:60s} "
              f"first_seen={a['meta']['first_seen']}  "
              f"last_seen={a['meta']['last_seen']}")

    # 渲染 HTML 可视化
    render_html(g, HTML_OUT, title="AI-OntoSIEM · Full Graph")
    print(f"\n[viz] full graph → {HTML_OUT}")
    render_html(g, HTML_ATTACK,
                title="Attack Focus: FIN-SRV-01 · 2 hops",
                center=("Host", "FIN-SRV-01"), depth=2)
    print(f"[viz] attack focus → {HTML_ATTACK}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
