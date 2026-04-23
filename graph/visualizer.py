"""知识图谱 HTML 可视化（pyvis + NetworkX）。

用法：
    from graph.visualizer import render_html
    render_html(store, "graph.html", title="...", center=("Host","FIN-SRV-01"), depth=2)
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional, Tuple

from pyvis.network import Network

from graph.store import GraphStore


# 节点类型 → 颜色（Demo 一眼区分）
NODE_COLOR = {
    "User":            "#7B3F00",  # 棕（声明）
    "Account":         "#1F77B4",  # 蓝（日志账户）
    "Host":            "#2CA02C",  # 绿
    "Process":         "#D62728",  # 红
    "NetworkEndpoint": "#9467BD",  # 紫
}

EDGE_COLOR = {
    "owns":             "#7B3F00",
    "authenticated_as": "#4F81BD",
    "logged_into":      "#1F77B4",
    "spawned":          "#D62728",
    "executed_on":      "#2CA02C",
    "connected_to":     "#9467BD",
    "schedules":        "#FF8C00",
}


def _label(view: dict) -> str:
    """节点显示标签：简短，偏重类型+主键后缀。"""
    nid = view["node_id"]
    if len(nid) > 30:
        nid = "..." + nid[-28:]
    return f"{view['node_type']}\n{nid}"


def _title(view: dict) -> str:
    """hover tooltip：HTML 格式，展示 attrs + meta。"""
    parts = [f"<b>{view['node_type']}: {view['node_id']}</b>"]
    if view.get("attrs"):
        parts.append("<b>attrs:</b>")
        for k, v in view["attrs"].items():
            parts.append(f"  {k} = {v}")
    if view.get("meta"):
        parts.append("<b>meta:</b>")
        for k in ("first_seen", "last_seen", "confidence", "source", "ontology_version"):
            if k in view["meta"]:
                parts.append(f"  {k} = {view['meta'][k]}")
    return "\n".join(str(p) for p in parts)


def render_html(
    store: GraphStore,
    output_path: Path,
    *,
    title: str = "Knowledge Graph",
    center: Optional[Tuple[str, str]] = None,
    depth: int = 1,
    height: str = "800px",
    width: str = "100%",
) -> Path:
    """渲染图到 HTML。center=None 渲染全图；否则渲染 N 跳子图。"""
    if center is not None:
        view = store.subgraph_around(center[0], center[1], depth=depth)
        nodes = view["nodes"]
        edges = view["edges"]
    else:
        nodes = []
        edges = []
        for t in ["User", "Account", "Host", "Process", "NetworkEndpoint"]:
            nodes.extend(store.list_nodes_by_type(t))
        # 所有边
        for n in nodes:
            for e in store.out_edges(n["node_type"], n["node_id"]):
                edges.append(e)

    net = Network(height=height, width=width, directed=True,
                  notebook=False, cdn_resources="remote", heading=title)
    net.barnes_hut(
        gravity=-12000, central_gravity=0.15,
        spring_length=120, spring_strength=0.02, damping=0.4,
    )

    node_keys_added = set()
    for v in nodes:
        key = f"{v['node_type']}:{v['node_id']}"
        if key in node_keys_added:
            continue
        node_keys_added.add(key)
        net.add_node(
            key,
            label=_label(v),
            title=_title(v),
            color=NODE_COLOR.get(v["node_type"], "#888"),
            shape="dot",
            size=18 if v["node_type"] in ("User", "Host") else 12,
        )

    for e in edges:
        fkey = f"{e['from_type']}:{e['from_id']}"
        tkey = f"{e['to_type']}:{e['to_id']}"
        if fkey not in node_keys_added or tkey not in node_keys_added:
            continue
        net.add_edge(
            fkey, tkey,
            title=f"{e['edge_type']}\nattrs={json.dumps(e['attrs'], ensure_ascii=False)}\n"
                  f"last_seen={e['meta'].get('last_seen')}",
            color=EDGE_COLOR.get(e["edge_type"], "#AAA"),
            label=e["edge_type"],
            arrows="to",
        )

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    # pyvis 的 write_html 写入文件
    net.write_html(str(output_path), notebook=False, open_browser=False)
    return Path(output_path)
