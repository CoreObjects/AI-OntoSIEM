"""pyvis 可视化 smoke test（Demo UI 用）。"""
from __future__ import annotations

from pathlib import Path


def test_visualizer_writes_html_file_with_node_labels(tmp_path: Path) -> None:
    from graph.store import GraphStore
    from graph.visualizer import render_html

    g = GraphStore(ontology_version="1.0")
    g.upsert_entity("Account", "S-1-5-21-1-1001",
                    attrs={"sid": "S-1-5-21-1-1001", "username": "alice"},
                    timestamp="2026-04-15T09:00:00Z", source="log")
    g.upsert_entity("Host", "HR-WS-01",
                    attrs={"hostname": "HR-WS-01"},
                    timestamp="2026-04-15T09:00:00Z", source="log")
    g.upsert_relation("logged_into",
                      "Account", "S-1-5-21-1-1001",
                      "Host", "HR-WS-01",
                      timestamp="2026-04-15T09:00:00Z", source="log",
                      attrs={"logon_type": "2"})

    out = tmp_path / "graph.html"
    render_html(g, out, title="Test Graph")

    assert out.exists()
    body = out.read_text(encoding="utf-8")
    # 基本健康检查：节点 id / 类型颜色 / 边类型都应出现在 HTML 中
    assert "S-1-5-21-1-1001" in body
    assert "HR-WS-01" in body
    assert "logged_into" in body


def test_visualizer_subgraph_scope(tmp_path: Path) -> None:
    """render_html 可接受 center 节点 + depth，限定渲染范围。"""
    from graph.store import GraphStore
    from graph.visualizer import render_html

    g = GraphStore(ontology_version="1.0")
    # 两个独立子图
    g.upsert_entity("Account", "A1", attrs={"sid": "A1"},
                    timestamp="2026-04-15T09:00:00Z", source="log")
    g.upsert_entity("Host", "H1", attrs={"hostname": "H1"},
                    timestamp="2026-04-15T09:00:00Z", source="log")
    g.upsert_relation("logged_into", "Account", "A1", "Host", "H1",
                      timestamp="2026-04-15T09:00:00Z", source="log")

    g.upsert_entity("Account", "A2", attrs={"sid": "A2"},
                    timestamp="2026-04-15T09:00:00Z", source="log")
    g.upsert_entity("Host", "H2", attrs={"hostname": "H2"},
                    timestamp="2026-04-15T09:00:00Z", source="log")
    g.upsert_relation("logged_into", "Account", "A2", "Host", "H2",
                      timestamp="2026-04-15T09:00:00Z", source="log")

    out = tmp_path / "subgraph.html"
    render_html(g, out, center=("Account", "A1"), depth=1)

    body = out.read_text(encoding="utf-8")
    assert "A1" in body and "H1" in body
    # 另一个子图不应出现
    assert "A2" not in body
