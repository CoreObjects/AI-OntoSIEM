"""CMDB 声明源加载器：User + owns 边的唯一合法来源（需求 §4.5 硬约束）。"""
from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest


def _write_cmdb(path: Path, body: str) -> None:
    path.write_text(dedent(body).strip(), encoding="utf-8")


def test_cmdb_loader_creates_users(tmp_path: Path) -> None:
    from graph.cmdb_loader import load_cmdb
    from graph.store import GraphStore

    cmdb = tmp_path / "cmdb.yaml"
    _write_cmdb(cmdb, """
        source: "cmdb"
        version: "1.0"
        declared_at: "2026-04-22T00:00:00Z"
        users:
          - user_id: "u1001"
            display_name: "Alice Chen"
            department: "Finance"
            accounts:
              - sid: "S-1-5-21-1-1001"
          - user_id: "u1002"
            display_name: "Bob Martinez"
            department: "IT"
            accounts:
              - sid: "S-1-5-21-1-1002"
    """)

    g = GraphStore(ontology_version="1.0")
    # 预先 upsert 被 own 的 Account（来自日志）
    g.upsert_entity("Account", "S-1-5-21-1-1001",
                    attrs={"sid": "S-1-5-21-1-1001"},
                    timestamp="2026-04-15T09:00:00Z", source="log")
    g.upsert_entity("Account", "S-1-5-21-1-1002",
                    attrs={"sid": "S-1-5-21-1-1002"},
                    timestamp="2026-04-15T09:00:00Z", source="log")

    stats = load_cmdb(cmdb, g)
    assert stats["users_created"] == 2
    assert stats["owns_created"] == 2
    assert g.has_node("User", "u1001")
    assert g.has_node("User", "u1002")


def test_cmdb_loader_user_meta_source_is_cmdb(tmp_path: Path) -> None:
    from graph.cmdb_loader import load_cmdb
    from graph.store import GraphStore

    cmdb = tmp_path / "cmdb.yaml"
    _write_cmdb(cmdb, """
        source: "cmdb"
        users:
          - user_id: "u1001"
            display_name: "Alice"
            accounts:
              - sid: "S-1-5-21-1-1001"
    """)
    g = GraphStore(ontology_version="1.0")
    g.upsert_entity("Account", "S-1-5-21-1-1001",
                    attrs={"sid": "S-1-5-21-1-1001"},
                    timestamp="2026-04-15T09:00:00Z", source="log")

    load_cmdb(cmdb, g)
    user = g.get_node("User", "u1001")
    assert user["meta"]["source"] == "cmdb"


def test_cmdb_loader_skips_owns_when_account_missing(tmp_path: Path) -> None:
    """CMDB 声明某 SID 但图里还没见过此 Account → 跳过 owns，计入 skipped。"""
    from graph.cmdb_loader import load_cmdb
    from graph.store import GraphStore

    cmdb = tmp_path / "cmdb.yaml"
    _write_cmdb(cmdb, """
        source: "cmdb"
        users:
          - user_id: "u9999"
            display_name: "Ghost User"
            accounts:
              - sid: "S-1-5-21-1-9999"
    """)
    g = GraphStore(ontology_version="1.0")
    stats = load_cmdb(cmdb, g)
    assert stats["users_created"] == 1
    assert stats["owns_created"] == 0
    assert stats["owns_skipped"] == 1


def test_cmdb_loader_idempotent(tmp_path: Path) -> None:
    """重复加载同一份 CMDB 声明不应报错，也不应重复计数。"""
    from graph.cmdb_loader import load_cmdb
    from graph.store import GraphStore

    cmdb = tmp_path / "cmdb.yaml"
    _write_cmdb(cmdb, """
        source: "cmdb"
        users:
          - user_id: "u1001"
            display_name: "Alice"
            accounts:
              - sid: "S-1-5-21-1-1001"
    """)
    g = GraphStore(ontology_version="1.0")
    g.upsert_entity("Account", "S-1-5-21-1-1001",
                    attrs={"sid": "S-1-5-21-1-1001"},
                    timestamp="2026-04-15T09:00:00Z", source="log")

    load_cmdb(cmdb, g)
    load_cmdb(cmdb, g)  # 二次加载
    assert g.edge_count() == 1  # owns 去重合并
    assert len(g.list_nodes_by_type("User")) == 1
