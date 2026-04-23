"""从 parsed_events.duckdb 导入实体 + 关系到 GraphStore。"""
from __future__ import annotations

import json
from pathlib import Path

import duckdb
import pytest


def _init_parsed_db(db_path: Path) -> None:
    con = duckdb.connect(str(db_path))
    con.execute("""
        CREATE TABLE entities (
            record_id        BIGINT,
            node_type        VARCHAR,
            node_id          VARCHAR,
            ref_key          VARCHAR,
            attrs            JSON,
            meta             JSON,
            timestamp        TIMESTAMP,
            ontology_version VARCHAR
        )
    """)
    con.execute("""
        CREATE TABLE relations (
            record_id        BIGINT,
            edge_type        VARCHAR,
            from_type        VARCHAR,
            from_id          VARCHAR,
            to_type          VARCHAR,
            to_id            VARCHAR,
            attrs            JSON,
            timestamp        TIMESTAMP,
            ontology_version VARCHAR
        )
    """)
    con.close()


def _insert_entity(con, record_id, node_type, node_id, attrs, ts,
                   source="log", confidence=1.0) -> None:
    meta = {"source": source, "confidence": confidence}
    con.execute(
        "INSERT INTO entities VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [record_id, node_type, node_id, node_type,
         json.dumps(attrs), json.dumps(meta), ts, "1.0"],
    )


def _insert_relation(con, record_id, edge_type, from_type, from_id, to_type, to_id,
                     attrs, ts) -> None:
    con.execute(
        "INSERT INTO relations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [record_id, edge_type, from_type, from_id, to_type, to_id,
         json.dumps(attrs), ts, "1.0"],
    )


def test_importer_loads_entities_and_merges(tmp_path: Path) -> None:
    """同 SID 多次出现 → 合并为一个 Account 节点。"""
    from graph.importer import import_parsed_db
    from graph.store import GraphStore

    db = tmp_path / "parsed.duckdb"
    _init_parsed_db(db)
    con = duckdb.connect(str(db))
    # svc_sccm 出现 3 次（不同时间），1 个 Host
    for i, day in enumerate(["2026-04-15", "2026-04-16", "2026-04-17"]):
        _insert_entity(con, i + 1, "Account", "S-1-5-21-1-2002",
                       {"sid": "S-1-5-21-1-2002", "domain": "CORP", "username": "svc_sccm"},
                       f"{day} 09:00:00")
    _insert_entity(con, 10, "Host", "HR-WS-01", {"hostname": "HR-WS-01"},
                   "2026-04-15 09:00:00")
    con.close()

    g = GraphStore(ontology_version="1.0")
    stats = import_parsed_db(db, g)

    assert g.node_count() == 2  # 1 Account (合并) + 1 Host
    assert stats["entities_read"] == 4
    assert stats["entities_merged"] == 2  # 3 Account 合并成 1 = 2 次 merge

    node = g.get_node("Account", "S-1-5-21-1-2002")
    assert node["meta"]["first_seen"].startswith("2026-04-15")
    assert node["meta"]["last_seen"].startswith("2026-04-17")


def test_importer_loads_relations(tmp_path: Path) -> None:
    from graph.importer import import_parsed_db
    from graph.store import GraphStore

    db = tmp_path / "parsed.duckdb"
    _init_parsed_db(db)
    con = duckdb.connect(str(db))
    _insert_entity(con, 1, "Account", "S-1-5-21-1-2002",
                   {"sid": "S-1-5-21-1-2002"}, "2026-04-15 09:00:00")
    _insert_entity(con, 1, "Host", "HR-WS-01",
                   {"hostname": "HR-WS-01"}, "2026-04-15 09:00:00")
    _insert_relation(con, 1, "logged_into",
                     "Account", "S-1-5-21-1-2002",
                     "Host", "HR-WS-01",
                     {"logon_type": "3"}, "2026-04-15 09:00:00")
    _insert_relation(con, 2, "logged_into",
                     "Account", "S-1-5-21-1-2002",
                     "Host", "HR-WS-01",
                     {"logon_type": "3"}, "2026-04-16 09:00:00")
    con.close()

    g = GraphStore(ontology_version="1.0")
    stats = import_parsed_db(db, g)

    assert g.edge_count() == 1  # 两次 logged_into 合并
    assert stats["relations_read"] == 2
    out = g.out_edges("Account", "S-1-5-21-1-2002")
    assert out[0]["attrs"]["logon_type"] == "3"


def test_importer_skips_relation_with_missing_endpoint(tmp_path: Path) -> None:
    """关系端点在图里不存在时，不应 crash，而是计入 skipped。"""
    from graph.importer import import_parsed_db
    from graph.store import GraphStore

    db = tmp_path / "parsed.duckdb"
    _init_parsed_db(db)
    con = duckdb.connect(str(db))
    _insert_entity(con, 1, "Account", "S-1-5-21-1-2002",
                   {"sid": "S-1-5-21-1-2002"}, "2026-04-15 09:00:00")
    # Host 没入库，关系的 to 端缺失
    _insert_relation(con, 1, "logged_into",
                     "Account", "S-1-5-21-1-2002",
                     "Host", "MISSING-HOST",
                     {}, "2026-04-15 09:00:00")
    con.close()

    g = GraphStore(ontology_version="1.0")
    stats = import_parsed_db(db, g)
    assert g.edge_count() == 0
    assert stats["relations_skipped"] == 1


def test_importer_normalizes_account_id_via_resolver(tmp_path: Path) -> None:
    """parser 给 node_id='alice'（只有 username），importer 应按 resolver 规范化为 '?\\alice'。"""
    from graph.importer import import_parsed_db
    from graph.store import GraphStore

    db = tmp_path / "parsed.duckdb"
    _init_parsed_db(db)
    con = duckdb.connect(str(db))
    _insert_entity(con, 1, "Account", "alice",
                   {"username": "alice"}, "2026-04-15 09:00:00")
    _insert_entity(con, 2, "Account", "alice",
                   {"username": "alice"}, "2026-04-16 09:00:00")
    con.close()

    g = GraphStore(ontology_version="1.0")
    import_parsed_db(db, g)

    # 原始 node_id 不应存在；规范化后的 canonical_id 才是真 key
    assert not g.has_node("Account", "alice")
    assert g.has_node("Account", "?\\alice")
    node = g.get_node("Account", "?\\alice")
    # weak match → confidence < 0.8
    assert node["meta"]["confidence"] < 0.8


def test_importer_sid_present_takes_precedence(tmp_path: Path) -> None:
    """attrs 含 sid → canonical 用 SID，不管 parser 给啥 node_id。"""
    from graph.importer import import_parsed_db
    from graph.store import GraphStore

    db = tmp_path / "parsed.duckdb"
    _init_parsed_db(db)
    con = duckdb.connect(str(db))
    _insert_entity(con, 1, "Account", "whatever-parser-said",
                   {"sid": "S-1-5-21-1-1001", "domain": "CORP", "username": "alice"},
                   "2026-04-15 09:00:00")
    con.close()

    g = GraphStore(ontology_version="1.0")
    import_parsed_db(db, g)

    assert g.has_node("Account", "S-1-5-21-1-1001")
    assert not g.has_node("Account", "whatever-parser-said")


def test_importer_relation_endpoints_follow_canonical(tmp_path: Path) -> None:
    """关系的 from_id/to_id 也要按 canonical 映射。"""
    from graph.importer import import_parsed_db
    from graph.store import GraphStore

    db = tmp_path / "parsed.duckdb"
    _init_parsed_db(db)
    con = duckdb.connect(str(db))
    _insert_entity(con, 1, "Account", "alice",
                   {"username": "alice"}, "2026-04-15 09:00:00")
    _insert_entity(con, 1, "Host", "HR-WS-01",
                   {"hostname": "HR-WS-01"}, "2026-04-15 09:00:00")
    _insert_relation(con, 1, "logged_into",
                     "Account", "alice",
                     "Host", "HR-WS-01",
                     {"logon_type": "2"}, "2026-04-15 09:00:00")
    con.close()

    g = GraphStore(ontology_version="1.0")
    import_parsed_db(db, g)

    # 关系应该挂在 canonical '?\\alice' 节点上
    out = g.out_edges("Account", "?\\alice")
    assert len(out) == 1
    assert out[0]["to_id"] == "HR-WS-01"


def test_importer_on_real_parsed_db_produces_expected_counts() -> None:
    """对真实 data/parsed_events.duckdb 集成验证。"""
    from graph.importer import import_parsed_db
    from graph.store import GraphStore

    real_db = Path(__file__).resolve().parents[1] / "data" / "parsed_events.duckdb"
    if not real_db.exists():
        pytest.skip("data/parsed_events.duckdb not available")

    g = GraphStore(ontology_version="1.0")
    stats = import_parsed_db(real_db, g)
    # 去重后应该：Host 6、Account ~7（6 声明 + 可能 SYSTEM/Anonymous）、Process ~数百
    hosts = g.list_nodes_by_type("Host")
    accounts = g.list_nodes_by_type("Account")
    assert 6 <= len(hosts) <= 10
    assert 5 <= len(accounts) <= 15
    # 关系数量应当大幅少于原 4036（去重后）
    assert g.edge_count() < stats["relations_read"]
