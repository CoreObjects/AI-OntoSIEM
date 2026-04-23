"""组件 5 知识图谱层单测（TDD）。"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest


# =========================================================
# 空图 + 基础节点添加
# =========================================================

def test_empty_graph_counts_zero() -> None:
    from graph.store import GraphStore
    g = GraphStore(ontology_version="1.0")
    assert g.node_count() == 0
    assert g.edge_count() == 0


def test_add_account_increments_node_count() -> None:
    from graph.store import GraphStore
    g = GraphStore(ontology_version="1.0")
    g.upsert_entity(
        node_type="Account",
        node_id="S-1-5-21-1-1001",
        attrs={"sid": "S-1-5-21-1-1001", "domain": "CORP", "username": "alice"},
        timestamp="2026-04-15T09:00:00Z",
        source="log",
    )
    assert g.node_count() == 1


# =========================================================
# Account 强匹配：同 SID 合并（不增节点计数）
# =========================================================

def test_account_same_sid_merges_not_duplicates() -> None:
    from graph.store import GraphStore
    g = GraphStore(ontology_version="1.0")
    for i in range(4):
        g.upsert_entity(
            node_type="Account",
            node_id="S-1-5-21-1-1001",
            attrs={"sid": "S-1-5-21-1-1001", "domain": "CORP", "username": "alice"},
            timestamp=f"2026-04-{15+i}T09:00:00Z",
            source="log",
        )
    assert g.node_count() == 1


def test_account_merge_preserves_first_seen_advances_last_seen() -> None:
    from graph.store import GraphStore
    g = GraphStore(ontology_version="1.0")
    g.upsert_entity(
        node_type="Account",
        node_id="S-1-5-21-1-1001",
        attrs={"sid": "S-1-5-21-1-1001", "domain": "CORP", "username": "alice"},
        timestamp="2026-04-15T09:00:00Z",
        source="log",
    )
    g.upsert_entity(
        node_type="Account",
        node_id="S-1-5-21-1-1001",
        attrs={"sid": "S-1-5-21-1-1001", "domain": "CORP", "username": "alice"},
        timestamp="2026-04-17T11:00:00Z",
        source="log",
    )
    node = g.get_node("Account", "S-1-5-21-1-1001")
    assert node["meta"]["first_seen"] == "2026-04-15T09:00:00Z"
    assert node["meta"]["last_seen"] == "2026-04-17T11:00:00Z"


def test_account_merge_out_of_order_last_seen_is_max() -> None:
    """乱序到达：last_seen 取最大值，first_seen 取最小值。"""
    from graph.store import GraphStore
    g = GraphStore(ontology_version="1.0")
    g.upsert_entity("Account", "S-1-5-21-1-1001",
                    attrs={"sid": "S-1-5-21-1-1001"},
                    timestamp="2026-04-17T11:00:00Z", source="log")
    g.upsert_entity("Account", "S-1-5-21-1-1001",
                    attrs={"sid": "S-1-5-21-1-1001"},
                    timestamp="2026-04-15T09:00:00Z", source="log")
    node = g.get_node("Account", "S-1-5-21-1-1001")
    assert node["meta"]["first_seen"] == "2026-04-15T09:00:00Z"
    assert node["meta"]["last_seen"] == "2026-04-17T11:00:00Z"


def test_account_merge_ontology_version_recorded() -> None:
    """每次更新 meta.ontology_version 记录当前活跃本体版本。"""
    from graph.store import GraphStore
    g = GraphStore(ontology_version="1.0")
    g.upsert_entity("Account", "S-1-5-21-1-1001",
                    attrs={"sid": "S-1-5-21-1-1001"},
                    timestamp="2026-04-15T09:00:00Z", source="log")
    node = g.get_node("Account", "S-1-5-21-1-1001")
    assert node["meta"]["ontology_version"] == "1.0"
    assert node["meta"]["source"] == "log"


# =========================================================
# Host / Process 主键
# =========================================================

def test_host_primary_key_is_hostname() -> None:
    from graph.store import GraphStore
    g = GraphStore(ontology_version="1.0")
    g.upsert_entity("Host", "HR-WS-01",
                    attrs={"hostname": "HR-WS-01", "os": "Windows 10"},
                    timestamp="2026-04-15T09:00:00Z", source="log")
    g.upsert_entity("Host", "HR-WS-01",
                    attrs={"hostname": "HR-WS-01", "os": "Windows 10"},
                    timestamp="2026-04-16T09:00:00Z", source="log")
    assert g.node_count() == 1
    assert g.get_node("Host", "HR-WS-01")["attrs"]["os"] == "Windows 10"


def test_different_node_types_do_not_collide() -> None:
    """Host 'alice' 和 Account 'alice' 不应互相覆盖。"""
    from graph.store import GraphStore
    g = GraphStore(ontology_version="1.0")
    g.upsert_entity("Host", "alice",
                    attrs={"hostname": "alice"},
                    timestamp="2026-04-15T09:00:00Z", source="log")
    g.upsert_entity("Account", "alice",
                    attrs={"username": "alice"},
                    timestamp="2026-04-15T09:00:00Z", source="log")
    assert g.node_count() == 2


# =========================================================
# 硬约束：User 节点 + owns 边只能来自 CMDB/IAM
# =========================================================

def test_user_node_from_log_rejected() -> None:
    """User 只能从 CMDB/IAM 来；log source 拒绝。"""
    from graph.store import GraphStore, HardConstraintViolation
    g = GraphStore(ontology_version="1.0")
    with pytest.raises(HardConstraintViolation, match="User.*log"):
        g.upsert_entity("User", "u1001",
                        attrs={"user_id": "u1001"},
                        timestamp="2026-04-15T09:00:00Z", source="log")


def test_user_node_from_cmdb_accepted() -> None:
    from graph.store import GraphStore
    g = GraphStore(ontology_version="1.0")
    g.upsert_entity("User", "u1001",
                    attrs={"user_id": "u1001", "display_name": "Alice Chen"},
                    timestamp="2026-04-15T09:00:00Z", source="cmdb")
    assert g.node_count() == 1


def test_owns_edge_from_log_rejected() -> None:
    """owns 边只能声明不能推断。"""
    from graph.store import GraphStore, HardConstraintViolation
    g = GraphStore(ontology_version="1.0")
    g.upsert_entity("User", "u1001", attrs={"user_id": "u1001"},
                    timestamp="2026-04-15T09:00:00Z", source="cmdb")
    g.upsert_entity("Account", "S-1-5-21-1-1001",
                    attrs={"sid": "S-1-5-21-1-1001"},
                    timestamp="2026-04-15T09:00:00Z", source="log")
    with pytest.raises(HardConstraintViolation, match="owns"):
        g.upsert_relation(
            edge_type="owns",
            from_type="User", from_id="u1001",
            to_type="Account", to_id="S-1-5-21-1-1001",
            timestamp="2026-04-15T09:00:00Z",
            source="log",
        )


def test_owns_edge_from_cmdb_accepted() -> None:
    from graph.store import GraphStore
    g = GraphStore(ontology_version="1.0")
    g.upsert_entity("User", "u1001", attrs={"user_id": "u1001"},
                    timestamp="2026-04-15T09:00:00Z", source="cmdb")
    g.upsert_entity("Account", "S-1-5-21-1-1001",
                    attrs={"sid": "S-1-5-21-1-1001"},
                    timestamp="2026-04-15T09:00:00Z", source="log")
    g.upsert_relation(
        edge_type="owns",
        from_type="User", from_id="u1001",
        to_type="Account", to_id="S-1-5-21-1-1001",
        timestamp="2026-04-15T09:00:00Z",
        source="cmdb",
    )
    assert g.edge_count() == 1


# =========================================================
# 关系合并 + 属性
# =========================================================

def _fixture_logon(g, ts: str) -> None:
    g.upsert_entity("Account", "S-1-5-21-1-1001", attrs={"sid": "S-1-5-21-1-1001"},
                    timestamp=ts, source="log")
    g.upsert_entity("Host", "HR-WS-01", attrs={"hostname": "HR-WS-01"},
                    timestamp=ts, source="log")


def test_relation_same_endpoints_merges_not_duplicates() -> None:
    from graph.store import GraphStore
    g = GraphStore(ontology_version="1.0")
    _fixture_logon(g, "2026-04-15T09:00:00Z")
    for i in range(3):
        g.upsert_relation(
            edge_type="logged_into",
            from_type="Account", from_id="S-1-5-21-1-1001",
            to_type="Host", to_id="HR-WS-01",
            timestamp=f"2026-04-{15+i}T09:00:00Z",
            source="log",
        )
    assert g.edge_count() == 1


def test_relation_merge_updates_last_seen() -> None:
    from graph.store import GraphStore
    g = GraphStore(ontology_version="1.0")
    _fixture_logon(g, "2026-04-15T09:00:00Z")
    g.upsert_relation("logged_into", "Account", "S-1-5-21-1-1001",
                      "Host", "HR-WS-01",
                      timestamp="2026-04-15T09:00:00Z", source="log")
    g.upsert_relation("logged_into", "Account", "S-1-5-21-1-1001",
                      "Host", "HR-WS-01",
                      timestamp="2026-04-17T11:30:00Z", source="log")
    edges = g.out_edges("Account", "S-1-5-21-1-1001")
    assert len(edges) == 1
    e = edges[0]
    assert e["meta"]["first_seen"] == "2026-04-15T09:00:00Z"
    assert e["meta"]["last_seen"] == "2026-04-17T11:30:00Z"


def test_relation_preserves_edge_attrs() -> None:
    """logon_type 等边属性应保留到边 attrs 上。"""
    from graph.store import GraphStore
    g = GraphStore(ontology_version="1.0")
    _fixture_logon(g, "2026-04-15T09:00:00Z")
    g.upsert_relation(
        "logged_into", "Account", "S-1-5-21-1-1001", "Host", "HR-WS-01",
        timestamp="2026-04-15T09:00:00Z", source="log",
        attrs={"logon_type": "3"},
    )
    e = g.out_edges("Account", "S-1-5-21-1-1001")[0]
    assert e["attrs"]["logon_type"] == "3"


def test_relation_endpoint_missing_raises() -> None:
    from graph.store import GraphStore
    g = GraphStore(ontology_version="1.0")
    g.upsert_entity("Host", "HR-WS-01", attrs={}, timestamp="2026-04-15T09:00:00Z", source="log")
    with pytest.raises(KeyError):
        g.upsert_relation(
            "logged_into", "Account", "S-1-5-21-1-1001", "Host", "HR-WS-01",
            timestamp="2026-04-15T09:00:00Z", source="log",
        )


# =========================================================
# 查询 API：邻居 / 子图 / 按类型列举
# =========================================================

def _fixture_attack_mini(g) -> None:
    """造一个小攻击子图：Account → logged_into → Host，Process → executed_on → Host。"""
    ts = "2026-04-17T10:12:00Z"
    g.upsert_entity("Account", "S-1-5-21-1-2001",
                    attrs={"sid": "S-1-5-21-1-2001", "username": "svc_backup"},
                    timestamp=ts, source="log")
    g.upsert_entity("Host", "FIN-SRV-01",
                    attrs={"hostname": "FIN-SRV-01"}, timestamp=ts, source="log")
    g.upsert_entity("Process", "FIN-SRV-01::whoami.exe::5000::" + ts,
                    attrs={"pid": "5000", "image_name": "whoami.exe"},
                    timestamp=ts, source="log")
    g.upsert_relation("logged_into",
                      "Account", "S-1-5-21-1-2001",
                      "Host", "FIN-SRV-01",
                      timestamp=ts, source="log", attrs={"logon_type": "3"})
    g.upsert_relation("executed_on",
                      "Process", "FIN-SRV-01::whoami.exe::5000::" + ts,
                      "Host", "FIN-SRV-01",
                      timestamp=ts, source="log")


def test_list_nodes_by_type() -> None:
    from graph.store import GraphStore
    g = GraphStore(ontology_version="1.0")
    _fixture_attack_mini(g)
    accts = g.list_nodes_by_type("Account")
    hosts = g.list_nodes_by_type("Host")
    procs = g.list_nodes_by_type("Process")
    assert len(accts) == 1 and accts[0]["node_id"] == "S-1-5-21-1-2001"
    assert len(hosts) == 1
    assert len(procs) == 1


def test_out_edges_returns_outgoing_only() -> None:
    from graph.store import GraphStore
    g = GraphStore(ontology_version="1.0")
    _fixture_attack_mini(g)
    out = g.out_edges("Account", "S-1-5-21-1-2001")
    assert len(out) == 1
    assert out[0]["edge_type"] == "logged_into"
    assert out[0]["to_type"] == "Host"


def test_subgraph_1hop_includes_neighbors_and_edges() -> None:
    from graph.store import GraphStore
    g = GraphStore(ontology_version="1.0")
    _fixture_attack_mini(g)
    sub = g.subgraph_around("Host", "FIN-SRV-01", depth=1)
    # 应包含 Host 自身 + Account + Process 共 3 节点
    assert len(sub["nodes"]) == 3
    # 包含 2 条入边 (logged_into + executed_on)
    assert len(sub["edges"]) == 2


# =========================================================
# 本体变更订阅 → 回填钩子（核心差异点）
# =========================================================

class _FakeOntology:
    def __init__(self, version, nodes, edges):
        self.version = version
        self.nodes = dict.fromkeys(nodes, {})
        self.edges = dict.fromkeys(edges, {})


class _FakeOntologyService:
    def __init__(self, current):
        self._current = current
        self._subs = []

    def get_current(self):
        return self._current

    def subscribe(self, cb):
        self._subs.append(cb)

    def simulate_upgrade(self, new):
        old = self._current
        self._current = new
        for cb in self._subs:
            cb(old, new)


def test_store_subscribes_to_ontology_upgrade() -> None:
    """本体升级后，store 自动更新其 ontology_version。"""
    from graph.store import GraphStore

    v1 = _FakeOntology("1.0", ["Account", "Host"], ["logged_into"])
    svc = _FakeOntologyService(v1)

    g = GraphStore(ontology_version="1.0")
    g.subscribe_to_ontology(svc)

    v2 = _FakeOntology("1.1", ["Account", "Host", "ScheduledTask"],
                       ["logged_into", "schedules"])
    svc.simulate_upgrade(v2)

    assert g.ontology_version == "1.1"


def test_store_upgrade_invokes_backfill_with_diff() -> None:
    """升级时调用 backfill_fn，传入 (new_nodes, new_edges, store)。"""
    from graph.store import GraphStore

    v1 = _FakeOntology("1.0", ["Account", "Host"], ["logged_into"])
    svc = _FakeOntologyService(v1)

    captured = {}

    def fake_backfill(new_nodes, new_edges, store):
        captured["nodes"] = set(new_nodes)
        captured["edges"] = set(new_edges)
        captured["store"] = store

    g = GraphStore(ontology_version="1.0")
    g.subscribe_to_ontology(svc, backfill_fn=fake_backfill)

    v2 = _FakeOntology("1.1", ["Account", "Host", "ScheduledTask"],
                       ["logged_into", "schedules"])
    svc.simulate_upgrade(v2)

    assert captured["nodes"] == {"ScheduledTask"}
    assert captured["edges"] == {"schedules"}
    assert captured["store"] is g


def test_store_no_diff_no_backfill_call() -> None:
    """本体版本变了但节点/边集合未变 → 不调用 backfill。"""
    from graph.store import GraphStore

    v1 = _FakeOntology("1.0", ["Account"], ["logged_into"])
    svc = _FakeOntologyService(v1)

    called = [False]
    g = GraphStore(ontology_version="1.0")
    g.subscribe_to_ontology(svc, backfill_fn=lambda n, e, s: called.__setitem__(0, True))

    v2 = _FakeOntology("1.1", ["Account"], ["logged_into"])
    svc.simulate_upgrade(v2)

    assert called[0] is False
    assert g.ontology_version == "1.1"


def test_subgraph_0hop_only_self() -> None:
    from graph.store import GraphStore
    g = GraphStore(ontology_version="1.0")
    _fixture_attack_mini(g)
    sub = g.subgraph_around("Host", "FIN-SRV-01", depth=0)
    assert len(sub["nodes"]) == 1
    assert sub["nodes"][0]["node_id"] == "FIN-SRV-01"
    assert sub["edges"] == []
