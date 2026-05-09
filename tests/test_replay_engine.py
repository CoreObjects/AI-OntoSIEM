"""组件 10 Day 3：ReplayEngine TDD。

输入：(anomaly_pool, parser_config, ontology, graph)
输出：ReplayReport
副作用：成功 → mark_backfilled + 灌图（新实体带 backfilled=True attrs）
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest


# =========================================================
# Fakes / fixtures
# =========================================================

class FakeOntology:
    _DEFAULT_ENDPOINTS = {
        "owns": ("User", "Account"),
        "logged_into": ("Account", "Host"),
        "executed_on": ("Process", "Host"),
    }

    def __init__(self, version: str = "1.1"):
        self.version = version
        self.nodes = {n: {} for n in
                      ["User", "Account", "Host", "Process",
                       "NetworkEndpoint", "ScheduledTask"]}
        self.edges = {e: {} for e in self._DEFAULT_ENDPOINTS.keys()}

    def has_node(self, n): return n in self.nodes
    def has_edge(self, e): return e in self.edges
    def edge_endpoints(self, e): return self._DEFAULT_ENDPOINTS.get(e)


def _scheduled_task_rule() -> Dict[str, Any]:
    """模拟 Day 1 ParserGenerator 输出 + Day 2 approve_and_apply 写入 generated YAML 的规则。"""
    return {
        "name": "4698_scheduled_task_create",
        "event_id": 4698,
        "channel": "Security",
        "description": "auto",
        "entities": [
            {"node": "ScheduledTask",
             "id_expr": "compose:@computer|event_data.TaskName",
             "attrs": {"task_name": "event_data.TaskName"},
             "meta": {"source": "log", "confidence": 0.9}},
            {"node": "Account",
             "id_expr": "event_data.SubjectUserSid",
             "attrs": {"sid": "event_data.SubjectUserSid",
                       "username": "event_data.SubjectUserName"},
             "meta": {"source": "log", "confidence": 1.0}},
            {"node": "Host",
             "id_expr": "@computer",
             "attrs": {"hostname": "@computer"},
             "meta": {"source": "log", "confidence": 1.0}},
        ],
        "relations": [],
    }


def _make_parser_config():
    from parsers.windows_parser import EventRule, ParserConfig
    cfg = ParserConfig(
        version="1.1", target_ontology_version="1.1",
        description="test replay config",
        rules=[EventRule.from_dict(_scheduled_task_rule())],
    )
    cfg._build_index()
    return cfg


def _add_anomaly_4698(pool, record_id: int, computer: str = "HR-WS-01",
                     task: str = "\\Microsoft\\Idle"):
    raw = {
        "event_id": 4698,
        "channel": "Security",
        "provider": "Microsoft-Windows-Security-Auditing",
        "record_number": record_id,
        "timestamp": "2026-04-14 17:31:00",
        "computer": computer,
        "event_data": json.dumps({
            "SubjectUserSid": f"S-1-5-21-1000-1000-1000-{1000+record_id}",
            "SubjectUserName": "bob",
            "SubjectDomainName": "CORP",
            "SubjectLogonId": "0x3D40",
            "TaskName": task,
            "TaskContent": "<Task/>",
        }),
    }
    pool.add(
        record_id=record_id, event_id=4698, computer=computer,
        timestamp=raw["timestamp"], failure_reason="no rule for 4698",
        raw_event=raw, ontology_version="1.0",
    )


def _add_anomaly_unknown(pool, record_id: int):
    """异常池里的 unknown event_id —— 没规则，replay 也救不了。"""
    raw = {
        "event_id": 9999, "channel": "Security",
        "record_number": record_id, "timestamp": "2026-04-14 17:31:00",
        "computer": "X", "event_data": json.dumps({"X": "y"}),
    }
    pool.add(
        record_id=record_id, event_id=9999, computer="X",
        timestamp=raw["timestamp"], failure_reason="no rule",
        raw_event=raw, ontology_version="1.0",
    )


@pytest.fixture()
def pool(tmp_path: Path):
    from storage.anomaly_pool import AnomalyPool
    p = AnomalyPool(db_path=tmp_path / "anomaly.duckdb")
    yield p
    p.close()


@pytest.fixture()
def graph():
    from graph.store import GraphStore
    return GraphStore(ontology_version="1.1")


@pytest.fixture()
def ontology():
    return FakeOntology()


# =========================================================
# Report dataclass
# =========================================================

def test_replay_report_dataclass_fields() -> None:
    from evolution.replay_engine import ReplayReport
    r = ReplayReport(
        started_at="t1", finished_at="t2", ontology_version="1.1",
        total_open_before=10, attempted=10,
        backfilled=8, failed=2, total_open_after=2,
        new_entities=24, merged_entities=0,
        new_relations=0, merged_relations=0,
        by_event_id={4698: {"backfilled": 8, "failed": 0}},
    )
    assert r.success_rate == 0.8


# =========================================================
# 基础 replay 流程
# =========================================================

def test_replay_empty_pool_returns_zero_report(pool, graph, ontology) -> None:
    from evolution.replay_engine import ReplayEngine
    eng = ReplayEngine(anomaly_pool=pool, parser_config=_make_parser_config(),
                       ontology=ontology, graph=graph)
    report = eng.replay()
    assert report.attempted == 0
    assert report.backfilled == 0
    assert report.total_open_after == 0


def test_replay_marks_backfilled_for_successful_records(pool, graph, ontology) -> None:
    from evolution.replay_engine import ReplayEngine
    _add_anomaly_4698(pool, 1)
    _add_anomaly_4698(pool, 2)
    _add_anomaly_4698(pool, 3)
    assert pool.size_open() == 3

    eng = ReplayEngine(anomaly_pool=pool, parser_config=_make_parser_config(),
                       ontology=ontology, graph=graph)
    report = eng.replay()

    assert report.attempted == 3
    assert report.backfilled == 3
    assert report.failed == 0
    assert pool.size_open() == 0
    assert pool.size_total() == 3


def test_replay_leaves_unparseable_records_in_pool(pool, graph, ontology) -> None:
    from evolution.replay_engine import ReplayEngine
    _add_anomaly_4698(pool, 1)            # 能救
    _add_anomaly_unknown(pool, 99)        # 救不了（没规则）
    assert pool.size_open() == 2

    eng = ReplayEngine(anomaly_pool=pool, parser_config=_make_parser_config(),
                       ontology=ontology, graph=graph)
    report = eng.replay()

    assert report.backfilled == 1
    assert report.failed == 1
    assert pool.size_open() == 1   # unknown 还留


def test_replay_skips_already_backfilled(pool, graph, ontology) -> None:
    """二次跑 replay 不应重复处理同样的记录。"""
    from evolution.replay_engine import ReplayEngine
    _add_anomaly_4698(pool, 1)
    _add_anomaly_4698(pool, 2)
    eng = ReplayEngine(anomaly_pool=pool, parser_config=_make_parser_config(),
                       ontology=ontology, graph=graph)
    eng.replay()  # 第一次
    report2 = eng.replay()  # 第二次
    assert report2.attempted == 0
    assert report2.backfilled == 0


# =========================================================
# 灌图 + backfilled flag
# =========================================================

def test_replay_adds_new_target_node_to_graph_with_backfilled_flag(
        pool, graph, ontology) -> None:
    from evolution.replay_engine import ReplayEngine
    _add_anomaly_4698(pool, 1, task="\\Demo\\Task")
    eng = ReplayEngine(anomaly_pool=pool, parser_config=_make_parser_config(),
                       ontology=ontology, graph=graph)
    eng.replay()

    sched = graph.list_nodes_by_type("ScheduledTask")
    assert len(sched) == 1
    node = sched[0]
    # backfilled flag 在 attrs 里
    assert node["attrs"].get("backfilled") is True
    assert "backfilled_at" in node["attrs"]
    assert node["attrs"]["backfilled_ontology_version"] == "1.1"


def test_replay_existing_entity_merges_without_backfilled_flag(
        pool, graph, ontology) -> None:
    """Account/Host 如果已经在图里（来自原始 4624 解析），replay 合并 last_seen，
    不打 backfilled=True（避免误标"老节点是 backfill 来的"）。"""
    from evolution.replay_engine import ReplayEngine
    # 先模拟"原始"灌入 Account
    graph.upsert_entity(
        "Account", "S-1-5-21-1000-1000-1000-1001",
        attrs={"username": "bob"},
        timestamp="2026-04-10 09:00:00", source="log", confidence=1.0,
    )
    _add_anomaly_4698(pool, 1)  # 这条会创建 SID=...1001 的 Account（同一个）
    eng = ReplayEngine(anomaly_pool=pool, parser_config=_make_parser_config(),
                       ontology=ontology, graph=graph)
    eng.replay()

    accs = graph.list_nodes_by_type("Account")
    assert len(accs) == 1
    # Account 不应被打 backfilled=True（它原本就在图里）
    assert accs[0]["attrs"].get("backfilled") is not True


def test_replay_counts_new_vs_merged_entities(pool, graph, ontology) -> None:
    from evolution.replay_engine import ReplayEngine
    # 先原始放进 Host
    graph.upsert_entity(
        "Host", "HR-WS-01", attrs={"hostname": "HR-WS-01"},
        timestamp="2026-04-10 09:00:00", source="log", confidence=1.0,
    )
    _add_anomaly_4698(pool, 1, computer="HR-WS-01")  # ScheduledTask + Account 新；Host 旧
    eng = ReplayEngine(anomaly_pool=pool, parser_config=_make_parser_config(),
                       ontology=ontology, graph=graph)
    report = eng.replay()
    # ScheduledTask + Account = 新；Host 已存在 = 合并
    assert report.new_entities == 2
    assert report.merged_entities == 1


# =========================================================
# 副作用隔离：不污染原 anomaly_pool（额外失败信号 / signal_hub）
# =========================================================

def test_replay_failed_record_does_not_double_log(pool, graph, ontology) -> None:
    """unknown event 9999 的 anomaly_pool 记录在 replay 后不应再多一条副本。"""
    from evolution.replay_engine import ReplayEngine
    _add_anomaly_unknown(pool, 99)
    before = pool.size_total()
    eng = ReplayEngine(anomaly_pool=pool, parser_config=_make_parser_config(),
                       ontology=ontology, graph=graph)
    eng.replay()
    after = pool.size_total()
    assert after == before  # 没新增重复条目


# =========================================================
# 报告 by_event_id 拆分
# =========================================================

def test_report_breakdown_by_event_id(pool, graph, ontology) -> None:
    from evolution.replay_engine import ReplayEngine
    _add_anomaly_4698(pool, 1)
    _add_anomaly_4698(pool, 2)
    _add_anomaly_unknown(pool, 99)
    eng = ReplayEngine(anomaly_pool=pool, parser_config=_make_parser_config(),
                       ontology=ontology, graph=graph)
    report = eng.replay()
    assert report.by_event_id[4698]["backfilled"] == 2
    assert report.by_event_id[4698]["failed"] == 0
    assert report.by_event_id[9999]["failed"] == 1


# =========================================================
# total_open_before / after
# =========================================================

def test_report_pool_size_before_and_after(pool, graph, ontology) -> None:
    from evolution.replay_engine import ReplayEngine
    _add_anomaly_4698(pool, 1)
    _add_anomaly_4698(pool, 2)
    _add_anomaly_unknown(pool, 99)
    eng = ReplayEngine(anomaly_pool=pool, parser_config=_make_parser_config(),
                       ontology=ontology, graph=graph)
    report = eng.replay()
    assert report.total_open_before == 3
    assert report.total_open_after == 1   # 4698 两条已 backfilled，9999 留池
