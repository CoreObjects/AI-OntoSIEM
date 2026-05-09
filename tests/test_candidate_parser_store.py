"""组件 10 Day 2：CandidateParserStore TDD。"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import pytest

from evolution.parser_generator import CandidateParser


# =========================================================
# Fixtures
# =========================================================

def _make_candidate(
    candidate_id: str = "c-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    target: str = "ScheduledTask",
    proposal_id: str = "p-1111",
    base_version: str = "1.1",
    sample_count: int = 10,
    confidence: float = 0.85,
) -> CandidateParser:
    return CandidateParser(
        candidate_id=candidate_id,
        triggered_by_ontology_version=base_version,
        triggered_by_proposal_id=proposal_id,
        target_node_type=target,
        source_events=[{"event_id": 4698, "channel": "Security"}],
        rules=[{
            "name": "4698_x", "event_id": 4698, "channel": "Security",
            "description": "...",
            "entities": [
                {"node": target, "id_expr": "compose:@computer|event_data.TaskName",
                 "attrs": {"task_name": "event_data.TaskName"}, "meta": {}}
            ],
            "relations": [],
        }],
        sample_count=sample_count,
        confidence=confidence,
        explanation="...",
        stripped_relations=[
            {"edge": "owns", "from_ref": "Account", "to_ref": "ScheduledTask",
             "reason": "edge 'owns' is declared-only"}
        ],
    )


@pytest.fixture()
def store(tmp_path: Path):
    from storage.candidate_parser_store import CandidateParserStore
    s = CandidateParserStore(db_path=tmp_path / "candidates.duckdb")
    yield s
    s.close()


# =========================================================
# 写入
# =========================================================

def test_insert_and_get(store) -> None:
    c = _make_candidate()
    store.insert(c)
    row = store.get(c.candidate_id)
    assert row is not None
    assert row["candidate_id"] == c.candidate_id
    assert row["target_node_type"] == "ScheduledTask"
    assert row["status"] == "pending"
    assert row["confidence"] == 0.85
    assert row["sample_count"] == 10


def test_insert_idempotent(store) -> None:
    c = _make_candidate()
    store.insert(c)
    store.insert(c)
    assert store.count() == 1


def test_insert_many(store) -> None:
    items = [_make_candidate(candidate_id=f"c-{i}-x") for i in range(3)]
    store.insert_many(items)
    assert store.count() == 3


def test_get_returns_none_for_unknown(store) -> None:
    assert store.get("nope") is None


# =========================================================
# JSON 列 round-trip
# =========================================================

def test_json_columns_roundtrip(store) -> None:
    c = _make_candidate()
    store.insert(c)
    row = store.get(c.candidate_id)
    assert row["rules"] == c.rules
    assert row["source_events"] == c.source_events
    assert row["stripped_relations"] == c.stripped_relations


def test_as_candidate_rebuilds_dataclass(store) -> None:
    c = _make_candidate()
    store.insert(c)
    rebuilt = store.as_candidate(c.candidate_id)
    assert rebuilt is not None
    assert rebuilt.candidate_id == c.candidate_id
    assert rebuilt.target_node_type == c.target_node_type
    assert rebuilt.rules == c.rules
    assert rebuilt.stripped_relations == c.stripped_relations
    # yaml_text round-trip
    import yaml
    doc = yaml.safe_load(rebuilt.yaml_text)
    assert doc["rules"][0]["event_id"] == 4698


# =========================================================
# 状态机
# =========================================================

def test_mark_approved_records_yaml_path(store) -> None:
    c = _make_candidate()
    store.insert(c)
    ok = store.mark_approved(c.candidate_id, yaml_path="parsers/generated/abc.yaml")
    assert ok is True
    row = store.get(c.candidate_id)
    assert row["status"] == "approved"
    assert row["yaml_path"] == "parsers/generated/abc.yaml"


def test_mark_rejected_records_reason(store) -> None:
    c = _make_candidate()
    store.insert(c)
    ok = store.mark_rejected(c.candidate_id, reason="字段引用不可信")
    assert ok is True
    row = store.get(c.candidate_id)
    assert row["status"] == "rejected"
    assert row["rejection_reason"] == "字段引用不可信"


def test_mark_returns_false_for_unknown(store) -> None:
    assert store.mark_approved("nope", yaml_path="x") is False
    assert store.mark_rejected("nope", reason="y") is False


# =========================================================
# 查询
# =========================================================

def test_list_by_status(store) -> None:
    c1 = _make_candidate(candidate_id="c-1")
    c2 = _make_candidate(candidate_id="c-2")
    c3 = _make_candidate(candidate_id="c-3")
    store.insert_many([c1, c2, c3])
    store.mark_approved("c-1", yaml_path="x.yaml")
    store.mark_rejected("c-2", reason="r")
    pending = store.list_by_status("pending")
    approved = store.list_by_status("approved")
    rejected = store.list_by_status("rejected")
    assert {r["candidate_id"] for r in pending} == {"c-3"}
    assert {r["candidate_id"] for r in approved} == {"c-1"}
    assert {r["candidate_id"] for r in rejected} == {"c-2"}


def test_count_by_status(store) -> None:
    c1 = _make_candidate(candidate_id="c-1")
    c2 = _make_candidate(candidate_id="c-2")
    store.insert_many([c1, c2])
    store.mark_approved("c-1", yaml_path="x")
    counts = store.count_by_status()
    assert counts.get("pending", 0) == 1
    assert counts.get("approved", 0) == 1


def test_list_by_proposal(store) -> None:
    """同一个提议如果生成了多个 candidate（多轮 LLM），应能按 proposal_id 查回。"""
    c1 = _make_candidate(candidate_id="c-1", proposal_id="p-A")
    c2 = _make_candidate(candidate_id="c-2", proposal_id="p-A")
    c3 = _make_candidate(candidate_id="c-3", proposal_id="p-B")
    store.insert_many([c1, c2, c3])
    a = store.list_by_proposal("p-A")
    assert {r["candidate_id"] for r in a} == {"c-1", "c-2"}


# =========================================================
# 持久化跨进程
# =========================================================

def test_persistence_across_reopen(tmp_path) -> None:
    from storage.candidate_parser_store import CandidateParserStore
    db = tmp_path / "candidates.duckdb"
    s1 = CandidateParserStore(db_path=db)
    s1.insert(_make_candidate())
    s1.close()
    s2 = CandidateParserStore(db_path=db)
    assert s2.count() == 1
    s2.close()
