"""组件 10 Day 2：候选 parser 审核动作 TDD（approve / reject / 抽样预览）。"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest

from evolution.parser_generator import CandidateParser


# =========================================================
# Fixtures
# =========================================================

class FakeOntology:
    _DEFAULT_ENDPOINTS = {
        "owns": ("User", "Account"),
        "logged_into": ("Account", "Host"),
        "executed_on": ("Process", "Host"),
    }

    def __init__(self, version="1.1"):
        self.version = version
        self.nodes = {n: {} for n in
                      ["User", "Account", "Host", "Process",
                       "NetworkEndpoint", "ScheduledTask"]}
        self.edges = {e: {} for e in self._DEFAULT_ENDPOINTS.keys()}

    def has_node(self, n): return n in self.nodes
    def has_edge(self, e): return e in self.edges
    def edge_endpoints(self, e): return self._DEFAULT_ENDPOINTS.get(e)


def _make_candidate(cid="c-aaa") -> CandidateParser:
    return CandidateParser(
        candidate_id=cid,
        triggered_by_ontology_version="1.1",
        triggered_by_proposal_id="p-1",
        target_node_type="ScheduledTask",
        source_events=[{"event_id": 4698, "channel": "Security"}],
        rules=[{
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
                 "attrs": {"sid": "event_data.SubjectUserSid"},
                 "meta": {"source": "log", "confidence": 1.0}},
                {"node": "Host",
                 "id_expr": "@computer",
                 "attrs": {"hostname": "@computer"},
                 "meta": {"source": "log", "confidence": 1.0}},
            ],
            "relations": [],
        }],
        sample_count=10,
        confidence=0.85,
        explanation="ok",
        stripped_relations=[],
    )


def _4698_event(record_no=10, computer="HR-WS-01", task="\\Microsoft\\Idle"):
    return {
        "event_id": 4698,
        "channel": "Security",
        "provider": "Microsoft-Windows-Security-Auditing",
        "record_number": record_no,
        "timestamp": "2026-04-14 17:31:00",
        "computer": computer,
        "event_data": json.dumps({
            "SubjectUserSid": "S-1-5-21-1000-1000-1000-1002",
            "SubjectUserName": "bob",
            "SubjectDomainName": "CORP",
            "SubjectLogonId": "0x3D40",
            "TaskName": task,
            "TaskContent": "<Task/>",
        }),
    }


def _anomaly_record(event):
    """Anomaly pool list_open() 返回结构。"""
    return {
        "record_id": event["record_number"],
        "event_id": event["event_id"],
        "computer": event["computer"],
        "timestamp": event["timestamp"],
        "failure_reason": "no rule",
        "raw_event": event,
    }


@pytest.fixture()
def store(tmp_path: Path):
    from storage.candidate_parser_store import CandidateParserStore
    s = CandidateParserStore(db_path=tmp_path / "candidates.duckdb")
    yield s
    s.close()


# =========================================================
# approve_and_apply
# =========================================================

def test_approve_and_apply_writes_yaml_and_marks_approved(store, tmp_path) -> None:
    from evolution.parser_review_actions import approve_and_apply
    c = _make_candidate()
    store.insert(c)

    out_dir = tmp_path / "generated"
    yaml_path = approve_and_apply(store, c.candidate_id, output_dir=out_dir)

    # 文件落地
    assert yaml_path.exists()
    text = yaml_path.read_text(encoding="utf-8")
    import yaml as yaml_mod
    doc = yaml_mod.safe_load(text)
    assert doc["rules"][0]["event_id"] == 4698
    # 状态 → approved + yaml_path 记录
    row = store.get(c.candidate_id)
    assert row["status"] == "approved"
    assert row["yaml_path"] == str(yaml_path)


def test_approve_and_apply_rejects_unknown_id(store, tmp_path) -> None:
    from evolution.parser_review_actions import approve_and_apply
    with pytest.raises(KeyError):
        approve_and_apply(store, "nope", output_dir=tmp_path)


def test_approve_and_apply_rejects_already_decided(store, tmp_path) -> None:
    """approve 二次（已 approved）应拒。"""
    from evolution.parser_review_actions import approve_and_apply, CandidateNotPending
    c = _make_candidate()
    store.insert(c)
    approve_and_apply(store, c.candidate_id, output_dir=tmp_path)
    with pytest.raises(CandidateNotPending):
        approve_and_apply(store, c.candidate_id, output_dir=tmp_path)


# =========================================================
# reject_candidate
# =========================================================

def test_reject_candidate_records_reason(store) -> None:
    from evolution.parser_review_actions import reject_candidate
    c = _make_candidate()
    store.insert(c)
    reject_candidate(store, c.candidate_id, reason="抽样回放成功率不足")
    row = store.get(c.candidate_id)
    assert row["status"] == "rejected"
    assert row["rejection_reason"] == "抽样回放成功率不足"


def test_reject_candidate_unknown_id_raises(store) -> None:
    from evolution.parser_review_actions import reject_candidate
    with pytest.raises(KeyError):
        reject_candidate(store, "nope", reason="x")


# =========================================================
# preview_candidate_parsing
# =========================================================

def test_preview_returns_expected_keys() -> None:
    from evolution.parser_review_actions import preview_candidate_parsing
    c = _make_candidate()
    samples = [_anomaly_record(_4698_event(10))]
    result = preview_candidate_parsing(c, samples, ontology=FakeOntology())
    for k in ("total", "success_count", "failure_count",
              "success_rate", "parsed_samples", "failures"):
        assert k in result


def test_preview_success_for_matching_4698_samples() -> None:
    from evolution.parser_review_actions import preview_candidate_parsing
    c = _make_candidate()
    samples = [_anomaly_record(_4698_event(10)),
               _anomaly_record(_4698_event(11, task="\\Chkdsk")),
               _anomaly_record(_4698_event(12, task="\\Backup"))]
    result = preview_candidate_parsing(c, samples, ontology=FakeOntology())
    assert result["total"] == 3
    assert result["success_count"] == 3
    assert result["failure_count"] == 0
    assert result["success_rate"] == 1.0
    assert len(result["parsed_samples"]) >= 1
    # 抽样产物含 entity 类型
    first = result["parsed_samples"][0]
    types = {e["node_type"] for e in first["entities"]}
    assert "ScheduledTask" in types


def test_preview_records_failures() -> None:
    """事件不在 candidate.rules 覆盖（如 5145）→ failures 列表非空。"""
    from evolution.parser_review_actions import preview_candidate_parsing
    c = _make_candidate()
    odd = _4698_event(99)
    odd["event_id"] = 5145  # 不在 candidate.rules 内
    samples = [_anomaly_record(_4698_event(10)), _anomaly_record(odd)]
    result = preview_candidate_parsing(c, samples, ontology=FakeOntology())
    assert result["total"] == 2
    assert result["success_count"] == 1
    assert result["failure_count"] == 1
    assert any("5145" in str(f) for f in result["failures"])


def test_preview_does_not_pollute_anomaly_pool_or_signals(tmp_path) -> None:
    """preview 是 dry-run，不能往 anomaly_pool / signal_hub 写。"""
    from evolution.parser_review_actions import preview_candidate_parsing
    from storage.anomaly_pool import AnomalyPool
    pool = AnomalyPool(db_path=tmp_path / "p.duckdb")
    before = pool.size_total()
    c = _make_candidate()
    samples = [_anomaly_record(_4698_event(10))]
    preview_candidate_parsing(c, samples, ontology=FakeOntology())
    after = pool.size_total()
    pool.close()
    assert after == before  # 没污染
