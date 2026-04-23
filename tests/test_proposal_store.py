"""组件 8 提议存储单测。"""
from __future__ import annotations

from pathlib import Path

import pytest


def _mk(pid="p-1", name="ScheduledTask", status="pending"):
    from evolution.proposer import Proposal
    return Proposal(
        proposal_id=pid,
        proposal_type="node",
        name=name,
        semantic_definition=f"{name} 的语义定义",
        supporting_evidence=[{"record_id": i, "excerpt": f"s{i}"} for i in range(3)],
        overlap_analysis={"Process": 0.3, "Account": 0.1},
        attack_mapping=["T1053.005"],
        source_signals=["data:unparseable_event:4698"],
        ontology_base_version="1.0",
        status=status,
    )


def test_insert_and_count(tmp_path: Path) -> None:
    from storage.proposal_store import ProposalStore
    s = ProposalStore(db_path=tmp_path / "props.duckdb")
    assert s.count() == 0
    s.insert(_mk("p-1"))
    s.insert(_mk("p-2"))
    assert s.count() == 2
    s.close()


def test_idempotent(tmp_path: Path) -> None:
    from storage.proposal_store import ProposalStore
    s = ProposalStore(db_path=tmp_path / "props.duckdb")
    s.insert(_mk("p-1"))
    s.insert(_mk("p-1"))
    assert s.count() == 1
    s.close()


def test_list_by_status(tmp_path: Path) -> None:
    from storage.proposal_store import ProposalStore
    s = ProposalStore(db_path=tmp_path / "props.duckdb")
    s.insert(_mk("p-1", name="A", status="pending"))
    s.insert(_mk("p-2", name="B", status="approved"))
    s.insert(_mk("p-3", name="C", status="rejected"))
    s.insert(_mk("p-4", name="D", status="pending"))

    pending = s.list_by_status("pending")
    assert sorted(p["name"] for p in pending) == ["A", "D"]

    approved = s.list_by_status("approved")
    assert [p["name"] for p in approved] == ["B"]
    s.close()


def test_mark_approved_updates_status(tmp_path: Path) -> None:
    from storage.proposal_store import ProposalStore
    s = ProposalStore(db_path=tmp_path / "props.duckdb")
    s.insert(_mk("p-1"))
    assert s.mark_approved("p-1") is True
    rows = s.list_by_status("approved")
    assert len(rows) == 1
    assert rows[0]["proposal_id"] == "p-1"
    # 原 pending 列表已空
    assert s.list_by_status("pending") == []
    s.close()


def test_mark_rejected_with_reason(tmp_path: Path) -> None:
    from storage.proposal_store import ProposalStore
    s = ProposalStore(db_path=tmp_path / "props.duckdb")
    s.insert(_mk("p-1"))
    s.mark_rejected("p-1", reason="与现有 Process 重叠")
    row = s.list_by_status("rejected")[0]
    assert row["rejection_reason"] == "与现有 Process 重叠"
    s.close()


def test_mark_modified_and_deferred(tmp_path: Path) -> None:
    from storage.proposal_store import ProposalStore
    s = ProposalStore(db_path=tmp_path / "props.duckdb")
    s.insert(_mk("p-1", name="A"))
    s.insert(_mk("p-2", name="B"))
    s.mark_modified("p-1", new_name="A_v2", new_definition="修正后的定义")
    s.mark_deferred("p-2")

    row1 = s.list_by_status("modified")[0]
    row2 = s.list_by_status("deferred")[0]
    assert row1["name"] == "A_v2"
    assert row1["semantic_definition"] == "修正后的定义"
    assert row2["proposal_id"] == "p-2"
    s.close()


def test_rejection_names_returns_rejected_names(tmp_path: Path) -> None:
    """反面样本库查询 —— 给 ProposalEngine 用作 rejection_names。"""
    from storage.proposal_store import ProposalStore
    s = ProposalStore(db_path=tmp_path / "props.duckdb")
    s.insert(_mk("p-1", name="GoodConcept", status="approved"))
    s.insert(_mk("p-2", name="BadOne", status="rejected"))
    s.insert(_mk("p-3", name="AnotherBad", status="rejected"))
    s.insert(_mk("p-4", name="Pending1", status="pending"))

    names = s.rejection_names()
    assert sorted(names) == ["AnotherBad", "BadOne"]
    s.close()


def test_count_by_status(tmp_path: Path) -> None:
    from storage.proposal_store import ProposalStore
    s = ProposalStore(db_path=tmp_path / "props.duckdb")
    s.insert(_mk("p-1", name="A", status="pending"))
    s.insert(_mk("p-2", name="B", status="approved"))
    s.insert(_mk("p-3", name="C", status="rejected"))
    s.insert(_mk("p-4", name="D", status="approved"))
    c = s.count_by_status()
    assert c == {"pending": 1, "approved": 2, "rejected": 1}
    s.close()


def test_mark_nonexistent_returns_false(tmp_path: Path) -> None:
    from storage.proposal_store import ProposalStore
    s = ProposalStore(db_path=tmp_path / "props.duckdb")
    assert s.mark_approved("no-such-id") is False
    assert s.mark_rejected("no-such-id", reason="x") is False
    s.close()
