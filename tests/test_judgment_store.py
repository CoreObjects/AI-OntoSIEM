"""组件 6 判决存储单测。"""
from __future__ import annotations

from pathlib import Path

import pytest


def _mk_judgment(
    jid="j-1", alert_id="al-1", verdict="suspicious", confidence=0.75,
    semantic_gap=None, needs_review=False,
):
    from reasoning.judgment_engine import Judgment
    return Judgment(
        judgment_id=jid,
        alert_id=alert_id,
        verdict=verdict,
        confidence=confidence,
        reasoning_steps=["s1", "s2"],
        evidence_refs=[{"type": "matched_field", "ref": "EventData.LogonType"}],
        attack_chain=["T1078"],
        next_steps=["isolate"],
        ontology_version="1.0",
        semantic_gap=semantic_gap,
        needs_review=needs_review,
    )


def test_store_insert_and_count(tmp_path: Path) -> None:
    from storage.judgment_store import JudgmentStore
    s = JudgmentStore(db_path=tmp_path / "judgments.duckdb")
    assert s.count() == 0
    s.insert(_mk_judgment("j-1"))
    s.insert(_mk_judgment("j-2"))
    assert s.count() == 2
    s.close()


def test_store_insert_many(tmp_path: Path) -> None:
    from storage.judgment_store import JudgmentStore
    s = JudgmentStore(db_path=tmp_path / "judgments.duckdb")
    s.insert_many([_mk_judgment("j-1"), _mk_judgment("j-2"), _mk_judgment("j-3")])
    assert s.count() == 3
    s.close()


def test_store_idempotent(tmp_path: Path) -> None:
    from storage.judgment_store import JudgmentStore
    s = JudgmentStore(db_path=tmp_path / "judgments.duckdb")
    s.insert(_mk_judgment("j-1"))
    s.insert(_mk_judgment("j-1"))
    assert s.count() == 1
    s.close()


def test_store_list_recent_full_fields(tmp_path: Path) -> None:
    from storage.judgment_store import JudgmentStore
    s = JudgmentStore(db_path=tmp_path / "judgments.duckdb")
    s.insert(_mk_judgment("j-1", verdict="malicious", confidence=0.92))
    rows = s.list_recent(limit=10)
    assert len(rows) == 1
    r = rows[0]
    assert r["judgment_id"] == "j-1"
    assert r["verdict"] == "malicious"
    assert r["confidence"] == 0.92
    assert r["reasoning_steps"] == ["s1", "s2"]
    assert r["attack_chain"] == ["T1078"]
    assert r["evidence_refs"][0]["ref"] == "EventData.LogonType"
    s.close()


def test_store_count_by_verdict(tmp_path: Path) -> None:
    from storage.judgment_store import JudgmentStore
    s = JudgmentStore(db_path=tmp_path / "judgments.duckdb")
    s.insert_many([
        _mk_judgment("j-1", verdict="malicious"),
        _mk_judgment("j-2", verdict="malicious"),
        _mk_judgment("j-3", verdict="suspicious"),
        _mk_judgment("j-4", verdict="benign"),
    ])
    c = s.count_by_verdict()
    assert c["malicious"] == 2
    assert c["suspicious"] == 1
    assert c["benign"] == 1
    s.close()


def test_store_list_needs_review_only(tmp_path: Path) -> None:
    """人工复核队列过滤：needs_review=True 的那些。"""
    from storage.judgment_store import JudgmentStore
    s = JudgmentStore(db_path=tmp_path / "judgments.duckdb")
    s.insert(_mk_judgment("j-ok", confidence=0.9, needs_review=False))
    s.insert(_mk_judgment("j-low", confidence=0.3, needs_review=True))
    review = s.list_needs_review()
    assert len(review) == 1
    assert review[0]["judgment_id"] == "j-low"
    s.close()


def test_store_persists_semantic_gap(tmp_path: Path) -> None:
    from storage.judgment_store import JudgmentStore
    s = JudgmentStore(db_path=tmp_path / "judgments.duckdb")
    s.insert(_mk_judgment(
        "j-gap",
        semantic_gap={"description": "missing ScheduledTask",
                      "missing_concept": "ScheduledTask"},
    ))
    row = s.list_recent(10)[0]
    assert row["semantic_gap"]["missing_concept"] == "ScheduledTask"
    s.close()
