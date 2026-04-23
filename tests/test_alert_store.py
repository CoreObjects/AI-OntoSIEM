"""组件 4 告警存储单测。"""
from __future__ import annotations

from pathlib import Path

import pytest


def _mk_alert(alert_id="a-1", rule_id="r-1", event_record_id=42, techniques=None):
    from detection.engine import Alert
    return Alert(
        alert_id=alert_id,
        rule_id=rule_id,
        rule_title="test rule",
        severity="high",
        event_record_id=event_record_id,
        event_id=4624,
        channel="Security",
        computer="H1",
        timestamp="2026-04-22T10:00:00Z",
        attack_techniques=list(techniques or ["T1078"]),
        matched_fields={"EventData.LogonType": 2},
        ontology_version="1.0",
        raw_event={"event_id": 4624, "event_data": {"LogonType": 2}},
    )


def test_alert_store_insert_and_count(tmp_path: Path) -> None:
    from storage.alert_store import AlertStore

    store = AlertStore(db_path=tmp_path / "alerts.duckdb")
    assert store.count() == 0
    store.insert(_mk_alert("a-1"))
    store.insert(_mk_alert("a-2"))
    assert store.count() == 2
    store.close()


def test_alert_store_insert_many(tmp_path: Path) -> None:
    from storage.alert_store import AlertStore

    store = AlertStore(db_path=tmp_path / "alerts.duckdb")
    store.insert_many([_mk_alert("a-1"), _mk_alert("a-2"), _mk_alert("a-3")])
    assert store.count() == 3
    store.close()


def test_alert_store_duplicate_id_is_idempotent(tmp_path: Path) -> None:
    from storage.alert_store import AlertStore

    store = AlertStore(db_path=tmp_path / "alerts.duckdb")
    store.insert(_mk_alert("a-1"))
    store.insert(_mk_alert("a-1"))
    assert store.count() == 1
    store.close()


def test_alert_store_list_recent_returns_full_fields(tmp_path: Path) -> None:
    from storage.alert_store import AlertStore

    store = AlertStore(db_path=tmp_path / "alerts.duckdb")
    store.insert(_mk_alert("a-1", techniques=["T1078", "T1021"]))
    recent = store.list_recent(limit=10)
    assert len(recent) == 1
    row = recent[0]
    assert row["alert_id"] == "a-1"
    assert row["rule_id"] == "r-1"
    assert row["severity"] == "high"
    assert row["computer"] == "H1"
    assert row["attack_techniques"] == ["T1078", "T1021"]
    assert row["matched_fields"] == {"EventData.LogonType": 2}
    assert row["raw_event"]["event_id"] == 4624
    store.close()


def test_alert_store_count_by_technique(tmp_path: Path) -> None:
    from storage.alert_store import AlertStore

    store = AlertStore(db_path=tmp_path / "alerts.duckdb")
    store.insert(_mk_alert("a-1", techniques=["T1078"]))
    store.insert(_mk_alert("a-2", techniques=["T1078", "T1021"]))
    store.insert(_mk_alert("a-3", techniques=["T1053"]))
    counts = store.count_by_technique()
    assert counts["T1078"] == 2
    assert counts["T1021"] == 1
    assert counts["T1053"] == 1
    store.close()
