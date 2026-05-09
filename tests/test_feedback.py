"""阶段 4 B 段：审核员反馈写信号 TDD（无 LLM）。"""
from __future__ import annotations

from typing import Any, Dict, List

import pytest


# =========================================================
# Fake SignalHub
# =========================================================

class FakeHub:
    def __init__(self):
        self.calls: List[Dict[str, Any]] = []

    def report_signal(
        self, source_layer: str, signal_type: str, payload: Dict[str, Any],
        *, aggregation_key=None, ontology_version=None,
        priority=None, timestamp=None,
    ):
        self.calls.append({
            "source_layer": source_layer,
            "signal_type": signal_type,
            "payload": dict(payload),
            "aggregation_key": aggregation_key,
            "priority": priority,
        })
        return {"signal_id": f"fake-{len(self.calls)}"}


# =========================================================
# 写入
# =========================================================

def test_record_feedback_writes_manual_annotation_signal() -> None:
    from evolution.feedback import record_feedback
    hub = FakeHub()
    record_feedback(hub, judgment_id="j-123", feedback="up")
    assert len(hub.calls) == 1
    c = hub.calls[0]
    assert c["source_layer"] == "copilot"
    assert c["signal_type"] == "manual_annotation"
    assert c["payload"]["feedback"] == "up"
    assert c["payload"]["judgment_id"] == "j-123"


def test_record_feedback_includes_alert_id_when_given() -> None:
    from evolution.feedback import record_feedback
    hub = FakeHub()
    record_feedback(hub, judgment_id="j-1", feedback="down", alert_id="a-1")
    assert hub.calls[0]["payload"]["alert_id"] == "a-1"


def test_record_feedback_includes_notes_when_given() -> None:
    from evolution.feedback import record_feedback
    hub = FakeHub()
    record_feedback(hub, judgment_id="j-1", feedback="down",
                    notes="LSASS dump 应被判 malicious")
    assert hub.calls[0]["payload"]["notes"] == "LSASS dump 应被判 malicious"


def test_record_feedback_aggregation_key_separates_up_and_down() -> None:
    """聚合键含 feedback 类型，看板可分别统计 👍 / 👎 数。"""
    from evolution.feedback import record_feedback
    hub = FakeHub()
    record_feedback(hub, judgment_id="j-1", feedback="up")
    record_feedback(hub, judgment_id="j-2", feedback="down")
    keys = [c["aggregation_key"] for c in hub.calls]
    assert "up" in keys[0]
    assert "down" in keys[1]
    assert keys[0] != keys[1]


def test_record_feedback_skips_optional_keys_when_not_given() -> None:
    from evolution.feedback import record_feedback
    hub = FakeHub()
    record_feedback(hub, judgment_id="j-1", feedback="up")
    payload = hub.calls[0]["payload"]
    assert "alert_id" not in payload
    assert "notes" not in payload


# =========================================================
# 校验
# =========================================================

def test_record_feedback_rejects_invalid_value() -> None:
    from evolution.feedback import record_feedback
    hub = FakeHub()
    with pytest.raises(ValueError):
        record_feedback(hub, judgment_id="j-1", feedback="thumbs_sideways")
    assert hub.calls == []


def test_record_feedback_rejects_empty_judgment_id() -> None:
    from evolution.feedback import record_feedback
    hub = FakeHub()
    with pytest.raises(ValueError):
        record_feedback(hub, judgment_id="", feedback="up")


# =========================================================
# 真 SignalHub 集成（落库）
# =========================================================

def test_record_feedback_with_real_hub_persists_to_db(tmp_path) -> None:
    from evolution.feedback import record_feedback
    from evolution.signal_hub import SignalHub
    db = tmp_path / "signals.duckdb"
    hub = SignalHub(db_path=db)
    record_feedback(hub, judgment_id="j-1", feedback="up", alert_id="a-1")
    record_feedback(hub, judgment_id="j-2", feedback="down")

    rows = hub.list_recent(limit=10)
    types = [r["signal_type"] for r in rows]
    assert types.count("manual_annotation") == 2
    feedbacks = sorted(r["payload"]["feedback"] for r in rows
                       if r["signal_type"] == "manual_annotation")
    assert feedbacks == ["down", "up"]
