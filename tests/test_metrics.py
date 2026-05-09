"""阶段 4 A 段：评测看板指标层 TDD（纯函数无 LLM）。"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import pytest


# =========================================================
# Fixtures
# =========================================================

def _judg(alert_id: str, verdict: str, conf: float = 0.65) -> Dict[str, Any]:
    return {
        "alert_id": alert_id, "verdict": verdict,
        "confidence": conf, "evidence_refs": [{"type": "matched_field", "ref": "x"}],
        "ontology_version": "1.0", "semantic_gap": None,
    }


def _alert(alert_id: str, rule_id: str) -> Dict[str, Any]:
    return {"alert_id": alert_id, "rule_id": rule_id, "computer": "X"}


def _sig(signal_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    return {"signal_type": signal_type, "payload": payload,
            "source_layer": "ui", "priority": "warm"}


# =========================================================
# 研判准确率
# =========================================================

def test_judgment_accuracy_perfect() -> None:
    from evolution.metrics import compute_judgment_accuracy
    judgments = [_judg("a1", "malicious"), _judg("a2", "suspicious")]
    alerts = [_alert("a1", "r1"), _alert("a2", "r2")]
    gt = {"r1": "malicious", "r2": "suspicious"}
    acc, correct, total, breakdown = compute_judgment_accuracy(judgments, alerts, gt)
    assert acc == 1.0
    assert correct == 2 and total == 2


def test_judgment_accuracy_zero() -> None:
    from evolution.metrics import compute_judgment_accuracy
    judgments = [_judg("a1", "benign"), _judg("a2", "benign")]
    alerts = [_alert("a1", "r1"), _alert("a2", "r2")]
    gt = {"r1": "malicious", "r2": "suspicious"}
    acc, correct, total, _ = compute_judgment_accuracy(judgments, alerts, gt)
    assert acc == 0.0
    assert correct == 0 and total == 2


def test_judgment_accuracy_partial() -> None:
    """5/10 = 0.5，对应 v1.0 实测：r1 ✓ + r2×3 ✓ + r5 ✓ ；r3×3 / r4 / r6 ✗。"""
    from evolution.metrics import compute_judgment_accuracy
    judgments = [
        _judg("a1", "malicious"),    # r1: malicious ✓
        _judg("a2", "suspicious"),   # r2 ✓
        _judg("a3", "suspicious"),   # r2 ✓
        _judg("a4", "suspicious"),   # r2 ✓
        _judg("a5", "suspicious"),   # r3 ✗ (gt malicious)
        _judg("a6", "suspicious"),   # r3 ✗
        _judg("a7", "suspicious"),   # r3 ✗
        _judg("a8", "suspicious"),   # r4 ✗ (gt malicious)
        _judg("a9", "suspicious"),   # r5 ✓
        _judg("a10", "suspicious"),  # r6 ✗ (gt malicious)
    ]
    alerts = [
        _alert("a1", "r1"), _alert("a2", "r2"), _alert("a3", "r2"),
        _alert("a4", "r2"), _alert("a5", "r3"), _alert("a6", "r3"),
        _alert("a7", "r3"), _alert("a8", "r4"), _alert("a9", "r5"),
        _alert("a10", "r6"),
    ]
    gt = {"r1": "malicious", "r2": "suspicious", "r3": "malicious",
          "r4": "malicious", "r5": "suspicious", "r6": "malicious"}
    acc, correct, total, breakdown = compute_judgment_accuracy(judgments, alerts, gt)
    assert correct == 5
    assert total == 10
    assert acc == 0.5
    # breakdown 拆到每条规则
    assert breakdown["r1"] == (1, 1)
    assert breakdown["r2"] == (3, 3)
    assert breakdown["r3"] == (0, 3)
    assert breakdown["r6"] == (0, 1)


def test_judgment_accuracy_skips_alerts_without_ground_truth() -> None:
    from evolution.metrics import compute_judgment_accuracy
    judgments = [_judg("a1", "malicious"), _judg("a2", "suspicious")]
    alerts = [_alert("a1", "r1"), _alert("a2", "rXX")]   # rXX 不在 gt
    gt = {"r1": "malicious"}
    acc, correct, total, _ = compute_judgment_accuracy(judgments, alerts, gt)
    assert correct == 1 and total == 1
    assert acc == 1.0


def test_judgment_accuracy_zero_total_returns_zero_safely() -> None:
    from evolution.metrics import compute_judgment_accuracy
    acc, correct, total, _ = compute_judgment_accuracy([], [], {})
    assert acc == 0.0 and correct == 0 and total == 0


# =========================================================
# 反馈采纳率
# =========================================================

def test_feedback_adoption_zero_when_no_signals() -> None:
    from evolution.metrics import compute_feedback_adoption
    rate, up, down, total = compute_feedback_adoption(signals=[], judgment_count=10)
    assert rate == 0.0
    assert up == 0 and down == 0


def test_feedback_adoption_counts_thumbs() -> None:
    from evolution.metrics import compute_feedback_adoption
    sigs = [
        _sig("manual_annotation", {"feedback": "up", "judgment_id": "j1"}),
        _sig("manual_annotation", {"feedback": "up", "judgment_id": "j2"}),
        _sig("manual_annotation", {"feedback": "down", "judgment_id": "j3"}),
        _sig("unrelated", {"x": 1}),  # 应被忽略
    ]
    rate, up, down, total = compute_feedback_adoption(signals=sigs, judgment_count=10)
    assert up == 2
    assert down == 1
    # 3 / 10 = 0.3
    assert rate == pytest.approx(0.3)


def test_feedback_adoption_zero_judgment_count() -> None:
    from evolution.metrics import compute_feedback_adoption
    rate, _, _, _ = compute_feedback_adoption(signals=[], judgment_count=0)
    assert rate == 0.0


# =========================================================
# 本体覆盖率
# =========================================================

def test_ontology_coverage_full() -> None:
    from evolution.metrics import compute_ontology_coverage
    cov, parsed, total = compute_ontology_coverage(
        parsed_count=2297, anomaly_pool_open=0)
    assert cov == 1.0


def test_ontology_coverage_partial() -> None:
    from evolution.metrics import compute_ontology_coverage
    cov, parsed, total = compute_ontology_coverage(
        parsed_count=2297, anomaly_pool_open=10)
    assert cov == pytest.approx(2297 / 2307, rel=1e-4)


def test_ontology_coverage_zero_data() -> None:
    from evolution.metrics import compute_ontology_coverage
    cov, parsed, total = compute_ontology_coverage(parsed_count=0,
                                                    anomaly_pool_open=0)
    assert cov == 0.0


# =========================================================
# MetricsSnapshot
# =========================================================

def test_metrics_snapshot_to_dict_and_emoji_status() -> None:
    from evolution.metrics import MetricsSnapshot
    snap = MetricsSnapshot(
        timestamp="2026-05-09T10:00:00Z",
        judgment_accuracy=0.5, accuracy_correct=5, accuracy_total=10,
        accuracy_breakdown={"r1": (1, 1)},
        feedback_adoption=0.3, feedback_thumbs_up=2, feedback_thumbs_down=1,
        feedback_total_judgments=10,
        ontology_coverage=0.99, parsed_event_count=2297, total_event_count=2307,
        anomaly_pool_size_open=10, anomaly_pool_size_total=32,
        anomaly_pool_size_open_by_event_id={4702: 8, 5140: 1, 5145: 1},
    )
    d = snap.to_dict()
    assert d["judgment_accuracy"] == 0.5
    assert d["anomaly_pool_size_open"] == 10
    assert d["feedback_adoption"] == 0.3


# =========================================================
# 加载 ground_truth.yaml
# =========================================================

def test_load_ground_truth_yaml_returns_rule_to_verdict_map() -> None:
    from evolution.metrics import load_ground_truth
    gt = load_ground_truth(Path("data/ground_truth.yaml"))
    # 至少应含 demo 数据集的 6 条规则
    assert "r1-lsass-memory-dump" in gt
    assert gt["r1-lsass-memory-dump"] == "malicious"
    assert gt["r2-anomalous-service-account-logon"] == "suspicious"


def test_load_ground_truth_missing_file_returns_empty() -> None:
    from evolution.metrics import load_ground_truth
    gt = load_ground_truth(Path("data/does_not_exist.yaml"))
    assert gt == {}


# =========================================================
# 顶层 collect_metrics
# =========================================================

def test_collect_metrics_returns_snapshot(tmp_path) -> None:
    """组合所有指标 → MetricsSnapshot。"""
    from evolution.metrics import collect_metrics
    judgments = [_judg("a1", "malicious"), _judg("a2", "suspicious")]
    alerts = [_alert("a1", "r1"), _alert("a2", "r2")]
    gt = {"r1": "malicious", "r2": "suspicious"}
    snap = collect_metrics(
        judgments=judgments, alerts=alerts, ground_truth=gt,
        signals=[], parsed_event_count=2297, anomaly_pool_size_open=10,
        anomaly_pool_size_total=32,
        anomaly_pool_size_open_by_event_id={4702: 8},
    )
    assert snap.accuracy_correct == 2
    assert snap.feedback_adoption == 0.0
    assert snap.anomaly_pool_size_open == 10
