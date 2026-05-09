"""组件 10 Day 5：RollbackProposer TDD（纯函数无 LLM）。

输入 ValidatorReport → 评估指标恶化 → 输出 RollbackProposal（含触发原因 + 严重等级）。
人工审核才能 apply rollback；自动只是产候选（R8 风险：演化空转 缓解）。
"""
from __future__ import annotations

from typing import Any, Dict, List

import pytest

from evolution.replay_validator import ValidatorReport, VerdictChange


# =========================================================
# Fixtures
# =========================================================

def _make_report(**kwargs) -> ValidatorReport:
    defaults = dict(
        started_at="t1", finished_at="t2",
        ontology_version_before="1.0", ontology_version_after="1.1",
        pool_open_before=32, pool_open_after=10,
        rejudged_count=10,
        verdict_changes=[],
        verdict_unchanged=10, verdict_upgraded=0, verdict_downgraded=0,
        semantic_gap_cleared=0, semantic_gap_persisted=0,
        avg_evidence_refs_before=8.0, avg_evidence_refs_after=8.0,
    )
    defaults.update(kwargs)
    return ValidatorReport(**defaults)


# =========================================================
# Dataclass
# =========================================================

def test_rollback_proposal_dataclass_fields() -> None:
    from evolution.rollback_proposer import RollbackProposal
    p = RollbackProposal(
        proposal_id="rb-1",
        target_version="1.0", current_version="1.1",
        triggered_by_metrics={"verdict_downgraded": 3},
        rationale="3 条 verdict 被降级，0 条升级",
        severity="critical",
    )
    assert p.status == "pending"
    assert p.suggested_action == "rollback"


def test_rollback_proposal_to_dict() -> None:
    from evolution.rollback_proposer import RollbackProposal
    p = RollbackProposal(
        proposal_id="rb-1",
        target_version="1.0", current_version="1.1",
        triggered_by_metrics={"x": 1},
        rationale="r", severity="warning",
    )
    d = p.to_dict()
    assert d["proposal_id"] == "rb-1"
    assert d["target_version"] == "1.0"
    assert d["severity"] == "warning"


# =========================================================
# 不触发回滚（指标改善 / 持平）
# =========================================================

def test_no_rollback_when_metrics_improve() -> None:
    from evolution.rollback_proposer import assess_for_rollback
    report = _make_report(
        verdict_upgraded=2, verdict_downgraded=0,
        semantic_gap_cleared=3, semantic_gap_persisted=0,
        avg_evidence_refs_before=6.0, avg_evidence_refs_after=8.0,
    )
    assert assess_for_rollback(report) is None


def test_no_rollback_when_metrics_unchanged() -> None:
    from evolution.rollback_proposer import assess_for_rollback
    report = _make_report()  # 全 0 变化
    assert assess_for_rollback(report) is None


# =========================================================
# 触发 - verdict 净降级
# =========================================================

def test_rollback_when_more_downgraded_than_upgraded() -> None:
    """downgraded > upgraded → 回滚提议（核心 demo 场景：LSASS 被 LLM 误降）。"""
    from evolution.rollback_proposer import assess_for_rollback
    report = _make_report(
        verdict_upgraded=0, verdict_downgraded=2,
    )
    p = assess_for_rollback(report)
    assert p is not None
    assert p.target_version == "1.0"
    assert p.current_version == "1.1"
    assert "downgraded" in p.rationale.lower() or "降级" in p.rationale
    assert p.severity in {"critical", "warning"}


def test_rollback_severity_critical_for_large_downgrade() -> None:
    """downgrade 显著（>= 30% rejudged）→ critical 级别。"""
    from evolution.rollback_proposer import assess_for_rollback
    report = _make_report(
        rejudged_count=10,
        verdict_downgraded=4, verdict_upgraded=0,
    )
    p = assess_for_rollback(report)
    assert p is not None
    assert p.severity == "critical"


def test_rollback_severity_warning_for_minor_downgrade() -> None:
    from evolution.rollback_proposer import assess_for_rollback
    report = _make_report(
        rejudged_count=10,
        verdict_downgraded=1, verdict_upgraded=0,
    )
    p = assess_for_rollback(report)
    assert p is not None
    assert p.severity == "warning"


# =========================================================
# 触发 - semantic_gap 持续 >> 清除
# =========================================================

def test_rollback_when_semantic_gap_persists_dominant() -> None:
    """演化升级后大量 gap 仍在 → 演化没解决核心问题（信号）。"""
    from evolution.rollback_proposer import assess_for_rollback
    report = _make_report(
        semantic_gap_cleared=1, semantic_gap_persisted=8,
    )
    p = assess_for_rollback(report)
    assert p is not None
    assert "semantic_gap" in p.rationale.lower() or "gap" in p.rationale.lower()


# =========================================================
# 触发 - evidence_refs 大幅减少
# =========================================================

def test_rollback_when_evidence_refs_drop_significantly() -> None:
    """avg_refs_after < 70% of before → LLM 推理深度可能下降。"""
    from evolution.rollback_proposer import assess_for_rollback
    report = _make_report(
        avg_evidence_refs_before=10.0, avg_evidence_refs_after=6.0,
    )
    p = assess_for_rollback(report)
    assert p is not None
    assert "evidence" in p.rationale.lower() or "证据" in p.rationale


def test_no_rollback_when_evidence_refs_drop_marginal() -> None:
    """微降（>70% 保留）不触发。"""
    from evolution.rollback_proposer import assess_for_rollback
    report = _make_report(
        avg_evidence_refs_before=8.0, avg_evidence_refs_after=7.5,
    )
    assert assess_for_rollback(report) is None


# =========================================================
# 统计噪音过滤
# =========================================================

def test_no_rollback_for_too_few_rejudged() -> None:
    """rejudged_count < min_rejudged → 拒触发（避免单条噪音搅局）。"""
    from evolution.rollback_proposer import assess_for_rollback
    report = _make_report(
        rejudged_count=2,
        verdict_downgraded=2, verdict_upgraded=0,  # 100% 降级，但样本太少
    )
    assert assess_for_rollback(report) is None


def test_min_rejudged_can_be_overridden() -> None:
    from evolution.rollback_proposer import assess_for_rollback
    report = _make_report(
        rejudged_count=3, verdict_downgraded=2, verdict_upgraded=0,
    )
    # 默认阈值（5）下应不触发
    assert assess_for_rollback(report) is None
    # 显式降低阈值后触发
    p = assess_for_rollback(report, require_min_rejudged=3)
    assert p is not None


# =========================================================
# triggered_by_metrics 含完整原始数据
# =========================================================

def test_proposal_carries_triggering_metrics() -> None:
    """rationale 要文字化；triggered_by_metrics 应保留原始数字便于审计。"""
    from evolution.rollback_proposer import assess_for_rollback
    report = _make_report(
        verdict_upgraded=0, verdict_downgraded=3,
        semantic_gap_cleared=1, semantic_gap_persisted=4,
        avg_evidence_refs_before=8.0, avg_evidence_refs_after=5.0,
    )
    p = assess_for_rollback(report)
    assert p is not None
    m = p.triggered_by_metrics
    assert m["verdict_downgraded"] == 3
    assert m["verdict_upgraded"] == 0
    assert m["pool_open_before"] == 32
    assert m["pool_open_after"] == 10
