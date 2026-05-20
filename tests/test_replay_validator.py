"""组件 10 Day 4：ReplayValidator TDD（纯 diff 函数 — 无 LLM）。

用 mock 数据对比老/新 judgments，输出 ValidatorReport。
"""
from __future__ import annotations

from typing import Any, Dict, List

import pytest

from reasoning.judgment_engine import Judgment


# =========================================================
# Fixtures
# =========================================================

def _old(alert_id: str, verdict: str, conf: float, *,
         refs: int = 3, semantic_gap: bool = False) -> Dict[str, Any]:
    """模拟 JudgmentStore.list_recent 返回的 dict（v1.0 时代的老判决）。"""
    return {
        "judgment_id": f"old-{alert_id}",
        "alert_id": alert_id,
        "verdict": verdict,
        "confidence": conf,
        "reasoning_steps": ["step1", "step2"],
        "evidence_refs": [
            {"type": "matched_field", "ref": f"field_{i}"} for i in range(refs)
        ],
        "attack_chain": ["T1003"],
        "next_steps": ["isolate"],
        "ontology_version": "1.0",
        "semantic_gap": ({"missing_concept": "X"} if semantic_gap else None),
        "needs_review": conf < 0.5,
        "created_at": "2026-04-23T10:00:00Z",
    }


def _new(alert_id: str, verdict: str, conf: float, *,
         refs: List[Dict[str, Any]] = None,
         semantic_gap: bool = False,
         ontology_version: str = "1.1") -> Judgment:
    """模拟 JudgmentEngine.judge 返回的新 Judgment。"""
    if refs is None:
        refs = [{"type": "matched_field", "ref": "field_0"}]
    return Judgment(
        judgment_id=f"new-{alert_id}",
        alert_id=alert_id,
        verdict=verdict,
        confidence=conf,
        reasoning_steps=["s1"],
        evidence_refs=refs,
        attack_chain=["T1053.005"],
        next_steps=["investigate"],
        ontology_version=ontology_version,
        semantic_gap=({"missing_concept": "Y"} if semantic_gap else None),
        needs_review=conf < 0.5,
    )


# =========================================================
# Dataclass schema
# =========================================================

def test_rejudge_alerts_calls_progress_cb_per_alert() -> None:
    """progress_cb 每条 alert 回调一次，喂 UI 进度条。"""
    from evolution.replay_validator import rejudge_alerts

    class _A:
        def __init__(self, aid):
            self.alert_id = aid
            self.rule_id = "r-" + aid

    class _Engine:
        def judge(self, a):
            return _new(a.alert_id, "suspicious", 0.65)

    alerts = [_A("a1"), _A("a2"), _A("a3")]
    seen = []
    out = rejudge_alerts(_Engine(), alerts,
                         progress_cb=lambda i, n, a, j: seen.append((i, n, a.alert_id, j.verdict)))
    assert len(out) == 3
    assert seen == [(1, 3, "a1", "suspicious"),
                    (2, 3, "a2", "suspicious"),
                    (3, 3, "a3", "suspicious")]


def test_validator_report_dataclass_fields() -> None:
    from evolution.replay_validator import ValidatorReport
    r = ValidatorReport(
        started_at="t1", finished_at="t2",
        ontology_version_before="1.0", ontology_version_after="1.1",
        pool_open_before=32, pool_open_after=10,
        rejudged_count=10,
        verdict_changes=[],
        verdict_unchanged=8, verdict_upgraded=1, verdict_downgraded=1,
        semantic_gap_cleared=4, semantic_gap_persisted=2,
        avg_evidence_refs_before=3.0, avg_evidence_refs_after=4.5,
    )
    d = r.to_dict()
    assert d["pool_open_before"] == 32
    assert d["pool_open_after"] == 10
    assert d["semantic_gap_cleared"] == 4


def test_verdict_change_dataclass_fields() -> None:
    from evolution.replay_validator import VerdictChange
    vc = VerdictChange(
        alert_id="a-1",
        before_verdict="suspicious", after_verdict="malicious",
        before_confidence=0.65, after_confidence=0.9,
        before_evidence_count=3, after_evidence_count=5,
        new_graph_node_refs=["ScheduledTask:HR-WS-01:T"],
        semantic_gap_cleared=True, notes="",
    )
    assert vc.delta == "upgraded"


# =========================================================
# 基础 diff
# =========================================================

def test_diff_zero_changes_for_identical(pool_before=0, pool_after=0) -> None:
    from evolution.replay_validator import compare_judgments
    before = [_old("a-1", "suspicious", 0.65)]
    after = [_new("a-1", "suspicious", 0.65,
                  refs=[{"type": "matched_field", "ref": "field_0"},
                        {"type": "matched_field", "ref": "field_1"},
                        {"type": "matched_field", "ref": "field_2"}])]
    r = compare_judgments(before, after, pool_open_before=10, pool_open_after=10)
    assert r.rejudged_count == 1
    assert r.verdict_unchanged == 1
    assert r.verdict_upgraded == 0
    assert r.verdict_downgraded == 0


def test_diff_counts_verdict_upgrades() -> None:
    from evolution.replay_validator import compare_judgments
    before = [_old("a-1", "suspicious", 0.65),
              _old("a-2", "benign", 0.4)]
    after = [_new("a-1", "malicious", 0.9),
             _new("a-2", "suspicious", 0.7)]
    r = compare_judgments(before, after, pool_open_before=10, pool_open_after=5)
    assert r.verdict_upgraded == 2
    assert r.verdict_unchanged == 0


def test_diff_counts_verdict_downgrades() -> None:
    from evolution.replay_validator import compare_judgments
    before = [_old("a-1", "malicious", 0.95)]
    after = [_new("a-1", "suspicious", 0.6)]
    r = compare_judgments(before, after, pool_open_before=10, pool_open_after=10)
    assert r.verdict_downgraded == 1


def test_diff_counts_unchanged() -> None:
    from evolution.replay_validator import compare_judgments
    before = [_old("a-1", "suspicious", 0.65),
              _old("a-2", "malicious", 0.95)]
    after = [_new("a-1", "suspicious", 0.7),
             _new("a-2", "malicious", 0.95)]
    r = compare_judgments(before, after, pool_open_before=10, pool_open_after=5)
    assert r.verdict_unchanged == 2


# =========================================================
# semantic_gap 状态
# =========================================================

def test_diff_counts_semantic_gap_cleared() -> None:
    from evolution.replay_validator import compare_judgments
    before = [_old("a-1", "suspicious", 0.65, semantic_gap=True),
              _old("a-2", "suspicious", 0.6, semantic_gap=True)]
    after = [_new("a-1", "suspicious", 0.7, semantic_gap=False),    # cleared
             _new("a-2", "suspicious", 0.65, semantic_gap=True)]    # persisted
    r = compare_judgments(before, after, pool_open_before=10, pool_open_after=5)
    assert r.semantic_gap_cleared == 1
    assert r.semantic_gap_persisted == 1


# =========================================================
# evidence_refs 增量
# =========================================================

def test_diff_avg_evidence_refs() -> None:
    from evolution.replay_validator import compare_judgments
    before = [_old("a-1", "suspicious", 0.65, refs=2),     # 2 refs
              _old("a-2", "suspicious", 0.65, refs=4)]      # 4 refs → 平均 3.0
    after = [_new("a-1", "suspicious", 0.7,
                  refs=[{"type": "matched_field", "ref": f} for f in
                        ["a", "b", "c"]]),                 # 3 refs
             _new("a-2", "suspicious", 0.7,
                  refs=[{"type": "matched_field", "ref": f} for f in
                        ["a", "b", "c", "d", "e"]])]       # 5 refs → 平均 4.0
    r = compare_judgments(before, after, pool_open_before=10, pool_open_after=5)
    assert r.avg_evidence_refs_before == pytest.approx(3.0)
    assert r.avg_evidence_refs_after == pytest.approx(4.0)


def test_diff_records_new_graph_node_refs() -> None:
    """新 judgment 引用了 ScheduledTask 节点 → 在 VerdictChange.new_graph_node_refs 体现。"""
    from evolution.replay_validator import compare_judgments
    before = [_old("a-1", "suspicious", 0.65, refs=2)]
    after = [_new("a-1", "malicious", 0.9, refs=[
        {"type": "matched_field", "ref": "field_0"},
        {"type": "graph_node", "ref": "ScheduledTask:HR-WS-01:\\T"},
        {"type": "graph_node", "ref": "Account:S-1-5..."},
    ])]
    r = compare_judgments(before, after, pool_open_before=10, pool_open_after=5)
    assert r.verdict_changes
    vc = r.verdict_changes[0]
    assert vc.new_graph_node_refs == [
        "ScheduledTask:HR-WS-01:\\T",
        "Account:S-1-5...",
    ]


# =========================================================
# Pool delta + ontology versions
# =========================================================

def test_diff_carries_pool_sizes_and_versions() -> None:
    from evolution.replay_validator import compare_judgments
    before = [_old("a-1", "suspicious", 0.65)]
    after = [_new("a-1", "suspicious", 0.65, ontology_version="1.1")]
    r = compare_judgments(before, after, pool_open_before=32, pool_open_after=10,
                          ontology_version_before="1.0",
                          ontology_version_after="1.1")
    assert r.pool_open_before == 32
    assert r.pool_open_after == 10
    assert r.ontology_version_before == "1.0"
    assert r.ontology_version_after == "1.1"


# =========================================================
# 不匹配的 alert_id（before/after 不一一对应）
# =========================================================

def test_diff_handles_mismatched_alert_ids() -> None:
    """新 judgment 缺一条对应的老 judgment → 跳过，不计入 changes 也不报错。"""
    from evolution.replay_validator import compare_judgments
    before = [_old("a-1", "suspicious", 0.65)]
    after = [_new("a-2", "malicious", 0.9)]   # alert_id 对不上
    r = compare_judgments(before, after, pool_open_before=10, pool_open_after=5)
    # rejudged_count = after 中能匹配的 = 0
    assert r.rejudged_count == 0
    assert r.verdict_changes == []
