"""组件 10 Day 4：演化前/后 diff 报告。

两个职责：
  - `compare_judgments(before, after, ...)`：纯 diff 函数，无 LLM
  - `rejudge_alerts(engine, alerts)`：调真 LLM 重判（脚本用）

ValidatorReport 字段对齐 Demo §8 "回放报告对比"叙事：
  - 异常池规模（来自 ReplayReport，传入即可）
  - judgment verdict 变化（upgrade / downgrade / unchanged）
  - semantic_gap 清零率
  - evidence_refs 增量（avg before/after）
  - 详细 VerdictChange 列表（含新引用的 graph_node ref）
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from reasoning.judgment_engine import Judgment

logger = logging.getLogger(__name__)


# verdict 等级映射（用于判 upgrade / downgrade）
_VERDICT_LEVEL: Dict[str, int] = {
    "benign": 0,
    "suspicious": 1,
    "malicious": 2,
}


# =========================================================
# Dataclasses
# =========================================================

@dataclass
class VerdictChange:
    alert_id: str
    before_verdict: str
    after_verdict: str
    before_confidence: float
    after_confidence: float
    before_evidence_count: int
    after_evidence_count: int
    new_graph_node_refs: List[str] = field(default_factory=list)
    semantic_gap_cleared: bool = False
    notes: str = ""

    @property
    def delta(self) -> str:
        """返回 'upgraded' / 'downgraded' / 'unchanged' / 'unknown_to_known'。"""
        b = _VERDICT_LEVEL.get(self.before_verdict)
        a = _VERDICT_LEVEL.get(self.after_verdict)
        if b is None or a is None:
            return "unchanged" if self.before_verdict == self.after_verdict else "ambiguous"
        if a > b:
            return "upgraded"
        if a < b:
            return "downgraded"
        return "unchanged"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "before_verdict": self.before_verdict,
            "after_verdict": self.after_verdict,
            "before_confidence": self.before_confidence,
            "after_confidence": self.after_confidence,
            "before_evidence_count": self.before_evidence_count,
            "after_evidence_count": self.after_evidence_count,
            "new_graph_node_refs": list(self.new_graph_node_refs),
            "semantic_gap_cleared": self.semantic_gap_cleared,
            "delta": self.delta,
            "notes": self.notes,
        }


@dataclass
class ValidatorReport:
    started_at: str
    finished_at: str
    ontology_version_before: str
    ontology_version_after: str

    # 异常池
    pool_open_before: int
    pool_open_after: int

    # 重判数量
    rejudged_count: int

    # 详细变更
    verdict_changes: List[VerdictChange] = field(default_factory=list)

    # 汇总
    verdict_unchanged: int = 0
    verdict_upgraded: int = 0
    verdict_downgraded: int = 0
    semantic_gap_cleared: int = 0
    semantic_gap_persisted: int = 0
    avg_evidence_refs_before: float = 0.0
    avg_evidence_refs_after: float = 0.0

    @property
    def pool_delta(self) -> int:
        """negative = improvement（异常池缩小）。"""
        return self.pool_open_after - self.pool_open_before

    def to_dict(self) -> Dict[str, Any]:
        return {
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "ontology_version_before": self.ontology_version_before,
            "ontology_version_after": self.ontology_version_after,
            "pool_open_before": self.pool_open_before,
            "pool_open_after": self.pool_open_after,
            "pool_delta": self.pool_delta,
            "rejudged_count": self.rejudged_count,
            "verdict_unchanged": self.verdict_unchanged,
            "verdict_upgraded": self.verdict_upgraded,
            "verdict_downgraded": self.verdict_downgraded,
            "semantic_gap_cleared": self.semantic_gap_cleared,
            "semantic_gap_persisted": self.semantic_gap_persisted,
            "avg_evidence_refs_before": self.avg_evidence_refs_before,
            "avg_evidence_refs_after": self.avg_evidence_refs_after,
            "verdict_changes": [c.to_dict() for c in self.verdict_changes],
        }


# =========================================================
# 纯 diff 函数（无 LLM 副作用）
# =========================================================

def compare_judgments(
    before: List[Dict[str, Any]],
    after: List[Judgment],
    *,
    pool_open_before: int = 0,
    pool_open_after: int = 0,
    ontology_version_before: str = "",
    ontology_version_after: str = "",
) -> ValidatorReport:
    started_at = _now_iso()
    before_by_id = {j["alert_id"]: j for j in before}

    changes: List[VerdictChange] = []
    unchanged = upgraded = downgraded = 0
    sg_cleared = sg_persisted = 0

    for new_j in after:
        old_j = before_by_id.get(new_j.alert_id)
        if old_j is None:
            continue  # 新 judgment 没对应的 before — 跳过

        # 收集老/新 evidence_refs
        old_refs = old_j.get("evidence_refs") or []
        new_refs = new_j.evidence_refs or []
        old_ref_keys = {(r.get("type"), r.get("ref")) for r in old_refs}
        new_graph_refs = [
            r["ref"] for r in new_refs
            if r.get("type") == "graph_node" and (r.get("type"), r.get("ref")) not in old_ref_keys
        ]

        # semantic_gap 状态
        had_gap = bool(old_j.get("semantic_gap"))
        has_gap = bool(new_j.semantic_gap)
        cleared = had_gap and not has_gap
        if had_gap:
            if cleared:
                sg_cleared += 1
            else:
                sg_persisted += 1

        change = VerdictChange(
            alert_id=new_j.alert_id,
            before_verdict=str(old_j.get("verdict") or ""),
            after_verdict=new_j.verdict,
            before_confidence=float(old_j.get("confidence") or 0.0),
            after_confidence=float(new_j.confidence),
            before_evidence_count=len(old_refs),
            after_evidence_count=len(new_refs),
            new_graph_node_refs=new_graph_refs,
            semantic_gap_cleared=cleared,
        )
        changes.append(change)

        d = change.delta
        if d == "upgraded":
            upgraded += 1
        elif d == "downgraded":
            downgraded += 1
        else:
            unchanged += 1

    rejudged = len(changes)
    avg_before = (
        sum(len(j.get("evidence_refs") or []) for j in before) / max(len(before), 1)
        if before else 0.0
    )
    avg_after = (
        sum(len(j.evidence_refs) for j in after) / max(len(after), 1)
        if after else 0.0
    )

    return ValidatorReport(
        started_at=started_at,
        finished_at=_now_iso(),
        ontology_version_before=ontology_version_before,
        ontology_version_after=ontology_version_after,
        pool_open_before=pool_open_before,
        pool_open_after=pool_open_after,
        rejudged_count=rejudged,
        verdict_changes=changes,
        verdict_unchanged=unchanged,
        verdict_upgraded=upgraded,
        verdict_downgraded=downgraded,
        semantic_gap_cleared=sg_cleared,
        semantic_gap_persisted=sg_persisted,
        avg_evidence_refs_before=avg_before,
        avg_evidence_refs_after=avg_after,
    )


# =========================================================
# 重判（脚本用 — 调真 LLM）
# =========================================================

def rejudge_alerts(engine, alerts) -> List[Judgment]:
    """对每个 Alert 跑 engine.judge() 并收集结果。"""
    out: List[Judgment] = []
    for a in alerts:
        try:
            out.append(engine.judge(a))
        except Exception:
            logger.exception("rejudge failed for alert %s", getattr(a, "alert_id", "?"))
    return out


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
