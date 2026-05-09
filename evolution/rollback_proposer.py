"""组件 10 Day 5：演化回滚提议器（R8 风险缓解 · 演化空转）。

输入：ValidatorReport（升级前/后 diff）
输出：RollbackProposal（含触发指标 + 严重等级 + 人读 rationale）；指标改善时返回 None

关键约束：
  - **从不自动回滚**。assess_for_rollback 只产候选，apply 必须人工审核
  - 严格阈值（避免抖动 / 统计噪音）：默认 require_min_rejudged=5
  - severity 分级：critical（≥30% rejudged 被降级）/ warning（其他触发）

触发条件（任一即触发，rationale 累计列出全部触发原因）：
  1) verdict_downgraded > verdict_upgraded（净降级）
  2) semantic_gap_persisted >= 2 × semantic_gap_cleared（演化没解决核心 gap）
  3) avg_evidence_refs_after < 0.7 × avg_evidence_refs_before（推理深度下降）
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# =========================================================
# Constants
# =========================================================

_DEFAULT_MIN_REJUDGED = 5
_EVIDENCE_DROP_RATIO = 0.7        # after/before < 0.7 触发
_GAP_PERSIST_RATIO = 2.0          # persisted/cleared >= 2 触发
_CRITICAL_DOWNGRADE_RATIO = 0.30  # downgraded/rejudged >= 30% → critical


# =========================================================
# Dataclass
# =========================================================

@dataclass
class RollbackProposal:
    proposal_id: str
    target_version: str           # 回滚目标（前一个版本号）
    current_version: str          # 当前生效的版本（被建议回滚的）
    triggered_by_metrics: Dict[str, Any]   # 完整 ValidatorReport 摘要 — 审计可回溯
    rationale: str                # 人读触发说明
    severity: str                 # "critical" / "warning" / "info"
    suggested_action: str = "rollback"     # 留扩展空间（rollback / modify / soft_warn）
    status: str = "pending"       # pending / approved / rejected
    rejection_reason: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "target_version": self.target_version,
            "current_version": self.current_version,
            "triggered_by_metrics": dict(self.triggered_by_metrics),
            "rationale": self.rationale,
            "severity": self.severity,
            "suggested_action": self.suggested_action,
            "status": self.status,
            "rejection_reason": self.rejection_reason,
            "created_at": self.created_at,
        }


# =========================================================
# 评估函数
# =========================================================

def assess_for_rollback(
    report,
    *,
    require_min_rejudged: int = _DEFAULT_MIN_REJUDGED,
    evidence_drop_ratio: float = _EVIDENCE_DROP_RATIO,
    gap_persist_ratio: float = _GAP_PERSIST_RATIO,
    critical_downgrade_ratio: float = _CRITICAL_DOWNGRADE_RATIO,
) -> Optional[RollbackProposal]:
    """评估 ValidatorReport 是否应触发 rollback 提议。

    Args:
      report: ValidatorReport 实例
      require_min_rejudged: 重判数 < 此值就拒绝触发（避免单条噪音搅局）
      evidence_drop_ratio: avg_evidence_refs_after / before < 此值触发
      gap_persist_ratio: persisted / cleared >= 此值触发
      critical_downgrade_ratio: downgraded / rejudged >= 此值升级为 critical

    Returns:
      RollbackProposal 或 None（指标无显著恶化）
    """
    if report.rejudged_count < require_min_rejudged:
        logger.info(
            "skip rollback assess: rejudged_count=%d < min=%d",
            report.rejudged_count, require_min_rejudged,
        )
        return None

    triggers: List[str] = []

    # 触发 1：verdict 净降级
    if report.verdict_downgraded > report.verdict_upgraded:
        triggers.append(
            f"verdict 净降级 {report.verdict_downgraded - report.verdict_upgraded} 条 "
            f"(downgraded={report.verdict_downgraded}, upgraded={report.verdict_upgraded})"
        )

    # 触发 2：semantic_gap 持续 >> 清除
    if report.semantic_gap_cleared > 0 or report.semantic_gap_persisted > 0:
        cleared = max(report.semantic_gap_cleared, 0)
        persisted = report.semantic_gap_persisted
        # 用 max(cleared, 1) 避免除零；持续 >= 阈值×清除 即触发
        if cleared == 0 and persisted >= int(gap_persist_ratio):
            triggers.append(
                f"semantic_gap 全部持续未清（persisted={persisted}, cleared=0）"
            )
        elif cleared > 0 and persisted >= cleared * gap_persist_ratio:
            triggers.append(
                f"semantic_gap 持续显著高于清除（persisted={persisted}, cleared={cleared}, "
                f"比 {persisted/cleared:.1f}× ≥ 阈值 {gap_persist_ratio}×）"
            )

    # 触发 3：evidence_refs 大幅减少
    if report.avg_evidence_refs_before > 0:
        ratio = report.avg_evidence_refs_after / report.avg_evidence_refs_before
        if ratio < evidence_drop_ratio:
            triggers.append(
                f"evidence_refs 平均大幅下降（{report.avg_evidence_refs_before:.2f} → "
                f"{report.avg_evidence_refs_after:.2f}, 保留率 {ratio*100:.0f}% < "
                f"阈值 {evidence_drop_ratio*100:.0f}%）"
            )

    if not triggers:
        return None

    # severity：降级显著则 critical，否则 warning
    severity = "warning"
    if report.rejudged_count > 0:
        downgrade_ratio = report.verdict_downgraded / report.rejudged_count
        if downgrade_ratio >= critical_downgrade_ratio:
            severity = "critical"

    rationale = "演化升级触发回滚提议（任一指标显著恶化）：\n  " + "\n  ".join(
        f"- {t}" for t in triggers
    )

    triggered_metrics = {
        "rejudged_count": report.rejudged_count,
        "verdict_upgraded": report.verdict_upgraded,
        "verdict_downgraded": report.verdict_downgraded,
        "verdict_unchanged": report.verdict_unchanged,
        "semantic_gap_cleared": report.semantic_gap_cleared,
        "semantic_gap_persisted": report.semantic_gap_persisted,
        "avg_evidence_refs_before": report.avg_evidence_refs_before,
        "avg_evidence_refs_after": report.avg_evidence_refs_after,
        "pool_open_before": report.pool_open_before,
        "pool_open_after": report.pool_open_after,
        "ontology_version_before": report.ontology_version_before,
        "ontology_version_after": report.ontology_version_after,
    }

    return RollbackProposal(
        proposal_id=str(uuid.uuid4()),
        target_version=report.ontology_version_before,
        current_version=report.ontology_version_after,
        triggered_by_metrics=triggered_metrics,
        rationale=rationale,
        severity=severity,
    )
