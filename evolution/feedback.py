"""阶段 4 B 段：审核员反馈写信号（manual_annotation）。

UI 按下 👍/👎 → 一行 record_feedback() 把反馈结构化落到 signal_hub，
看板的"反馈采纳率"指标就能算（feedback_total / judgment_count）。

aggregation_key 形如 `copilot:manual_annotation:up` 让 👍/👎 在 signal_hub
层就分开聚合，方便后续按反馈类型分级处理。
"""
from __future__ import annotations

import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

_VALID_FEEDBACK = {"up", "down"}


def record_feedback(
    signal_hub,
    *,
    judgment_id: str,
    feedback: str,
    alert_id: Optional[str] = None,
    notes: Optional[str] = None,
) -> Any:
    """把审核员的👍/👎 写成 manual_annotation 信号。

    Args:
      signal_hub: 任何具备 report_signal(...) 的对象（真 SignalHub 或 fake）
      judgment_id: 被反馈的判决 ID（必填）
      feedback: 'up' / 'down'
      alert_id: 可选 — 关联到原始告警，方便后续从 alert 反查反馈
      notes: 可选 — 文字说明（如"LSASS 应该是 malicious"）

    Returns:
      signal_hub.report_signal 的返回值（Signal 对象 或 fake dict）
    """
    if feedback not in _VALID_FEEDBACK:
        raise ValueError(
            f"feedback must be one of {sorted(_VALID_FEEDBACK)}; got {feedback!r}"
        )
    if not judgment_id:
        raise ValueError("judgment_id is required")

    payload: dict = {
        "judgment_id": judgment_id,
        "feedback": feedback,
    }
    if alert_id:
        payload["alert_id"] = alert_id
    if notes:
        payload["notes"] = notes

    return signal_hub.report_signal(
        source_layer="copilot",
        signal_type="manual_annotation",
        payload=payload,
        aggregation_key=f"copilot:manual_annotation:{feedback}",
    )
