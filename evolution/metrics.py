"""阶段 4 A 段：评测看板指标层。

四个核心数字（需求文档 §10）：
  1. 研判准确率（judgment_accuracy）：LLM verdict 与人工 ground truth 对比
  2. 反馈采纳率（feedback_adoption）：审核员按下👍/👎 / 总判决数
  3. 本体覆盖率（ontology_coverage）：成功 parse / (parse + 异常池 open)
  4. 异常池规模（anomaly_pool_size_open）

外加：演化前后对比（来自 ValidatorReport）。

设计：
  - 全部纯函数，TDD 友好；无 LLM 调用、无副作用
  - 顶层 `collect_metrics(...)` 装配 MetricsSnapshot
  - UI / API 层调 collect_metrics 后 to_dict() 渲染
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

logger = logging.getLogger(__name__)


# =========================================================
# 1. 研判准确率
# =========================================================

def compute_judgment_accuracy(
    judgments: List[Dict[str, Any]],
    alerts: List[Dict[str, Any]],
    ground_truth: Dict[str, str],
) -> Tuple[float, int, int, Dict[str, Tuple[int, int]]]:
    """对每条 judgment 找对应 alert 的 rule_id，与 ground_truth 比 verdict。

    返回 (accuracy, correct, total, breakdown_per_rule)
    跳过 ground_truth 中未列的规则（不影响分母）。
    """
    alert_to_rule = {a["alert_id"]: a["rule_id"] for a in alerts}
    breakdown: Dict[str, List[int]] = {}
    correct = total = 0

    for j in judgments:
        rule_id = alert_to_rule.get(j.get("alert_id"))
        if rule_id is None:
            continue
        gt = ground_truth.get(rule_id)
        if gt is None:
            continue
        b = breakdown.setdefault(rule_id, [0, 0])
        b[1] += 1
        total += 1
        if j.get("verdict") == gt:
            b[0] += 1
            correct += 1

    accuracy = correct / max(total, 1) if total > 0 else 0.0
    return accuracy, correct, total, {k: tuple(v) for k, v in breakdown.items()}


# =========================================================
# 2. 反馈采纳率
# =========================================================

def compute_feedback_adoption(
    signals: List[Dict[str, Any]],
    judgment_count: int,
) -> Tuple[float, int, int, int]:
    """从 signals 表过滤 manual_annotation，统计 👍/👎。

    payload 必有 "feedback" key，值 ∈ {"up", "down"}。
    返回 (adoption_rate, thumbs_up, thumbs_down, judgment_count)
    """
    up = down = 0
    for s in signals or []:
        if s.get("signal_type") != "manual_annotation":
            continue
        payload = s.get("payload") or {}
        fb = payload.get("feedback")
        if fb == "up":
            up += 1
        elif fb == "down":
            down += 1
    total = up + down
    rate = total / max(judgment_count, 1) if judgment_count > 0 else 0.0
    return rate, up, down, judgment_count


# =========================================================
# 3. 本体覆盖率
# =========================================================

def compute_ontology_coverage(
    parsed_count: int,
    anomaly_pool_open: int,
) -> Tuple[float, int, int]:
    """coverage = parsed / (parsed + anomaly_pool_open)。

    返回 (coverage, parsed, total)。
    """
    total = parsed_count + anomaly_pool_open
    coverage = parsed_count / total if total > 0 else 0.0
    return coverage, parsed_count, total


# =========================================================
# Ground truth 加载
# =========================================================

def load_ground_truth(path: Path) -> Dict[str, str]:
    """读 data/ground_truth.yaml → {rule_id: expected_verdict}。

    文件不存在时返回空 dict（看板降级显示 0% accuracy 而非崩溃）。
    """
    p = Path(path)
    if not p.exists():
        return {}
    with p.open("r", encoding="utf-8") as f:
        doc = yaml.safe_load(f) or {}
    rules = doc.get("rules") or {}
    return {
        rule_id: (entry or {}).get("expected_verdict", "")
        for rule_id, entry in rules.items()
        if (entry or {}).get("expected_verdict")
    }


# =========================================================
# Snapshot
# =========================================================

@dataclass
class MetricsSnapshot:
    timestamp: str

    # 1. 准确率
    judgment_accuracy: float
    accuracy_correct: int
    accuracy_total: int
    accuracy_breakdown: Dict[str, Tuple[int, int]]    # rule_id → (correct, total)

    # 2. 反馈采纳率
    feedback_adoption: float
    feedback_thumbs_up: int
    feedback_thumbs_down: int
    feedback_total_judgments: int

    # 3. 本体覆盖率
    ontology_coverage: float
    parsed_event_count: int
    total_event_count: int

    # 4. 异常池规模
    anomaly_pool_size_open: int
    anomaly_pool_size_total: int
    anomaly_pool_size_open_by_event_id: Dict[int, int] = field(default_factory=dict)

    # 演化前后对比（来自 ValidatorReport.to_dict()）
    evolution_diff: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "judgment_accuracy": self.judgment_accuracy,
            "accuracy_correct": self.accuracy_correct,
            "accuracy_total": self.accuracy_total,
            "accuracy_breakdown": {k: list(v) for k, v in self.accuracy_breakdown.items()},
            "feedback_adoption": self.feedback_adoption,
            "feedback_thumbs_up": self.feedback_thumbs_up,
            "feedback_thumbs_down": self.feedback_thumbs_down,
            "feedback_total_judgments": self.feedback_total_judgments,
            "ontology_coverage": self.ontology_coverage,
            "parsed_event_count": self.parsed_event_count,
            "total_event_count": self.total_event_count,
            "anomaly_pool_size_open": self.anomaly_pool_size_open,
            "anomaly_pool_size_total": self.anomaly_pool_size_total,
            "anomaly_pool_size_open_by_event_id": dict(self.anomaly_pool_size_open_by_event_id),
            "evolution_diff": self.evolution_diff,
        }


# =========================================================
# 顶层装配
# =========================================================

def collect_metrics(
    *,
    judgments: List[Dict[str, Any]],
    alerts: List[Dict[str, Any]],
    ground_truth: Dict[str, str],
    signals: List[Dict[str, Any]],
    parsed_event_count: int,
    anomaly_pool_size_open: int,
    anomaly_pool_size_total: int,
    anomaly_pool_size_open_by_event_id: Optional[Dict[int, int]] = None,
    evolution_diff: Optional[Dict[str, Any]] = None,
) -> MetricsSnapshot:
    acc, correct, total, breakdown = compute_judgment_accuracy(
        judgments, alerts, ground_truth)
    fb_rate, up, down, jc = compute_feedback_adoption(signals, len(judgments))
    cov, parsed, ev_total = compute_ontology_coverage(
        parsed_event_count, anomaly_pool_size_open)

    return MetricsSnapshot(
        timestamp=datetime.now(timezone.utc).isoformat(),
        judgment_accuracy=acc,
        accuracy_correct=correct, accuracy_total=total,
        accuracy_breakdown=breakdown,
        feedback_adoption=fb_rate,
        feedback_thumbs_up=up, feedback_thumbs_down=down,
        feedback_total_judgments=jc,
        ontology_coverage=cov,
        parsed_event_count=parsed,
        total_event_count=ev_total,
        anomaly_pool_size_open=anomaly_pool_size_open,
        anomaly_pool_size_total=anomaly_pool_size_total,
        anomaly_pool_size_open_by_event_id=dict(
            anomaly_pool_size_open_by_event_id or {}
        ),
        evolution_diff=evolution_diff,
    )
