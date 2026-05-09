"""组件 10 Day 2：候选 parser 审核动作（UI 与 store/parser 的胶水层）。

动作：
  approve_and_apply(store, cid, output_dir=...)  → 写 YAML + 标 approved
  reject_candidate(store, cid, reason=...)       → 标 rejected
  preview_candidate_parsing(candidate, samples,
                            ontology)            → dry-run 抽样回放报告

设计：
  - approve_and_apply 仅负责写 YAML + 状态机；hot reload 由调用方（或 Day 3
    replay engine 实例化新 parser）触发。
  - preview 内部用 NoOp anomaly_pool / signal_hub stub，不污染全局状态。
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from evolution.parser_generator import CandidateParser

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_DIR = ROOT / "parsers" / "generated"


class CandidateNotPending(RuntimeError):
    """对非 pending 状态的候选执行 approve/reject 时抛出。"""


# =========================================================
# 内部
# =========================================================

def _load_candidate(store, candidate_id: str) -> CandidateParser:
    c = store.as_candidate(candidate_id)
    if c is None:
        raise KeyError(f"no such candidate: {candidate_id!r}")
    return c


def _ensure_pending(c: CandidateParser) -> None:
    if c.status != "pending":
        raise CandidateNotPending(
            f"candidate {c.candidate_id!r} is in status {c.status!r}, not pending"
        )


# =========================================================
# 动作 · approve + apply
# =========================================================

def approve_and_apply(
    store,
    candidate_id: str,
    *,
    output_dir: Optional[Path] = None,
) -> Path:
    """审核通过 → 写 YAML 到 parsers/generated/ → 标 approved。

    返回 YAML 文件路径。Day 3 replay_engine 会从这个目录读 candidate parser 应用。
    """
    c = _load_candidate(store, candidate_id)
    _ensure_pending(c)

    out_dir = Path(output_dir) if output_dir else DEFAULT_OUTPUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    yaml_path = out_dir / f"{c.candidate_id[:8]}.yaml"
    yaml_path.write_text(c.yaml_text, encoding="utf-8")

    store.mark_approved(candidate_id, yaml_path=str(yaml_path))
    logger.info("candidate %s approved → %s", candidate_id, yaml_path.name)
    return yaml_path


# =========================================================
# 动作 · reject
# =========================================================

def reject_candidate(store, candidate_id: str, *, reason: str) -> None:
    c = _load_candidate(store, candidate_id)
    _ensure_pending(c)
    store.mark_rejected(candidate_id, reason=reason)
    logger.info("candidate %s rejected: %s", candidate_id, reason)


# =========================================================
# 抽样回放预览（dry-run）
# =========================================================

class _NoOpAnomalyPool:
    """preview 用 stub：parse 失败不写异常池。"""
    def add(self, **kwargs) -> None:
        pass


class _NoOpSignalHub:
    """preview 用 stub：parse 副作用不发信号。"""
    def report_signal(self, **kwargs) -> None:
        pass


def preview_candidate_parsing(
    candidate: CandidateParser,
    samples: List[Dict[str, Any]],
    *,
    ontology,
    show_first_n: int = 10,
) -> Dict[str, Any]:
    """临时实例化 WindowsParser 跑 candidate.rules，返回成功率 + 抽样产物。

    输出 schema：
        {
          total, success_count, failure_count, success_rate,
          parsed_samples: [{record_id, entities[..], relations[..]}, ...],
          failures: [{record_id, event_id, reason}, ...],
        }
    """
    from parsers.windows_parser import (
        EventRule, ParserConfig, WindowsParser,
    )

    if not samples:
        return {"total": 0, "success_count": 0, "failure_count": 0,
                "success_rate": 0.0, "parsed_samples": [], "failures": []}

    cfg = ParserConfig(
        version=candidate.triggered_by_ontology_version,
        target_ontology_version=candidate.triggered_by_ontology_version,
        description=f"preview for candidate {candidate.candidate_id[:8]}",
        rules=[EventRule.from_dict(r) for r in candidate.rules],
    )
    cfg._build_index()

    parser = WindowsParser(
        ontology=ontology,
        config=cfg,
        anomaly_pool=_NoOpAnomalyPool(),
        signal_hub=_NoOpSignalHub(),
    )

    parsed_samples: List[Dict[str, Any]] = []
    failures: List[Dict[str, Any]] = []

    for s in samples:
        raw = s.get("raw_event") or {}
        result = parser.parse_event(raw)
        if result.success:
            parsed_samples.append({
                "record_id": result.record_id,
                "entities": [
                    {"node_type": e.node_type, "node_id": e.node_id,
                     "attrs": e.attrs}
                    for e in result.entities
                ],
                "relations": [
                    {"edge_type": r.edge_type,
                     "from": f"{r.from_type}:{r.from_id}",
                     "to": f"{r.to_type}:{r.to_id}",
                     "attrs": r.attrs}
                    for r in result.relations
                ],
            })
        else:
            failures.append({
                "record_id": result.record_id,
                "event_id": raw.get("event_id"),
                "reason": result.failure_reason,
            })

    total = len(samples)
    success = len(parsed_samples)
    return {
        "total": total,
        "success_count": success,
        "failure_count": total - success,
        "success_rate": success / max(total, 1),
        "parsed_samples": parsed_samples[:show_first_n],
        "failures": failures[:show_first_n],
    }
