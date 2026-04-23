"""组件 8 本体演化提议引擎（需求 §4.8）。

输入：
  - signal_hub.list_pending()      待处理聚合信号（阶段 2 产出）
  - ontology_service.get_current() 当前本体
  - rejection_names                反面样本库（历史被拒的提议名）

四重闸门：
  1) system prompt 硬边界（写死 LLM 指令）
  2) 硬边界校验（代码侧二次把关 LLM 输出，防 LLM 违约）
  3) 重叠度闸一（overlap_analysis > 0.7 自动丢弃）
  4) 字符串相似度闸二（与本体 / 反面样本库名字近似 > 0.7 丢弃）

输出：List[Proposal]，已过滤后的候选。审核通过后才生效（组件 9）。
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from difflib import SequenceMatcher
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)


# =========================================================
# 常量
# =========================================================

_MAX_PROPOSALS_PER_BATCH = 5
_MIN_EVIDENCE = 3
_OVERLAP_HARD_LIMIT = 0.7
_STRING_SIM_LIMIT = 0.7
_ALLOWED_TYPES = {"node", "edge", "attr"}

_REQUIRED_KEYS = {"proposals"}


# =========================================================
# Proposal dataclass
# =========================================================

@dataclass
class Proposal:
    proposal_id: str
    proposal_type: str                       # "node" / "edge" / "attr"
    name: str
    semantic_definition: str
    supporting_evidence: List[Dict[str, Any]]
    overlap_analysis: Dict[str, float]       # {existing_concept: similarity}
    attack_mapping: List[str]                # [T1053.005]
    source_signals: List[str]                # [aggregation_key]
    ontology_base_version: str
    status: str = "pending"                  # pending / approved / rejected / modified / deferred
    rejection_reason: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# =========================================================
# ProposalEngine
# =========================================================

class ProposalEngine:
    def __init__(
        self,
        llm,
        signal_hub,
        ontology,
        rejection_names: Optional[Iterable[str]] = None,
    ) -> None:
        self._llm = llm
        self._hub = signal_hub
        self._ontology = ontology
        self._rejection_names = list(rejection_names or [])

    # -------- Public API --------

    def generate(self, *, window_hours: int = 24,
                 threshold: int = 10) -> List[Proposal]:
        pending = self._hub.list_pending(window_hours=window_hours, threshold=threshold)
        if not pending:
            return []

        system = self._render_system()
        user = self._render_user(pending)

        response = self._llm.structured_json(
            system=system, user=user,
            required_keys=_REQUIRED_KEYS,
            validator=self._validate_schema,
            max_tokens=4096, temperature=0.2, max_retries=2,
        )

        raw_props = response.get("proposals") or []
        # 单次最多 5（硬边界 4）
        raw_props = raw_props[:_MAX_PROPOSALS_PER_BATCH]

        accepted: List[Proposal] = []
        for raw in raw_props:
            p = self._try_build_proposal(raw)
            if p is None:
                continue
            accepted.append(p)
        return accepted

    # -------- prompt --------

    def _render_system(self) -> str:
        return (
            "你是一名本体演化提议者。根据观察到的待处理信号，提议向当前本体新增节点/边/属性。\n"
            "\n硬边界（违反立即拒）：\n"
            "  1) 只能新增，禁止修改或删除已有元素；proposal_type ∈ {node, edge, attr}\n"
            "  2) 每条提议必须附 ≥3 条 supporting_evidence（格式 {record_id, excerpt}）\n"
            "  3) 每条提议必须给出 overlap_analysis：{existing_concept: similarity 0..1}，"
            "与任一现有元素相似度 >0.7 将被自动丢弃\n"
            "  4) 单次最多提议 5 个\n"
            "  5) User ↔ Account 绝不自动归并（L3 级演化不在自动提议范围）\n"
            "\n输出 JSON schema：\n"
            '  {"proposals": [{\n'
            '     "proposal_type": "node",\n'
            '     "name": "ScheduledTask",\n'
            '     "semantic_definition": "...",\n'
            '     "supporting_evidence": [{"record_id": 1, "excerpt": "..."}, ...],\n'
            '     "overlap_analysis": {"Process": 0.2, ...},\n'
            '     "attack_mapping": ["T1053.005"],\n'
            '     "source_signals": ["data:unparseable_event:4698"]\n'
            '  }, ...]}\n'
            "\n若当前信号本体完全能表达（无 gap），返回 {\"proposals\": []}。"
            "保守优于冒进 —— 重叠度闸门会自动丢弃可疑提议，你将背负"
            "一个反面样本记录。\n"
        )

    def _render_user(self, pending: List[Dict[str, Any]]) -> str:
        node_types = list(self._ontology.nodes.keys())
        edge_types = list(self._ontology.edges.keys())
        version = getattr(self._ontology, "version", "1.0")

        sig_lines = []
        for g in pending:
            sig_lines.append(
                f"- aggregation_key={g['aggregation_key']}  "
                f"count={g['count']}  priority={g.get('priority','?')}  "
                f"source_layer={g.get('source_layer','?')}  "
                f"signal_type={g.get('signal_type','?')}"
            )

        rej_block = ""
        if self._rejection_names:
            rej_block = (
                "\n## 反面样本库（历史被拒的提议名，请勿重复提出或接近命名）:\n"
                + "\n".join(f"- {n}" for n in self._rejection_names)
            )

        return (
            f"## 当前本体 v{version}\n"
            f"nodes: {', '.join(node_types)}\n"
            f"edges: {', '.join(edge_types)}\n\n"
            f"## 待处理信号（窗口 24h · 按 count desc）\n"
            + "\n".join(sig_lines) + "\n"
            + rej_block
            + "\n\n## 任务\n"
            "针对以上信号，按 schema 输出 proposals。确保每条提议都精确对应至少一个 aggregation_key "
            "作为 source_signals。重叠度务必诚实填写——虚高的低相似度骗不过程序校验。"
        )

    @staticmethod
    def _validate_schema(data: Dict[str, Any]) -> Optional[str]:
        if "proposals" not in data:
            return "missing 'proposals' key"
        if not isinstance(data["proposals"], list):
            return "'proposals' must be a list"
        return None

    # -------- 单条提议闸门 --------

    def _try_build_proposal(self, raw: Dict[str, Any]) -> Optional[Proposal]:
        # 硬边界 1：proposal_type 白名单（只能新增）
        ptype = raw.get("proposal_type")
        if ptype not in _ALLOWED_TYPES:
            logger.info("drop proposal: invalid proposal_type=%r", ptype)
            return None

        name = raw.get("name") or ""
        if not name:
            logger.info("drop proposal: empty name")
            return None

        # 硬边界 5：与现有本体同名禁止（只能新增）
        if name in self._ontology.nodes or name in self._ontology.edges:
            logger.info("drop proposal: name %r collides with existing ontology", name)
            return None

        # 硬边界 2：≥3 条 supporting_evidence
        ev = raw.get("supporting_evidence") or []
        if not isinstance(ev, list) or len(ev) < _MIN_EVIDENCE:
            logger.info("drop proposal %r: insufficient evidence (%d)", name, len(ev))
            return None

        # 硬边界 3：overlap_analysis 必填
        overlap = raw.get("overlap_analysis") or {}
        if not isinstance(overlap, dict) or not overlap:
            logger.info("drop proposal %r: missing overlap_analysis", name)
            return None

        # 闸一：overlap > 0.7 丢弃
        try:
            max_overlap = max(float(v) for v in overlap.values())
        except (TypeError, ValueError):
            logger.info("drop proposal %r: non-numeric overlap values", name)
            return None
        if max_overlap > _OVERLAP_HARD_LIMIT:
            logger.info("drop proposal %r: overlap %.2f > %.2f",
                        name, max_overlap, _OVERLAP_HARD_LIMIT)
            return None

        # 闸二：字符串相似度 - 与本体 + 反面样本对比
        if self._name_too_similar(name):
            logger.info("drop proposal %r: string-similar to existing or rejected name",
                        name)
            return None

        return Proposal(
            proposal_id=str(uuid.uuid4()),
            proposal_type=ptype,
            name=name,
            semantic_definition=str(raw.get("semantic_definition") or ""),
            supporting_evidence=list(ev),
            overlap_analysis={str(k): float(v) for k, v in overlap.items()},
            attack_mapping=list(raw.get("attack_mapping") or []),
            source_signals=list(raw.get("source_signals") or []),
            ontology_base_version=getattr(self._ontology, "version", "1.0"),
        )

    def _name_too_similar(self, name: str) -> bool:
        candidates = (
            list(self._ontology.nodes.keys())
            + list(self._ontology.edges.keys())
            + list(self._rejection_names)
        )
        n = name.lower()
        for c in candidates:
            sim = SequenceMatcher(None, n, c.lower()).ratio()
            if sim >= _STRING_SIM_LIMIT:
                return True
        return False
