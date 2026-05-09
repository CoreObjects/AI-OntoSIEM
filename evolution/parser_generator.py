"""组件 10 Day 1：Parser 自动生成器（核心亮点）。

输入：
  - 审核通过的 Proposal（即新加入本体的节点/边/属性）
  - 异常池样本（list_open / list_by_event_id 返回的 dict 列表）
  - 当前 ParserConfig（可选，给 LLM 当格式范本）
  - 升级后的本体（含新概念）

输出：
  CandidateParser — 含 rules（与 ParserConfig.from_dict 兼容的 dict 列表）+ 元数据。
  审核通过后写入 parsers/generated/<id>.yaml，触发 parser hot reload。

四道闸门：
  G1 字段引用必须在样本中真实存在（反幻觉，最关键）
  G2 target_node_type / entities[*].node / relations[*].edge 必须在本体
  G3 rules 必须能被 ParserConfig 兼容的 EventRule.from_dict 解析
  G4 至少一条 entity 引用了 target_node_type
"""
from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


_REQUIRED_KEYS = {"target_node_type", "rules", "confidence"}

# 硬边界：parser 生成器不得引用以下节点/边类型（项目契约 · CLAUDE.md）
_FORBIDDEN_NODE_TYPES_FROM_LOGS = frozenset({"User"})   # User 节点只能来自 CMDB/IAM
_FORBIDDEN_EDGE_TYPES_FROM_LOGS = frozenset({"owns"})    # owns 边只能 declared 源


# =========================================================
# CandidateParser
# =========================================================

@dataclass
class CandidateParser:
    candidate_id: str
    triggered_by_ontology_version: str
    triggered_by_proposal_id: str
    target_node_type: str
    source_events: List[Dict[str, Any]]
    rules: List[Dict[str, Any]]
    sample_count: int
    confidence: float
    explanation: str = ""
    status: str = "pending"     # pending / approved / applied / rejected
    stripped_relations: List[Dict[str, Any]] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def yaml_text(self) -> str:
        """渲染为 parsers/generated/<id>.yaml 的合法文本（与 ParserConfig.load_all 兼容）。"""
        import yaml
        doc = {
            "version": self.triggered_by_ontology_version,
            "target_ontology_version": self.triggered_by_ontology_version,
            "description": (
                f"Auto-generated parser for {self.target_node_type} "
                f"(proposal {self.triggered_by_proposal_id[:8]}; "
                f"candidate {self.candidate_id[:8]})"
            ),
            "rules": self.rules,
        }
        return yaml.safe_dump(doc, allow_unicode=True, sort_keys=False)


# =========================================================
# ParserGenerator
# =========================================================

class ParserGenerator:
    def __init__(self, llm, ontology) -> None:
        self._llm = llm
        self._ontology = ontology

    # -------- Public API --------

    def generate(
        self,
        *,
        approved_proposal,
        anomaly_samples: List[Dict[str, Any]],
        current_parser_config=None,
    ) -> Optional[CandidateParser]:
        if not anomaly_samples:
            return None

        if approved_proposal.status != "approved":
            raise ValueError(
                f"parser generator requires approved proposal; got status="
                f"{approved_proposal.status!r}"
            )

        sample_keys = self._collect_sample_field_names(anomaly_samples)

        system = self._render_system()
        user = self._render_user(approved_proposal, anomaly_samples,
                                 current_parser_config, sample_keys)

        response = self._llm.structured_json(
            system=system, user=user,
            required_keys=_REQUIRED_KEYS,
            validator=self._validate_schema,
            max_tokens=4096, temperature=0.1, max_retries=2,
        )

        return self._build_candidate(response, approved_proposal,
                                     anomaly_samples, sample_keys)

    # -------- Build & validate --------

    def _build_candidate(
        self,
        response: Dict[str, Any],
        proposal,
        samples: List[Dict[str, Any]],
        sample_keys: set,
    ) -> Optional[CandidateParser]:
        target = response.get("target_node_type")
        # G2a：target_node_type 必须在本体
        if target not in self._ontology.nodes:
            logger.info("drop candidate: target_node_type %r not in ontology", target)
            return None

        rules = response.get("rules") or []
        if not isinstance(rules, list) or not rules:
            logger.info("drop candidate: rules empty or non-list")
            return None

        target_referenced = False
        valid_rules: List[Dict[str, Any]] = []
        all_stripped: List[Dict[str, Any]] = []
        for rule in rules:
            # entity 层：任一违反整条候选 reject（G1/G2b/G5）
            if not self._validate_entities(rule, sample_keys):
                logger.info("drop candidate: invalid entities in rule %r", rule.get("name"))
                return None

            for ent in rule.get("entities") or []:
                if ent.get("node") == target:
                    target_referenced = True

            # relation 层：违反 strip 不丢整候选（G2c/G6/G7）
            kept_rels, stripped = self._split_relations(rule, sample_keys)
            all_stripped.extend(stripped)

            cleaned = dict(rule)
            cleaned["relations"] = kept_rels

            # G3：cleaned rule 必须能 round-trip
            try:
                from parsers.windows_parser import EventRule
                EventRule.from_dict(cleaned)
            except Exception as exc:
                logger.info("rule %r failed EventRule.from_dict: %s",
                            cleaned.get("name"), exc)
                return None

            valid_rules.append(cleaned)

        # G4：target_node 必须被某条 entity 引用
        if not target_referenced:
            logger.info("drop candidate: no entity references target_node %r", target)
            return None

        try:
            confidence = float(response.get("confidence") or 0.0)
        except (TypeError, ValueError):
            confidence = 0.0

        return CandidateParser(
            candidate_id=str(uuid.uuid4()),
            triggered_by_ontology_version=getattr(self._ontology, "version", "unknown"),
            triggered_by_proposal_id=proposal.proposal_id,
            target_node_type=target,
            source_events=list(response.get("source_events") or []),
            rules=valid_rules,
            sample_count=len(samples),
            confidence=confidence,
            explanation=str(response.get("explanation") or ""),
            stripped_relations=all_stripped,
        )

    def _validate_entities(self, rule: Dict[str, Any], sample_keys: set) -> bool:
        for k in ("name", "event_id", "channel"):
            if k not in rule:
                return False
        for ent in rule.get("entities") or []:
            node = ent.get("node")
            # G5：禁止从日志生成 User（CMDB-only 硬边界）
            if node in _FORBIDDEN_NODE_TYPES_FROM_LOGS:
                logger.info("reject: entity uses forbidden log-source node %r", node)
                return False
            # G2b：node 必须在本体
            if node not in self._ontology.nodes:
                logger.info("reject: entity node %r not in ontology", node)
                return False
            # G1：id_expr 字段引用真实
            if not self._validate_expr(ent.get("id_expr"), sample_keys):
                return False
            for expr in (ent.get("attrs") or {}).values():
                if not self._validate_expr(expr, sample_keys):
                    return False
        return True

    def _split_relations(
        self, rule: Dict[str, Any], sample_keys: set,
    ) -> "tuple[List[Dict[str, Any]], List[Dict[str, Any]]]":
        kept: List[Dict[str, Any]] = []
        stripped: List[Dict[str, Any]] = []

        # ref_key → node_type 查表
        ref_to_type: Dict[str, str] = {}
        for ent in rule.get("entities") or []:
            rk = ent.get("ref_name") or ent.get("node")
            ref_to_type[rk] = ent.get("node")

        for rel in rule.get("relations") or []:
            edge = rel.get("edge")
            # G6：禁止从日志生成 owns（declared-only 硬边界）
            if edge in _FORBIDDEN_EDGE_TYPES_FROM_LOGS:
                stripped.append({**rel,
                                 "reason": f"edge {edge!r} is declared-only (CMDB), forbidden from logs"})
                continue
            # G2c：边类型必须在本体
            if edge not in self._ontology.edges:
                stripped.append({**rel,
                                 "reason": f"edge {edge!r} not in ontology"})
                continue
            # extra_attrs 表达式必须真实
            bad_expr = None
            for expr in (rel.get("extra_attrs") or {}).values():
                if not self._validate_expr(expr, sample_keys):
                    bad_expr = expr
                    break
            if bad_expr is not None:
                stripped.append({**rel,
                                 "reason": f"extra_attrs expr {bad_expr!r} references hallucinated field"})
                continue
            # G7：端点类型必须匹配本体声明
            endpoints = None
            if hasattr(self._ontology, "edge_endpoints"):
                endpoints = self._ontology.edge_endpoints(edge)
            if endpoints is not None:
                from_t = ref_to_type.get(rel.get("from_ref"))
                to_t = ref_to_type.get(rel.get("to_ref"))
                if (from_t, to_t) != endpoints:
                    stripped.append({
                        **rel,
                        "reason": (f"endpoint mismatch: ontology={endpoints}, "
                                   f"got=({from_t}, {to_t})"),
                    })
                    continue
            kept.append(rel)

        return kept, stripped

    @staticmethod
    def _validate_expr(expr: Any, sample_keys: set) -> bool:
        """合法 DSL：const:* / @computer / @timestamp / event_data.X(X∈样本) / compose:A|B|...

        compose 内部不嵌套 compose（保持简单），其余子表达式必须各自合法。
        """
        if not isinstance(expr, str) or not expr:
            return False
        if expr.startswith("const:"):
            return True
        if expr in {"@computer", "@timestamp"}:
            return True
        if expr.startswith("event_data."):
            field = expr.split(".", 1)[1]
            return bool(field) and field in sample_keys
        if expr.startswith("compose:"):
            parts = expr[8:].split("|")
            if not parts:
                return False
            for part in parts:
                if part.startswith("compose:"):
                    return False  # 拒绝嵌套 compose
                if not ParserGenerator._validate_expr(part, sample_keys):
                    return False
            return True
        return False

    @staticmethod
    def _collect_sample_field_names(samples: List[Dict[str, Any]]) -> set:
        """把所有样本 event_data 里出现过的 key 收集起来作为白名单。"""
        keys: set = set()
        for s in samples:
            raw = s.get("raw_event") or {}
            ed = raw.get("event_data")
            if isinstance(ed, str):
                try:
                    ed = json.loads(ed)
                except json.JSONDecodeError:
                    continue
            if isinstance(ed, dict):
                keys.update(ed.keys())
        return keys

    @staticmethod
    def _validate_schema(data: Dict[str, Any]) -> Optional[str]:
        rules = data.get("rules")
        if not isinstance(rules, list):
            return "rules must be a list"
        if len(rules) == 0:
            return "rules must be non-empty"
        if not isinstance(data.get("target_node_type"), str):
            return "target_node_type must be a string"
        return None

    # -------- Prompt --------

    def _render_system(self) -> str:
        return (
            "你是 Windows 日志 parser 生成器。基于审核通过的本体提议 + 异常池样本，"
            "输出 parser 配置（rules YAML 结构）以把这些事件映射进本体。\n"
            "\n表达式 DSL（仅这五种合法，不许发明）:\n"
            "  - \"@computer\"        事件顶层 computer\n"
            "  - \"@timestamp\"       事件顶层 timestamp\n"
            "  - \"event_data.X\"     event_data.X（X 必须在样本里实际出现）\n"
            "  - \"compose:A|B|C\"    多字段拼接（每段是上述其它表达式，不允许嵌套 compose）\n"
            "  - \"const:literal\"    字面量\n"
            "\n硬边界（违反整条候选丢弃）:\n"
            "  1) target_node_type 必须是当前本体已有的节点类型\n"
            "  2) entities 中的 node 类型、relations 中的 edge 类型必须在本体里\n"
            "  3) 至少一条 entity 引用 target_node_type 作为 node\n"
            "  4) event_data.X 引用的 X 必须在样本 event_data 里实际出现（不许编造字段）\n"
            "  5) entity.id_expr 应让节点跨事件可去重（用稳定字段 + 必要时拼 @computer）\n"
            "  6) **禁止 entities 中使用 'User' 节点** —— User 节点只能从 CMDB/IAM 声明源导入，"
            "日志里出现的用户身份一律用 'Account'\n"
            "  7) **禁止 relations 中使用 'owns' 边** —— owns 是声明式 (declared) 关系，"
            "禁止从日志推断；如需账户层关系请用 logged_into / authenticated_as\n"
            "  8) **relations 端点类型必须严格匹配本体声明**：检索本体 edges[<name>].from/to，"
            "from_ref 指向的 entity.node 必须等于 from，to_ref 同理。不匹配就别建这条关系\n"
            "\n输出 JSON schema:\n"
            "  {\n"
            "    \"target_node_type\": \"ScheduledTask\",\n"
            "    \"source_events\": [{\"event_id\": 4698, \"channel\": \"Security\"}],\n"
            "    \"rules\": [{\n"
            "       \"name\": \"4698_scheduled_task_create\",\n"
            "       \"event_id\": 4698, \"channel\": \"Security\",\n"
            "       \"description\": \"...\",\n"
            "       \"entities\": [\n"
            "          {\"node\": \"ScheduledTask\", \"id_expr\": \"compose:@computer|event_data.TaskName\",\n"
            "           \"attrs\": {\"task_name\": \"event_data.TaskName\"},\n"
            "           \"meta\": {\"source\": \"log\", \"confidence\": 0.9}}\n"
            "       ],\n"
            "       \"relations\": [{\"edge\": \"...\", \"from_ref\": \"...\", \"to_ref\": \"...\",\n"
            "                       \"extra_attrs\": {}}]\n"
            "    }],\n"
            "    \"confidence\": 0.85,\n"
            "    \"explanation\": \"...\"\n"
            "  }\n"
            "保守优于冒进 — 不确定的字段不要硬塞，缺乏证据宁可少建关系。"
            "审核员会基于这份配置 + 抽样回放结果 决定是否真正 apply。\n"
        )

    def _render_user(
        self,
        proposal,
        samples: List[Dict[str, Any]],
        parser_cfg,
        sample_keys: set,
    ) -> str:
        node_types = list(self._ontology.nodes.keys())
        edge_types = list(self._ontology.edges.keys())

        # 样本块（最多 5 条做 prompt size 控制）
        max_show = min(len(samples), 5)
        sample_block = (
            f"\n## 异常池样本（共 {len(samples)} 条；展示前 {max_show} 条）\n"
        )
        for s in samples[:max_show]:
            raw = s.get("raw_event") or {}
            ed = raw.get("event_data")
            if isinstance(ed, str):
                try:
                    ed = json.loads(ed)
                except json.JSONDecodeError:
                    ed = {"_unparseable": ed[:200]}
            sample_block += (
                f"- record_id={s.get('record_id')}  event_id={raw.get('event_id')}  "
                f"channel={raw.get('channel')}  computer={raw.get('computer')}\n"
                f"  event_data: {json.dumps(ed, ensure_ascii=False)[:600]}\n"
            )

        # 字段白名单（明示给 LLM，方便它选字段）
        whitelist_block = (
            f"\n## event_data 字段白名单（仅这些字段在样本里出现过）\n"
            f"{sorted(sample_keys)}\n"
        )

        # 现 parser 范例（取前两条作为格式参考）
        existing_block = ""
        if parser_cfg is not None and getattr(parser_cfg, "rules", None):
            existing_block = "\n## 现 parser 配置参考（前两条作格式样例）\n"
            for r in parser_cfg.rules[:2]:
                ent_summary = ""
                if r.entities:
                    e0 = r.entities[0]
                    ent_summary = (
                        f"node={e0.node}, id_expr={e0.id_expr}, "
                        f"attrs_keys={list(e0.attrs.keys())}"
                    )
                existing_block += (
                    f"- name: {r.name}\n"
                    f"  event_id: {r.event_id}\n"
                    f"  channel: {r.channel}\n"
                    f"  entities[0]: {ent_summary}\n"
                )

        return (
            f"## 升级后的本体 v{getattr(self._ontology, 'version', '?')}\n"
            f"nodes: {', '.join(node_types)}\n"
            f"edges: {', '.join(edge_types)}\n"
            f"\n## 审核通过的本体提议\n"
            f"  proposal_id: {proposal.proposal_id}\n"
            f"  type: {proposal.proposal_type}\n"
            f"  name: {proposal.name}\n"
            f"  semantic_definition: {proposal.semantic_definition}\n"
            f"  attack_mapping: {proposal.attack_mapping}\n"
            f"  source_signals: {proposal.source_signals}\n"
            + sample_block
            + whitelist_block
            + existing_block
            + "\n## 任务\n"
            f"为 '{proposal.name}' 生成 parser 配置 JSON，target_node_type 应为 '{proposal.name}'。"
            f" 若样本不足以覆盖某种事件类型，可只输出能覆盖的部分；不要硬编一条没把握的规则。\n"
        )
