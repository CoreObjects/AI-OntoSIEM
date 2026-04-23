"""组件 6 认知推理层：告警 + 子图 → LLM structured JSON → Judgment。

核心职责（需求 §4.6）：
  - 以 alert.computer 为 center 取 1-2 跳图子图
  - Prompt 动态注入当前本体的节点/边类型词汇表（订阅本体变更时自动刷新）
  - 调 LLMClient.structured_json → 强制输出 schema
  - evidence_refs 严格校验（反幻觉闸门二）：ref 必须指向真实 alert 字段或子图节点/边
  - confidence < threshold → needs_review 标记
  - semantic_gap 非空 → 上报 reasoning/semantic_gap 信号
"""
from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from reasoning.llm_client import validate_evidence_refs

logger = logging.getLogger(__name__)


# 默认本体词汇（ontology=None 时兜底，与 v1.0 对齐）
_DEFAULT_NODE_TYPES = ["User", "Account", "Host", "Process", "NetworkEndpoint"]
_DEFAULT_EDGE_TYPES = ["owns", "authenticated_as", "logged_into",
                       "spawned", "executed_on", "connected_to"]

_REQUIRED_KEYS = {
    "verdict", "confidence", "reasoning_steps",
    "evidence_refs", "attack_chain", "next_steps",
}

# 默认子图只保留身份上下文；Process 数量太大会炸 prompt token 预算，
# 需要时可通过 subgraph_node_types 显式包含。
_DEFAULT_SUBGRAPH_NODE_TYPES = frozenset(
    {"User", "Account", "Host", "NetworkEndpoint", "Process"}
)

# 每类节点的默认上限（超过按 last_seen desc 裁剪）。Process 最易爆炸，严格限量。
_DEFAULT_MAX_NODES_PER_TYPE = {"Process": 8}


@dataclass
class Judgment:
    judgment_id: str
    alert_id: str
    verdict: str                       # "malicious" | "suspicious" | "benign" | "unknown"
    confidence: float
    reasoning_steps: List[str]
    evidence_refs: List[Dict[str, Any]]
    attack_chain: List[str]
    next_steps: List[str]
    ontology_version: str
    semantic_gap: Optional[Dict[str, Any]] = None
    needs_review: bool = False
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class JudgmentEngine:
    def __init__(
        self,
        llm,
        graph,
        signal_hub,
        ontology=None,
        subgraph_depth: int = 2,
        low_conf_threshold: float = 0.5,
        subgraph_node_types=None,
        max_nodes_per_type=None,
    ) -> None:
        self._llm = llm
        self._graph = graph
        self._signal_hub = signal_hub
        self._ontology = ontology
        self._depth = subgraph_depth
        self._low_conf = low_conf_threshold
        self._include_types = (
            set(subgraph_node_types)
            if subgraph_node_types is not None
            else set(_DEFAULT_SUBGRAPH_NODE_TYPES)
        )
        self._max_per_type = dict(
            max_nodes_per_type
            if max_nodes_per_type is not None
            else _DEFAULT_MAX_NODES_PER_TYPE
        )

    # -------- Public API --------

    def judge(self, alert) -> Judgment:
        subgraph = self._extract_subgraph(alert)
        system = self._render_system()
        user = self._render_user(alert, subgraph)

        def _validator(data: Dict[str, Any]) -> Optional[str]:
            err = validate_evidence_refs(data)
            if err is not None:
                return err
            return self._validate_refs_strict(data, alert, subgraph)

        response = self._llm.structured_json(
            system=system, user=user,
            required_keys=_REQUIRED_KEYS,
            validator=_validator,
            max_tokens=2048, temperature=0.1, max_retries=2,
        )

        confidence = float(response["confidence"])
        judgment = Judgment(
            judgment_id=str(uuid.uuid4()),
            alert_id=alert.alert_id,
            verdict=str(response["verdict"]),
            confidence=confidence,
            reasoning_steps=list(response.get("reasoning_steps") or []),
            evidence_refs=list(response.get("evidence_refs") or []),
            attack_chain=list(response.get("attack_chain") or []),
            next_steps=list(response.get("next_steps") or []),
            ontology_version=alert.ontology_version,
            semantic_gap=response.get("semantic_gap"),
            needs_review=confidence < self._low_conf,
        )

        if judgment.semantic_gap:
            self._signal_hub.report_signal(
                source_layer="reasoning",
                signal_type="semantic_gap",
                payload={
                    "alert_id": alert.alert_id,
                    "rule_id": alert.rule_id,
                    "missing_concept": judgment.semantic_gap.get("missing_concept"),
                    "description": judgment.semantic_gap.get("description"),
                },
                aggregation_key=(
                    f"reasoning:semantic_gap:{judgment.semantic_gap.get('missing_concept','')}"
                ),
                ontology_version=alert.ontology_version,
            )

        return judgment

    # -------- 子图提取 --------

    def _extract_subgraph(self, alert) -> Dict[str, Any]:
        """以 alert.computer 对应的 Host 为 center 取 N 跳，
        再按 subgraph_node_types 过滤（默认排除 Process，避免 token 爆炸）。"""
        if not alert.computer:
            return {"nodes": [], "edges": []}
        if not self._graph.has_node("Host", alert.computer):
            return {"nodes": [], "edges": []}
        raw = self._graph.subgraph_around("Host", alert.computer, depth=self._depth)
        # 1) 按类型过滤
        filtered = [n for n in raw["nodes"] if n["node_type"] in self._include_types]
        # 2) 每类型按 last_seen desc 裁剪 top-N
        by_type: Dict[str, List[Dict[str, Any]]] = {}
        for n in filtered:
            by_type.setdefault(n["node_type"], []).append(n)
        keep_nodes: List[Dict[str, Any]] = []
        for t, nodes in by_type.items():
            cap = self._max_per_type.get(t)
            if cap is not None and len(nodes) > cap:
                nodes = sorted(
                    nodes, key=lambda x: x["meta"].get("last_seen", ""), reverse=True
                )[:cap]
            keep_nodes.extend(nodes)
        kept_keys = {n["key"] for n in keep_nodes}
        keep_edges = [
            e for e in raw["edges"]
            if f"{e['from_type']}:{e['from_id']}" in kept_keys
            and f"{e['to_type']}:{e['to_id']}" in kept_keys
        ]
        return {"nodes": keep_nodes, "edges": keep_edges}

    # -------- Prompt 渲染 --------

    def _render_system(self) -> str:
        if self._ontology is not None:
            node_types = list(self._ontology.nodes.keys())
            edge_types = list(self._ontology.edges.keys())
            version = getattr(self._ontology, "version", "1.0")
        else:
            node_types = _DEFAULT_NODE_TYPES
            edge_types = _DEFAULT_EDGE_TYPES
            version = "1.0"

        return (
            "你是一名资深 Windows 安全分析师，帮助一个 AI-native SIEM 做告警研判。\n"
            f"当前本体版本 v{version}。你只能使用以下本体概念描述世界：\n"
            f"  节点类型：{', '.join(node_types)}\n"
            f"  关系类型：{', '.join(edge_types)}\n"
            "\n严格要求：\n"
            "  1) 输出必须是合法 JSON object，键齐全：verdict / confidence / reasoning_steps / "
            "evidence_refs / attack_chain / next_steps；如能观察到本体覆盖不到的事实，再加 semantic_gap。\n"
            "  2) verdict ∈ {malicious, suspicious, benign, unknown}。\n"
            "  3) confidence ∈ [0,1]；证据不足时请保持 < 0.5，不要自信撒谎。\n"
            "  4) evidence_refs 每条是 {type, ref}：\n"
            "     - type='matched_field'，ref 必须来自 Alert.matched_fields 的键；\n"
            "     - type='graph_node'，ref 必须是下方 Subgraph 节点的 key（形如 'Account:<id>'）；\n"
            "     - type='graph_edge'，ref 形如 'edge_type:from_key->to_key'，且必须出现在 Subgraph 边中。\n"
            "     编造不存在的 ref 会被拒绝，你将被要求重写。\n"
            "  5) attack_chain 用 ATT&CK 技术号（如 T1078, T1021.002）。\n"
            "  6) 若本体缺失必要概念导致无法建模事件（即本体 nodes/edges 里没有对应类型），"
            "请在 semantic_gap 字段说明 missing_concept 和 description。\n"
            "     注意：子图已做工程裁剪（按类型限额 top-N），节点不齐全不等于本体缺失，"
            "只有本体词表本身没有该概念才算 semantic_gap。\n"
        )

    def _render_user(self, alert, subgraph: Dict[str, Any]) -> str:
        alert_info = {
            "alert_id": alert.alert_id,
            "rule_id": alert.rule_id,
            "rule_title": alert.rule_title,
            "severity": alert.severity,
            "event_id": alert.event_id,
            "channel": alert.channel,
            "computer": alert.computer,
            "timestamp": alert.timestamp,
            "attack_techniques": list(alert.attack_techniques),
            "matched_fields": dict(alert.matched_fields),
            "event_data": (alert.raw_event or {}).get("event_data", {}),
        }

        if subgraph["nodes"]:
            node_lines = []
            for n in subgraph["nodes"]:
                node_lines.append(
                    f"- {n['key']}  attrs={json.dumps(n['attrs'], ensure_ascii=False, default=str)}"
                    f"  first_seen={n['meta'].get('first_seen')}"
                )
            edge_lines = []
            for e in subgraph["edges"]:
                fkey = f"{e['from_type']}:{e['from_id']}"
                tkey = f"{e['to_type']}:{e['to_id']}"
                edge_lines.append(
                    f"- {fkey} --[{e['edge_type']} "
                    f"attrs={json.dumps(e['attrs'], ensure_ascii=False, default=str)}]--> {tkey}"
                )
            subgraph_block = (
                f"## Subgraph (center=Host:{alert.computer}, depth={self._depth})\n"
                f"nodes: {len(subgraph['nodes'])}  edges: {len(subgraph['edges'])}\n\n"
                "### Nodes:\n" + "\n".join(node_lines) + "\n\n"
                "### Edges:\n" + ("\n".join(edge_lines) or "(无)")
            )
        else:
            subgraph_block = (
                f"## Subgraph\n(empty — Host:{alert.computer} 未在图中，或图谱尚未建立)\n"
            )

        return (
            "## Alert\n"
            f"{json.dumps(alert_info, ensure_ascii=False, indent=2, default=str)}\n\n"
            f"{subgraph_block}\n\n"
            "## 请求\n"
            "请基于上述告警与子图，产出 JSON 研判结论。务必让 evidence_refs 严格回指上文出现过的字段或节点/边。"
        )

    # -------- 严格 evidence_refs 校验（闸门二） --------

    @staticmethod
    def _validate_refs_strict(
        data: Dict[str, Any], alert, subgraph: Dict[str, Any]
    ) -> Optional[str]:
        node_keys = {n["key"] for n in subgraph.get("nodes", [])}
        edge_keys = set()
        for e in subgraph.get("edges", []):
            fkey = f"{e['from_type']}:{e['from_id']}"
            tkey = f"{e['to_type']}:{e['to_id']}"
            edge_keys.add(f"{e['edge_type']}:{fkey}->{tkey}")

        for ref in data.get("evidence_refs") or []:
            if not isinstance(ref, dict):
                return f"evidence_ref must be object, got {type(ref).__name__}"
            t = ref.get("type")
            r = ref.get("ref")
            if t == "matched_field":
                if r not in (alert.matched_fields or {}):
                    return f"matched_field ref not found on alert: {r}"
            elif t == "graph_node":
                if r not in node_keys:
                    return f"graph_node ref not found in subgraph: {r}"
            elif t == "graph_edge":
                if r not in edge_keys:
                    return f"graph_edge ref not found in subgraph: {r}"
            else:
                return f"unknown evidence_ref type: {t!r}"
        return None
