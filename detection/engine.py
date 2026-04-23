"""组件 4 检测引擎：Sigma 子集规则引擎。

设计原则（需求文档 §4.4 + task_plan 组件 4）：
  - Sigma YAML 格式（子集：selection + 四种修饰符）
  - 规则加载时读本体校验 ontology_refs，缺失 → rule_schema_mismatch 信号
  - 每条告警带 ATT&CK 技术标签
  - 告警写 data/alerts.duckdb

Sigma 子集支持：
  - selection 下多个 key 为 AND
  - 每个 key 的 value 可以是标量或列表（列表为 OR）
  - 修饰符：|endswith / |startswith / |contains（大小写不敏感）/ 默认相等
  - 字段路径：EventData.X / @computer / @timestamp
"""
from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

logger = logging.getLogger(__name__)


# =========================================================
# 字段提取
# =========================================================

def _resolve_field(path: str, event: Dict[str, Any]) -> Optional[Any]:
    """从事件中取字段值。支持 EventData.X 和 @computer / @timestamp。"""
    if path == "@computer":
        return event.get("computer")
    if path == "@timestamp":
        return event.get("timestamp")
    if path == "@event_id":
        return event.get("event_id")
    if path.startswith("EventData."):
        key = path.split(".", 1)[1]
        ed = event.get("event_data")
        if isinstance(ed, str):
            try:
                ed = json.loads(ed)
            except json.JSONDecodeError:
                return None
        if not isinstance(ed, dict):
            return None
        return ed.get(key)
    # 未知前缀：当作顶层字段
    return event.get(path)


def _split_modifier(key: str) -> Tuple[str, str]:
    if "|" in key:
        field_path, mod = key.split("|", 1)
        return field_path, mod.lower()
    return key, "eq"


def _match_single(value: Any, expected: Any, modifier: str) -> bool:
    if value is None:
        return False
    s_val = str(value)
    s_exp = str(expected)
    if modifier == "eq":
        # 数值和字符串都支持；优先类型相等后字符串化相等
        if value == expected:
            return True
        return s_val == s_exp
    if modifier == "endswith":
        return s_val.lower().endswith(s_exp.lower())
    if modifier == "startswith":
        return s_val.lower().startswith(s_exp.lower())
    if modifier == "contains":
        return s_exp.lower() in s_val.lower()
    # 未知修饰符 → 不匹配
    return False


def _match_clause(value: Any, expected: Any, modifier: str) -> bool:
    """期望值可以是列表（OR）或标量。"""
    if isinstance(expected, list):
        return any(_match_single(value, e, modifier) for e in expected)
    return _match_single(value, expected, modifier)


# =========================================================
# SigmaRule
# =========================================================

@dataclass
class SigmaRule:
    id: str
    title: str
    description: str
    level: str
    channel: str
    event_ids: List[int]
    attack_techniques: List[str] = field(default_factory=list)
    selection: Dict[str, Any] = field(default_factory=dict)
    ontology_nodes: List[str] = field(default_factory=list)
    ontology_edges: List[str] = field(default_factory=list)

    @classmethod
    def from_yaml(cls, path: Path) -> "SigmaRule":
        with Path(path).open("r", encoding="utf-8") as f:
            doc = yaml.safe_load(f) or {}
        logsource = doc.get("logsource") or {}
        tags = doc.get("tags") or []
        # 只提取技术号（attack.t<digits> 或 attack.t<digits>.<sub>）；
        # 战术标签（attack.credential_access 等）不计入 techniques。
        attack: List[str] = []
        for t in tags:
            if not isinstance(t, str) or not t.startswith("attack."):
                continue
            suffix = t.split(".", 1)[1]
            # 必须形如 t1234 或 t1234.001
            head = suffix.split(".", 1)[0]
            if len(head) >= 2 and head[0] in ("t", "T") and head[1:].isdigit():
                attack.append(suffix.upper())
        detection = doc.get("detection") or {}
        onto_refs = doc.get("ontology_refs") or {}
        return cls(
            id=str(doc["id"]),
            title=str(doc.get("title", "")),
            description=str(doc.get("description", "")),
            level=str(doc.get("level", "medium")),
            channel=str(logsource.get("channel", "")),
            event_ids=[int(x) for x in (doc.get("event_ids") or [])],
            attack_techniques=attack,
            selection=dict(detection.get("selection") or {}),
            ontology_nodes=list(onto_refs.get("nodes") or []),
            ontology_edges=list(onto_refs.get("edges") or []),
        )

    def matches(self, event: Dict[str, Any]) -> bool:
        return self.match_detail(event) is not None

    def match_detail(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """返回匹配字段 {field_path: expected_value}；不匹配返回 None。"""
        if self.event_ids:
            ev_id = event.get("event_id")
            if ev_id is None or int(ev_id) not in self.event_ids:
                return None
        if self.channel and event.get("channel") != self.channel:
            return None
        matched: Dict[str, Any] = {}
        for key, expected in self.selection.items():
            field_path, modifier = _split_modifier(key)
            actual = _resolve_field(field_path, event)
            if isinstance(expected, list):
                hit = None
                for e in expected:
                    if _match_single(actual, e, modifier):
                        hit = e
                        break
                if hit is None:
                    return None
                matched[field_path] = hit
            else:
                if not _match_single(actual, expected, modifier):
                    return None
                matched[field_path] = expected
        return matched


# =========================================================
# Alert
# =========================================================

@dataclass
class Alert:
    alert_id: str
    rule_id: str
    rule_title: str
    severity: str
    event_record_id: int
    event_id: int
    channel: str
    computer: str
    timestamp: str
    attack_techniques: List[str]
    matched_fields: Dict[str, Any]
    ontology_version: str
    raw_event: Dict[str, Any] = field(default_factory=dict)


# =========================================================
# DetectionEngine
# =========================================================

class DetectionEngine:
    """加载规则 → 对事件求值 → 产出告警。"""

    def __init__(
        self,
        rules_dir: Path,
        ontology: Any = None,
        signal_hub: Any = None,
    ) -> None:
        self._rules_dir = Path(rules_dir)
        self._ontology = ontology
        self._signal_hub = signal_hub
        self.rules: List[SigmaRule] = self._load_rules()
        self._validate_ontology_refs()

    def _load_rules(self) -> List[SigmaRule]:
        if not self._rules_dir.exists():
            return []
        rules: List[SigmaRule] = []
        for p in sorted(self._rules_dir.glob("*.yaml")):
            try:
                rules.append(SigmaRule.from_yaml(p))
            except Exception:
                logger.exception("Failed to load rule %s", p)
        return rules

    def _validate_ontology_refs(self) -> None:
        """对每条规则校验 ontology_refs；缺失则发 rule_schema_mismatch 信号。

        降级策略：校验失败不阻断规则加载，规则仍可评估。
        """
        if self._ontology is None or self._signal_hub is None:
            return
        onto_ver = getattr(self._ontology, "version", "unknown")
        for rule in self.rules:
            missing_nodes = [n for n in rule.ontology_nodes if not self._ontology.has_node(n)]
            missing_edges = [e for e in rule.ontology_edges if not self._ontology.has_edge(e)]
            if not missing_nodes and not missing_edges:
                continue
            self._signal_hub.report_signal(
                source_layer="detection",
                signal_type="rule_schema_mismatch",
                payload={
                    "rule_id": rule.id,
                    "rule_title": rule.title,
                    "missing_nodes": missing_nodes,
                    "missing_edges": missing_edges,
                },
                aggregation_key=f"detection:rule_schema_mismatch:{rule.id}",
                ontology_version=onto_ver,
            )

    def evaluate_event(self, event: Dict[str, Any]) -> List[Alert]:
        alerts: List[Alert] = []
        onto_ver = getattr(self._ontology, "version", "unknown") if self._ontology else "unknown"
        for rule in self.rules:
            detail = rule.match_detail(event)
            if detail is None:
                continue
            alerts.append(Alert(
                alert_id=str(uuid.uuid4()),
                rule_id=rule.id,
                rule_title=rule.title,
                severity=rule.level,
                event_record_id=int(event.get("record_number") or 0),
                event_id=int(event.get("event_id") or 0),
                channel=str(event.get("channel") or ""),
                computer=str(event.get("computer") or ""),
                timestamp=str(event.get("timestamp") or ""),
                attack_techniques=list(rule.attack_techniques),
                matched_fields=detail,
                ontology_version=onto_ver,
                raw_event=dict(event),
            ))
        return alerts

    def evaluate_batch(self, events: List[Dict[str, Any]]) -> List[Alert]:
        out: List[Alert] = []
        for ev in events:
            out.extend(self.evaluate_event(ev))
        return out
