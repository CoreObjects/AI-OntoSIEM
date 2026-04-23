"""Windows 日志宽容解析器。

核心原则（需求文档 §4.3）：
  - 把原始日志映射到本体结构
  - 解析失败 → 进异常池，不丢
  - 未知字段 → 照常入库 + 上报信号
  - parser 配置 YAML 化，支持 hot reload（订阅本体变更）
  - 引擎是 Python 代码（稳定），配置是 YAML（LLM 可生成）

解析产物（parsed_events.duckdb）：
  - entities: 所有创建/更新的节点
  - relations: 所有创建/更新的关系
  - 按 event record_number 去重

设计决策：
  - "compose:A|B|C" → 拼接多个字段生成唯一 ID
  - "const:value"   → 字面量
  - "@computer" / "@timestamp" → 事件顶层字段
  - "event_data.X"  → event_data 子字段
"""
from __future__ import annotations

import json
import logging
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import duckdb
import yaml

from core.ontology_service import Ontology, OntologyService, get_service
from evolution.signal_hub import SignalHub, get_hub
from storage.anomaly_pool import AnomalyPool

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PARSED_DB = ROOT / "data" / "parsed_events.duckdb"
MAPPINGS_DIR = ROOT / "parsers" / "mappings"
GENERATED_MAPPINGS_DIR = ROOT / "parsers" / "generated"


# =========================================================
# 配置 & 数据结构
# =========================================================

@dataclass
class EntitySpec:
    node: str
    id_expr: str
    attrs: Dict[str, str] = field(default_factory=dict)
    meta: Dict[str, Any] = field(default_factory=dict)
    ref_name: Optional[str] = None  # 用于同事件中多个相同 node 类型的区分

    @property
    def ref_key(self) -> str:
        return self.ref_name or self.node


@dataclass
class RelationSpec:
    edge: str
    from_ref: str
    to_ref: str
    extra_attrs: Dict[str, str] = field(default_factory=dict)


@dataclass
class EventRule:
    name: str
    event_id: int
    channel: str
    description: str
    entities: List[EntitySpec]
    relations: List[RelationSpec]

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "EventRule":
        entities = [
            EntitySpec(
                node=e["node"],
                id_expr=e["id_expr"],
                attrs=e.get("attrs") or {},
                meta=e.get("meta") or {},
                ref_name=e.get("ref_name"),
            )
            for e in d.get("entities") or []
        ]
        relations = [
            RelationSpec(
                edge=r["edge"],
                from_ref=r["from_ref"],
                to_ref=r["to_ref"],
                extra_attrs=r.get("extra_attrs") or {},
            )
            for r in d.get("relations") or []
        ]
        return cls(
            name=d["name"],
            event_id=int(d["event_id"]),
            channel=d.get("channel", ""),
            description=d.get("description", ""),
            entities=entities,
            relations=relations,
        )


@dataclass
class ParserConfig:
    version: str
    target_ontology_version: str
    description: str
    rules: List[EventRule]

    # 索引：(event_id, channel) → rule
    _index: Dict[Tuple[int, str], EventRule] = field(default_factory=dict)

    @classmethod
    def load_all(cls, dirs: List[Path]) -> "ParserConfig":
        """从多个目录加载所有 YAML 配置并合并。"""
        all_rules: List[EventRule] = []
        version = "1.0"
        target_onto = "1.0"
        description = ""
        for d in dirs:
            if not d.exists():
                continue
            for yaml_path in sorted(d.glob("*.yaml")):
                with yaml_path.open("r", encoding="utf-8") as f:
                    doc = yaml.safe_load(f) or {}
                version = doc.get("version", version)
                target_onto = doc.get("target_ontology_version", target_onto)
                for rd in doc.get("rules") or []:
                    all_rules.append(EventRule.from_dict(rd))
        cfg = cls(
            version=version,
            target_ontology_version=target_onto,
            description=description,
            rules=all_rules,
        )
        cfg._build_index()
        return cfg

    def _build_index(self) -> None:
        self._index.clear()
        for rule in self.rules:
            self._index[(rule.event_id, rule.channel)] = rule

    def lookup(self, event_id: int, channel: str) -> Optional[EventRule]:
        return self._index.get((event_id, channel))


# =========================================================
# 字段表达式求值
# =========================================================

def resolve_expr(expr: str, event: Dict[str, Any]) -> Optional[Any]:
    """字段表达式求值。返回 None 表示字段缺失。"""
    if expr.startswith("const:"):
        return expr[6:]
    if expr.startswith("compose:"):
        parts = expr[8:].split("|")
        sub = [resolve_expr(p, event) for p in parts]
        if any(s is None for s in sub):
            return None
        return ":".join(str(s) for s in sub)
    if expr == "@computer":
        return event.get("computer")
    if expr == "@timestamp":
        return event.get("timestamp")
    if expr.startswith("event_data."):
        key = expr.split(".", 1)[1]
        ed = event.get("event_data")
        if isinstance(ed, str):
            try:
                ed = json.loads(ed)
            except json.JSONDecodeError:
                return None
        if not isinstance(ed, dict):
            return None
        return ed.get(key)
    # 未知表达式格式：作为字面量返回
    return expr


# =========================================================
# 解析结果
# =========================================================

@dataclass
class ParsedEntity:
    record_id: int         # 源事件 record_number
    node_type: str
    node_id: str
    ref_key: str
    attrs: Dict[str, Any]
    meta: Dict[str, Any]
    timestamp: str
    ontology_version: str


@dataclass
class ParsedRelation:
    record_id: int
    edge_type: str
    from_type: str
    from_id: str
    to_type: str
    to_id: str
    attrs: Dict[str, Any]
    timestamp: str
    ontology_version: str


@dataclass
class ParseResult:
    record_id: int
    success: bool
    entities: List[ParsedEntity] = field(default_factory=list)
    relations: List[ParsedRelation] = field(default_factory=list)
    unknown_fields: List[str] = field(default_factory=list)
    failure_reason: Optional[str] = None


# =========================================================
# Parser 主类
# =========================================================

class WindowsParser:
    """宽容解析引擎。

    对每条事件：
      1) 根据 (event_id, channel) 查找规则；找不到 → 异常池 + unparseable_event 信号
      2) 按规则解析 entities 和 relations；必要字段缺失 → 异常池
      3) event_data 中出现规则未引用的字段 → unknown_field 信号
      4) 引用的本体类型不在当前本体里 → 异常池 + orphan_entity 信号
    """

    def __init__(
        self,
        ontology: Optional[Ontology] = None,
        config: Optional[ParserConfig] = None,
        anomaly_pool: Optional[AnomalyPool] = None,
        signal_hub: Optional[SignalHub] = None,
        emit_unknown_field_signals: bool = False,
    ) -> None:
        # 默认不发 unknown_field 信号。原因：MVP 阶段的合法 Windows 事件里存在大量
        # 我们不需要的合法字段（如 SubjectLogonId、LogonGuid、TransmittedServices 等），
        # 全部上报会淹没真正的 unparseable_event 信号（Demo 主叙事）。
        # 需要时可手动开启（用于二级演化故事："新 Sysmon 版本引入 OriginalFileName"）。
        self._emit_unknown_field_signals = emit_unknown_field_signals
        self._onto_service: Optional[OntologyService] = None
        if ontology is None:
            self._onto_service = get_service()
            self._ontology = self._onto_service.get_current()
            self._onto_service.subscribe(self._on_ontology_upgrade)
        else:
            self._ontology = ontology

        self._config = config or ParserConfig.load_all([MAPPINGS_DIR, GENERATED_MAPPINGS_DIR])
        self._anomaly_pool = anomaly_pool if anomaly_pool is not None else AnomalyPool()
        self._signal_hub = signal_hub if signal_hub is not None else get_hub()
        self._lock = threading.RLock()

    def _on_ontology_upgrade(self, old: Optional[Ontology], new: Ontology) -> None:
        """订阅本体变更 → hot reload parser 配置。"""
        with self._lock:
            logger.info("Ontology upgraded %s -> %s, reloading parser config",
                        old.version if old else None, new.version)
            self._ontology = new
            self._config = ParserConfig.load_all([MAPPINGS_DIR, GENERATED_MAPPINGS_DIR])

    # -------- Public API --------

    def parse_event(self, event: Dict[str, Any]) -> ParseResult:
        """解析单条事件。

        期望 event 字段：event_id, channel, computer, timestamp, record_number, event_data
        """
        record_id = int(event.get("record_number") or 0)
        event_id = int(event.get("event_id") or 0)
        channel = event.get("channel") or ""

        rule = self._config.lookup(event_id, channel)
        if rule is None:
            reason = f"no rule for (event_id={event_id}, channel={channel})"
            self._report_unparseable(record_id, event, reason)
            return ParseResult(record_id=record_id, success=False, failure_reason=reason)

        entities: List[ParsedEntity] = []
        relations: List[ParsedRelation] = []
        ref_table: Dict[str, ParsedEntity] = {}

        # 1) 解析实体
        for espec in rule.entities:
            if not self._ontology.has_node(espec.node):
                reason = f"ontology has no node '{espec.node}' (needed by rule '{rule.name}')"
                self._report_unparseable(record_id, event, reason)
                self._signal_hub.report_signal(
                    source_layer="data",
                    signal_type="orphan_entity",
                    payload={"record_id": record_id, "node_type": espec.node, "rule": rule.name},
                    ontology_version=self._ontology.version,
                )
                return ParseResult(record_id=record_id, success=False, failure_reason=reason)

            node_id = resolve_expr(espec.id_expr, event)
            if node_id is None:
                reason = f"cannot resolve id_expr '{espec.id_expr}' for node '{espec.node}'"
                self._report_unparseable(record_id, event, reason)
                return ParseResult(record_id=record_id, success=False, failure_reason=reason)

            attrs: Dict[str, Any] = {}
            for k, expr in espec.attrs.items():
                v = resolve_expr(expr, event)
                if v is not None:
                    attrs[k] = v

            meta = dict(espec.meta)
            meta.setdefault("source", "log")
            meta.setdefault("confidence", 1.0)

            pe = ParsedEntity(
                record_id=record_id,
                node_type=espec.node,
                node_id=str(node_id),
                ref_key=espec.ref_key,
                attrs=attrs,
                meta=meta,
                timestamp=str(event.get("timestamp")),
                ontology_version=self._ontology.version,
            )
            entities.append(pe)
            ref_table[espec.ref_key] = pe

        # 2) 解析关系
        for rspec in rule.relations:
            if not self._ontology.has_edge(rspec.edge):
                self._signal_hub.report_signal(
                    source_layer="data",
                    signal_type="unmapped_relation",
                    payload={"record_id": record_id, "edge_type": rspec.edge, "rule": rule.name},
                    ontology_version=self._ontology.version,
                )
                continue

            f = ref_table.get(rspec.from_ref)
            t = ref_table.get(rspec.to_ref)
            if f is None or t is None:
                logger.warning("relation %s: missing ref %s or %s", rspec.edge, rspec.from_ref, rspec.to_ref)
                continue

            # 校验边的端点与本体定义一致
            endpoints = self._ontology.edge_endpoints(rspec.edge)
            if endpoints and (f.node_type, t.node_type) != endpoints:
                self._signal_hub.report_signal(
                    source_layer="data",
                    signal_type="unmapped_relation",
                    payload={
                        "record_id": record_id,
                        "edge_type": rspec.edge,
                        "found": (f.node_type, t.node_type),
                        "expected": endpoints,
                        "rule": rule.name,
                    },
                    ontology_version=self._ontology.version,
                )
                continue

            extra: Dict[str, Any] = {}
            for k, expr in rspec.extra_attrs.items():
                v = resolve_expr(expr, event)
                if v is not None:
                    extra[k] = v

            relations.append(ParsedRelation(
                record_id=record_id,
                edge_type=rspec.edge,
                from_type=f.node_type, from_id=f.node_id,
                to_type=t.node_type, to_id=t.node_id,
                attrs=extra,
                timestamp=str(event.get("timestamp")),
                ontology_version=self._ontology.version,
            ))

        # 3) 未知字段检测
        unknown = self._detect_unknown_fields(rule, event)

        return ParseResult(
            record_id=record_id,
            success=True,
            entities=entities,
            relations=relations,
            unknown_fields=unknown,
        )

    def parse_batch(self, events: List[Dict[str, Any]]) -> List[ParseResult]:
        return [self.parse_event(ev) for ev in events]

    def _detect_unknown_fields(self, rule: EventRule, event: Dict[str, Any]) -> List[str]:
        """检测 event_data 中出现了规则未引用的字段。"""
        ed = event.get("event_data")
        if isinstance(ed, str):
            try:
                ed = json.loads(ed)
            except json.JSONDecodeError:
                return []
        if not isinstance(ed, dict):
            return []

        referenced: set[str] = set()
        for espec in rule.entities:
            for expr in espec.attrs.values():
                if expr.startswith("event_data."):
                    referenced.add(expr.split(".", 1)[1])
                if expr.startswith("compose:"):
                    for part in expr[8:].split("|"):
                        if part.startswith("event_data."):
                            referenced.add(part.split(".", 1)[1])
            if espec.id_expr.startswith("event_data."):
                referenced.add(espec.id_expr.split(".", 1)[1])
            if espec.id_expr.startswith("compose:"):
                for part in espec.id_expr[8:].split("|"):
                    if part.startswith("event_data."):
                        referenced.add(part.split(".", 1)[1])
        for rspec in rule.relations:
            for expr in rspec.extra_attrs.values():
                if expr.startswith("event_data."):
                    referenced.add(expr.split(".", 1)[1])

        unknown = sorted(set(ed.keys()) - referenced)
        if unknown and self._emit_unknown_field_signals:
            self._signal_hub.report_signal(
                source_layer="data",
                signal_type="unknown_field",
                payload={
                    "event_id": rule.event_id,
                    "channel": rule.channel,
                    "unknown_fields": unknown,
                },
                aggregation_key=f"data:unknown_field:{rule.event_id}",
                ontology_version=self._ontology.version,
            )
        return unknown

    def _report_unparseable(self, record_id: int, event: Dict[str, Any], reason: str) -> None:
        self._anomaly_pool.add(
            record_id=record_id,
            event_id=int(event.get("event_id") or 0),
            computer=str(event.get("computer") or ""),
            timestamp=event.get("timestamp"),
            failure_reason=reason,
            raw_event=event,
            ontology_version=self._ontology.version,
        )
        self._signal_hub.report_signal(
            source_layer="data",
            signal_type="unparseable_event",
            payload={
                "record_id": record_id,
                "event_id": event.get("event_id"),
                "channel": event.get("channel"),
                "reason": reason,
            },
            aggregation_key=f"data:unparseable_event:{event.get('event_id')}",
            ontology_version=self._ontology.version,
        )


# =========================================================
# 批量处理：从 events.duckdb 读取 → 写入 parsed_events.duckdb
# =========================================================

def parse_database(
    events_db: Path,
    parsed_db: Path = DEFAULT_PARSED_DB,
    parser: Optional[WindowsParser] = None,
) -> Dict[str, int]:
    """从 events.duckdb 读全部事件，解析后写入 parsed_events.duckdb。

    返回统计信息（成功/失败/未知字段数）。
    """
    parser = parser or WindowsParser()
    parsed_db.parent.mkdir(parents=True, exist_ok=True)
    if parsed_db.exists():
        parsed_db.unlink()

    con_in = duckdb.connect(str(events_db), read_only=True)
    rows = con_in.execute(
        "SELECT event_id, channel, provider, record_number, timestamp, computer, event_data "
        "FROM events ORDER BY record_number"
    ).fetchall()
    con_in.close()

    con_out = duckdb.connect(str(parsed_db))
    con_out.execute("""
        CREATE TABLE entities (
            record_id        BIGINT,
            node_type        VARCHAR,
            node_id          VARCHAR,
            ref_key          VARCHAR,
            attrs            JSON,
            meta             JSON,
            timestamp        TIMESTAMP,
            ontology_version VARCHAR
        )
    """)
    con_out.execute("""
        CREATE TABLE relations (
            record_id        BIGINT,
            edge_type        VARCHAR,
            from_type        VARCHAR,
            from_id          VARCHAR,
            to_type          VARCHAR,
            to_id            VARCHAR,
            attrs            JSON,
            timestamp        TIMESTAMP,
            ontology_version VARCHAR
        )
    """)

    stats = defaultdict(int)
    ent_buf: List[tuple] = []
    rel_buf: List[tuple] = []

    for r in rows:
        event = {
            "event_id": r[0],
            "channel": r[1],
            "provider": r[2],
            "record_number": r[3],
            "timestamp": r[4],
            "computer": r[5],
            "event_data": r[6],
        }
        result = parser.parse_event(event)
        if result.success:
            stats["parsed"] += 1
            stats["entities"] += len(result.entities)
            stats["relations"] += len(result.relations)
            if result.unknown_fields:
                stats["events_with_unknown_fields"] += 1
            for e in result.entities:
                ent_buf.append((
                    e.record_id, e.node_type, e.node_id, e.ref_key,
                    json.dumps(e.attrs, ensure_ascii=False, default=str),
                    json.dumps(e.meta, ensure_ascii=False, default=str),
                    e.timestamp, e.ontology_version,
                ))
            for rel in result.relations:
                rel_buf.append((
                    rel.record_id, rel.edge_type, rel.from_type, rel.from_id,
                    rel.to_type, rel.to_id,
                    json.dumps(rel.attrs, ensure_ascii=False, default=str),
                    rel.timestamp, rel.ontology_version,
                ))
        else:
            stats["failed"] += 1

    if ent_buf:
        con_out.executemany(
            "INSERT INTO entities VALUES (?, ?, ?, ?, ?, ?, ?, ?)", ent_buf
        )
    if rel_buf:
        con_out.executemany(
            "INSERT INTO relations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", rel_buf
        )
    con_out.close()

    return dict(stats)
