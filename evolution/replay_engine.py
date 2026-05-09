"""组件 10 Day 3：异常池回放引擎。

输入：(anomaly_pool, parser_config, ontology, graph)
输出：ReplayReport

副作用：
  - 成功解析的 anomaly 记录 → mark_backfilled
  - 灌图：新建实体打 backfilled=True / backfilled_at / backfilled_ontology_version
        已存在的实体只合并 last_seen 不打 backfilled flag
  - 解析失败 → 留在 anomaly_pool（backfilled=False）

副作用隔离：内部 WindowsParser 用 NoOp anomaly_pool / signal_hub stub，
不会因为再次解析失败而往原池重复写。
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


# =========================================================
# Stubs（preview / replay 同模式 — 隔绝副作用）
# =========================================================

class _NoOpAnomalyPool:
    def add(self, **kwargs) -> None:
        pass


class _NoOpSignalHub:
    def report_signal(self, **kwargs) -> None:
        pass


# =========================================================
# Report
# =========================================================

@dataclass
class ReplayReport:
    started_at: str
    finished_at: str
    ontology_version: str
    total_open_before: int
    attempted: int
    backfilled: int
    failed: int
    total_open_after: int
    new_entities: int
    merged_entities: int
    new_relations: int
    merged_relations: int
    by_event_id: Dict[int, Dict[str, int]] = field(default_factory=dict)

    @property
    def success_rate(self) -> float:
        return self.backfilled / max(self.attempted, 1)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "ontology_version": self.ontology_version,
            "total_open_before": self.total_open_before,
            "attempted": self.attempted,
            "backfilled": self.backfilled,
            "failed": self.failed,
            "total_open_after": self.total_open_after,
            "new_entities": self.new_entities,
            "merged_entities": self.merged_entities,
            "new_relations": self.new_relations,
            "merged_relations": self.merged_relations,
            "by_event_id": self.by_event_id,
            "success_rate": self.success_rate,
        }


# =========================================================
# ReplayEngine
# =========================================================

class ReplayEngine:
    def __init__(self, *, anomaly_pool, parser_config, ontology, graph) -> None:
        self._pool = anomaly_pool
        self._cfg = parser_config
        self._ontology = ontology
        self._graph = graph

    def replay(self) -> ReplayReport:
        from parsers.windows_parser import WindowsParser

        started_at = _now_iso()
        total_before = self._pool.size_open()

        parser = WindowsParser(
            ontology=self._ontology,
            config=self._cfg,
            anomaly_pool=_NoOpAnomalyPool(),
            signal_hub=_NoOpSignalHub(),
        )

        attempted = 0
        backfilled = 0
        failed = 0
        new_entities = 0
        merged_entities = 0
        new_relations = 0
        merged_relations = 0
        by_event_id: Dict[int, Dict[str, int]] = {}

        # list_open 已经过滤 backfilled=True 的，所以不会重复跑已 backfill 的
        records = self._pool.list_open(limit=10000)
        now_iso = _now_iso()

        for rec in records:
            attempted += 1
            event_id = int(rec.get("event_id") or 0)
            ev_stats = by_event_id.setdefault(
                event_id, {"backfilled": 0, "failed": 0}
            )

            raw = rec.get("raw_event") or {}
            result = parser.parse_event(raw)

            if not result.success:
                failed += 1
                ev_stats["failed"] += 1
                continue

            n_new, n_merged = self._upsert_entities(result.entities, now_iso)
            new_entities += n_new
            merged_entities += n_merged

            n_rel_new, n_rel_merged = self._upsert_relations(result.relations)
            new_relations += n_rel_new
            merged_relations += n_rel_merged

            self._pool.mark_backfilled(rec["record_id"], self._ontology.version)
            backfilled += 1
            ev_stats["backfilled"] += 1

        finished_at = _now_iso()
        return ReplayReport(
            started_at=started_at, finished_at=finished_at,
            ontology_version=getattr(self._ontology, "version", "unknown"),
            total_open_before=total_before,
            attempted=attempted, backfilled=backfilled, failed=failed,
            total_open_after=self._pool.size_open(),
            new_entities=new_entities, merged_entities=merged_entities,
            new_relations=new_relations, merged_relations=merged_relations,
            by_event_id=by_event_id,
        )

    # -------- 灌图 --------

    def _upsert_entities(self, entities, now_iso: str) -> "tuple[int, int]":
        n_new = n_merged = 0
        for ent in entities:
            is_new = not self._graph.has_node(ent.node_type, ent.node_id)
            attrs = dict(ent.attrs)
            if is_new:
                attrs["backfilled"] = True
                attrs["backfilled_at"] = now_iso
                attrs["backfilled_ontology_version"] = getattr(
                    self._ontology, "version", "unknown"
                )
            try:
                self._graph.upsert_entity(
                    node_type=ent.node_type,
                    node_id=ent.node_id,
                    attrs=attrs,
                    timestamp=ent.timestamp,
                    source=str(ent.meta.get("source", "log")),
                    confidence=float(ent.meta.get("confidence", 1.0)),
                )
            except Exception as exc:
                logger.warning(
                    "replay upsert_entity failed (%s:%s): %s",
                    ent.node_type, ent.node_id, exc,
                )
                continue
            if is_new:
                n_new += 1
            else:
                n_merged += 1
        return n_new, n_merged

    def _upsert_relations(self, relations) -> "tuple[int, int]":
        """relations 简化处理：所有成功 upsert 都计入 new_relations。
        merge 与否对 Day 3 没语义影响（Day 4 diff 可再细化）。
        """
        n_new = 0
        n_merged = 0
        for rel in relations:
            try:
                self._graph.upsert_relation(
                    edge_type=rel.edge_type,
                    from_type=rel.from_type, from_id=rel.from_id,
                    to_type=rel.to_type, to_id=rel.to_id,
                    timestamp=rel.timestamp,
                    source="log",
                    confidence=1.0,
                    attrs=dict(rel.attrs),
                )
                n_new += 1
            except Exception as exc:
                logger.warning("replay upsert_relation failed (%s): %s",
                               rel.edge_type, exc)
        return n_new, n_merged


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
