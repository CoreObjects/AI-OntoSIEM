"""演化信号中枢（最小实现，组件 7 会在此基础上扩展）。

所有层通过 `report_signal()` 统一上报"本体失配"信号。
信号写入 `data/signals.duckdb`，供后续提议引擎消费。

Schema 见 docs/attack_scenarios.md 附录 B / 需求文档附录 B。
"""
from __future__ import annotations

import json
import logging
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import duckdb

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = ROOT / "data" / "signals.duckdb"

SOURCE_LAYERS = {"data", "detection", "graph", "reasoning", "copilot", "evaluation"}
SIGNAL_TYPES = {
    "unparseable_event", "unknown_field", "rule_schema_mismatch",
    "orphan_entity", "unmapped_relation", "semantic_gap",
    "manual_annotation", "coverage_deficit",
}
PRIORITIES = {"hot", "warm", "cold"}

# signal_type → priority 的默认映射
_DEFAULT_PRIORITY = {
    "unparseable_event":     "hot",
    "unknown_field":         "hot",
    "rule_schema_mismatch":  "warm",
    "orphan_entity":         "warm",
    "unmapped_relation":     "warm",
    "semantic_gap":          "warm",
    "manual_annotation":     "warm",
    "coverage_deficit":      "cold",
}


@dataclass
class Signal:
    signal_id: str
    timestamp: str
    source_layer: str
    signal_type: str
    priority: str
    payload: Dict[str, Any]
    aggregation_key: str
    ontology_version: str

    def to_db_row(self) -> tuple:
        return (
            self.signal_id,
            self.timestamp,
            self.source_layer,
            self.signal_type,
            self.priority,
            json.dumps(self.payload, ensure_ascii=False),
            self.aggregation_key,
            self.ontology_version,
        )


class SignalHub:
    """最小信号中枢：持久化到 DuckDB。

    线程安全；DuckDB 单连接（原型够用）。
    """

    def __init__(self, db_path: Path = DEFAULT_DB) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._con = duckdb.connect(str(self._db_path))
        self._con.execute("""
            CREATE TABLE IF NOT EXISTS signals (
                signal_id        VARCHAR PRIMARY KEY,
                timestamp        TIMESTAMP,
                source_layer     VARCHAR,
                signal_type      VARCHAR,
                priority         VARCHAR,
                payload          JSON,
                aggregation_key  VARCHAR,
                ontology_version VARCHAR,
                processed_at     TIMESTAMP
            )
        """)
        # 向后兼容：老 DB 可能没 processed_at 列
        try:
            self._con.execute(
                "ALTER TABLE signals ADD COLUMN processed_at TIMESTAMP"
            )
        except duckdb.CatalogException:
            pass  # 列已存在

    def report_signal(
        self,
        source_layer: str,
        signal_type: str,
        payload: Dict[str, Any],
        *,
        aggregation_key: Optional[str] = None,
        ontology_version: Optional[str] = None,
        priority: Optional[str] = None,
        timestamp: Optional[datetime] = None,
    ) -> Signal:
        if source_layer not in SOURCE_LAYERS:
            raise ValueError(f"Unknown source_layer: {source_layer}")
        if signal_type not in SIGNAL_TYPES:
            raise ValueError(f"Unknown signal_type: {signal_type}")
        if priority is None:
            priority = _DEFAULT_PRIORITY[signal_type]
        if priority not in PRIORITIES:
            raise ValueError(f"Unknown priority: {priority}")
        if aggregation_key is None:
            aggregation_key = f"{source_layer}:{signal_type}"

        sig = Signal(
            signal_id=str(uuid.uuid4()),
            timestamp=(timestamp or datetime.now(timezone.utc)).isoformat(),
            source_layer=source_layer,
            signal_type=signal_type,
            priority=priority,
            payload=payload,
            aggregation_key=aggregation_key,
            ontology_version=ontology_version or "unknown",
        )
        with self._lock:
            self._con.execute(
                "INSERT INTO signals (signal_id, timestamp, source_layer, signal_type, priority, payload, aggregation_key, ontology_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                sig.to_db_row(),
            )
        logger.info("signal %s/%s priority=%s", source_layer, signal_type, priority)
        return sig

    def count_by_type(self) -> Dict[str, int]:
        with self._lock:
            rows = self._con.execute(
                "SELECT signal_type, COUNT(*) FROM signals GROUP BY signal_type"
            ).fetchall()
        return {r[0]: r[1] for r in rows}

    def count_all(self) -> int:
        with self._lock:
            return self._con.execute("SELECT COUNT(*) FROM signals").fetchone()[0]

    def list_recent(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._con.execute(
                "SELECT signal_id, timestamp, source_layer, signal_type, priority, payload, aggregation_key, ontology_version "
                "FROM signals ORDER BY timestamp DESC LIMIT ?",
                [limit],
            ).fetchall()
        return [
            {
                "signal_id": r[0],
                "timestamp": str(r[1]),
                "source_layer": r[2],
                "signal_type": r[3],
                "priority": r[4],
                "payload": json.loads(r[5]) if isinstance(r[5], str) else r[5],
                "aggregation_key": r[6],
                "ontology_version": r[7],
            }
            for r in rows
        ]

    # -------- 聚合 / 分级 / 待处理 / 消费标记（组件 7 完整版）--------

    def list_aggregations(
        self,
        *,
        window_hours: Optional[int] = None,
        min_count: int = 1,
    ) -> List[Dict[str, Any]]:
        """按 aggregation_key 分组返回聚合视图。

        字段：aggregation_key / count / first_seen / last_seen /
             source_layer / signal_type / priority / processed(bool)
        processed=True 表示该组所有行都已被 mark_processed。
        """
        where_clause = ""
        params: List[Any] = []
        if window_hours is not None:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=window_hours)
            where_clause = "WHERE timestamp >= ?"
            params.append(cutoff)

        sql = f"""
            SELECT
                aggregation_key,
                COUNT(*) AS cnt,
                MIN(timestamp) AS first_seen,
                MAX(timestamp) AS last_seen,
                ANY_VALUE(source_layer) AS source_layer,
                ANY_VALUE(signal_type) AS signal_type,
                ANY_VALUE(priority) AS priority,
                SUM(CASE WHEN processed_at IS NULL THEN 1 ELSE 0 END) AS unprocessed_cnt
            FROM signals
            {where_clause}
            GROUP BY aggregation_key
            HAVING COUNT(*) >= ?
            ORDER BY cnt DESC, last_seen DESC
        """
        params.append(min_count)

        with self._lock:
            rows = self._con.execute(sql, params).fetchall()
        return [
            {
                "aggregation_key": r[0],
                "count": int(r[1]),
                "first_seen": str(r[2]),
                "last_seen": str(r[3]),
                "source_layer": r[4],
                "signal_type": r[5],
                "priority": r[6],
                "processed": int(r[7]) == 0,
            }
            for r in rows
        ]

    def list_pending(
        self,
        *,
        window_hours: int = 24,
        threshold: int = 20,
    ) -> List[Dict[str, Any]]:
        """窗口内 >= threshold 且尚未处理的聚合组。"""
        groups = self.list_aggregations(window_hours=window_hours, min_count=threshold)
        return [g for g in groups if not g["processed"]]

    def list_by_priority(self, priority: str, *, limit: int = 50) -> List[Dict[str, Any]]:
        if priority not in PRIORITIES:
            raise ValueError(f"Unknown priority: {priority}")
        with self._lock:
            rows = self._con.execute(
                "SELECT signal_id, timestamp, source_layer, signal_type, priority, "
                "payload, aggregation_key, ontology_version, processed_at "
                "FROM signals WHERE priority = ? ORDER BY timestamp DESC LIMIT ?",
                [priority, limit],
            ).fetchall()
        return [
            {
                "signal_id": r[0],
                "timestamp": str(r[1]),
                "source_layer": r[2],
                "signal_type": r[3],
                "priority": r[4],
                "payload": json.loads(r[5]) if isinstance(r[5], str) else r[5],
                "aggregation_key": r[6],
                "ontology_version": r[7],
                "processed_at": str(r[8]) if r[8] is not None else None,
            }
            for r in rows
        ]

    def count_by_priority(self) -> Dict[str, int]:
        with self._lock:
            rows = self._con.execute(
                "SELECT priority, COUNT(*) FROM signals GROUP BY priority"
            ).fetchall()
        return {r[0]: int(r[1]) for r in rows}

    def mark_processed(self, aggregation_key: str) -> int:
        """把该聚合组内所有未处理的信号标为已处理。返回被标记的行数。"""
        now = datetime.now(timezone.utc)
        with self._lock:
            n = self._con.execute(
                "SELECT COUNT(*) FROM signals "
                "WHERE aggregation_key = ? AND processed_at IS NULL",
                [aggregation_key],
            ).fetchone()[0]
            if n == 0:
                return 0
            self._con.execute(
                "UPDATE signals SET processed_at = ? "
                "WHERE aggregation_key = ? AND processed_at IS NULL",
                [now, aggregation_key],
            )
        return int(n)

    def clear(self) -> None:
        with self._lock:
            self._con.execute("DELETE FROM signals")

    def close(self) -> None:
        with self._lock:
            self._con.close()


_default_hub: Optional[SignalHub] = None


def get_hub() -> SignalHub:
    global _default_hub
    if _default_hub is None:
        _default_hub = SignalHub()
    return _default_hub
