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
from datetime import datetime, timezone
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
                ontology_version VARCHAR
            )
        """)

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
