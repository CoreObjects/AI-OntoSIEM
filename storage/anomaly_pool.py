"""异常事件池。

解析失败（本体覆盖不到）但不丢弃的日志缓冲区。
等待本体升级 + Parser 自动生成后回放。

需求文档 §4.3：
  - 遇到无法映射的事件：完整保留原始 JSON + 失败原因 + 时间戳
  - 本体升级后重跑，成功的事件追溯入图谱（标 backfilled = true）
"""
from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import duckdb

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = ROOT / "data" / "anomaly_pool.duckdb"


@dataclass
class AnomalyRecord:
    record_id: int  # 对应 events.record_number
    event_id: int
    computer: str
    timestamp: str
    failure_reason: str
    raw_event: Dict[str, Any]
    ontology_version: str
    added_at: str
    backfilled: bool = False
    backfilled_at: Optional[str] = None
    backfilled_ontology_version: Optional[str] = None


class AnomalyPool:
    def __init__(self, db_path: Path = DEFAULT_DB) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._con = duckdb.connect(str(self._db_path))
        self._con.execute("""
            CREATE TABLE IF NOT EXISTS anomaly_pool (
                record_id                   BIGINT PRIMARY KEY,
                event_id                    INTEGER,
                computer                    VARCHAR,
                timestamp                   TIMESTAMP,
                failure_reason              VARCHAR,
                raw_event                   JSON,
                ontology_version            VARCHAR,
                added_at                    TIMESTAMP,
                backfilled                  BOOLEAN,
                backfilled_at               TIMESTAMP,
                backfilled_ontology_version VARCHAR
            )
        """)

    def add(
        self,
        record_id: int,
        event_id: int,
        computer: str,
        timestamp: Any,
        failure_reason: str,
        raw_event: Dict[str, Any],
        ontology_version: str,
    ) -> None:
        with self._lock:
            self._con.execute(
                "INSERT OR REPLACE INTO anomaly_pool VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    record_id,
                    event_id,
                    computer,
                    timestamp,
                    failure_reason,
                    json.dumps(raw_event, ensure_ascii=False, default=str),
                    ontology_version,
                    datetime.now(timezone.utc),
                    False,
                    None,
                    None,
                ],
            )

    def mark_backfilled(self, record_id: int, new_ontology_version: str) -> None:
        with self._lock:
            self._con.execute(
                "UPDATE anomaly_pool SET backfilled = TRUE, backfilled_at = ?, backfilled_ontology_version = ? "
                "WHERE record_id = ?",
                [datetime.now(timezone.utc), new_ontology_version, record_id],
            )

    def size_open(self) -> int:
        """尚未回填的异常记录数（Demo 看板核心指标）。"""
        with self._lock:
            return self._con.execute(
                "SELECT COUNT(*) FROM anomaly_pool WHERE backfilled = FALSE"
            ).fetchone()[0]

    def size_total(self) -> int:
        with self._lock:
            return self._con.execute("SELECT COUNT(*) FROM anomaly_pool").fetchone()[0]

    def list_by_event_id(self, event_id: int, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._con.execute(
                "SELECT record_id, event_id, computer, timestamp, failure_reason, raw_event "
                "FROM anomaly_pool WHERE event_id = ? AND backfilled = FALSE LIMIT ?",
                [event_id, limit],
            ).fetchall()
        return [_row_to_dict(r) for r in rows]

    def list_open(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._con.execute(
                "SELECT record_id, event_id, computer, timestamp, failure_reason, raw_event "
                "FROM anomaly_pool WHERE backfilled = FALSE ORDER BY timestamp DESC LIMIT ?",
                [limit],
            ).fetchall()
        return [_row_to_dict(r) for r in rows]

    def count_by_event_id(self) -> Dict[int, int]:
        with self._lock:
            rows = self._con.execute(
                "SELECT event_id, COUNT(*) FROM anomaly_pool WHERE backfilled = FALSE GROUP BY event_id"
            ).fetchall()
        return {r[0]: r[1] for r in rows}

    def clear(self) -> None:
        with self._lock:
            self._con.execute("DELETE FROM anomaly_pool")

    def close(self) -> None:
        with self._lock:
            self._con.close()


def _row_to_dict(r: tuple) -> Dict[str, Any]:
    raw = r[5]
    return {
        "record_id": r[0],
        "event_id": r[1],
        "computer": r[2],
        "timestamp": str(r[3]),
        "failure_reason": r[4],
        "raw_event": json.loads(raw) if isinstance(raw, str) else raw,
    }
