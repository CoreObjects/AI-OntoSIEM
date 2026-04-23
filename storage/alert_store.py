"""告警存储（组件 4 的持久化后端）。

设计：
  - DuckDB 单文件（与 anomaly_pool / signals 同一套存储约定）
  - alert_id 为主键，重复插入幂等（ON CONFLICT DO NOTHING）
  - 支持按 ATT&CK 技术聚合统计（评测看板用）
"""
from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List

import duckdb

from detection.engine import Alert

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = ROOT / "data" / "alerts.duckdb"


class AlertStore:
    def __init__(self, db_path: Path = DEFAULT_DB) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._con = duckdb.connect(str(self._db_path))
        self._con.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id           VARCHAR PRIMARY KEY,
                rule_id            VARCHAR,
                rule_title         VARCHAR,
                severity           VARCHAR,
                event_record_id    BIGINT,
                event_id           INTEGER,
                channel            VARCHAR,
                computer           VARCHAR,
                timestamp          VARCHAR,
                attack_techniques  JSON,
                matched_fields     JSON,
                ontology_version   VARCHAR,
                raw_event          JSON,
                created_at         TIMESTAMP
            )
        """)

    # -------- 写入 --------

    def insert(self, alert: Alert) -> None:
        with self._lock:
            self._con.execute(
                "INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
                self._to_row(alert),
            )

    def insert_many(self, alerts: Iterable[Alert]) -> None:
        rows = [self._to_row(a) for a in alerts]
        if not rows:
            return
        with self._lock:
            self._con.executemany(
                "INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
                rows,
            )

    # -------- 读取 --------

    def count(self) -> int:
        with self._lock:
            return int(self._con.execute("SELECT COUNT(*) FROM alerts").fetchone()[0])

    def list_recent(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._con.execute(
                "SELECT alert_id, rule_id, rule_title, severity, event_record_id, event_id, "
                "channel, computer, timestamp, attack_techniques, matched_fields, "
                "ontology_version, raw_event, created_at "
                "FROM alerts ORDER BY created_at DESC LIMIT ?",
                [limit],
            ).fetchall()
        return [
            {
                "alert_id": r[0],
                "rule_id": r[1],
                "rule_title": r[2],
                "severity": r[3],
                "event_record_id": r[4],
                "event_id": r[5],
                "channel": r[6],
                "computer": r[7],
                "timestamp": r[8],
                "attack_techniques": _loads(r[9]),
                "matched_fields": _loads(r[10]),
                "ontology_version": r[11],
                "raw_event": _loads(r[12]),
                "created_at": str(r[13]),
            }
            for r in rows
        ]

    def count_by_technique(self) -> Dict[str, int]:
        """展开 attack_techniques 数组，按技术聚合计数。"""
        with self._lock:
            rows = self._con.execute("SELECT attack_techniques FROM alerts").fetchall()
        counts: Dict[str, int] = {}
        for r in rows:
            techs = _loads(r[0]) or []
            for t in techs:
                counts[str(t)] = counts.get(str(t), 0) + 1
        return counts

    def clear(self) -> None:
        with self._lock:
            self._con.execute("DELETE FROM alerts")

    def close(self) -> None:
        with self._lock:
            self._con.close()

    # -------- 内部 --------

    @staticmethod
    def _to_row(alert: Alert) -> tuple:
        return (
            alert.alert_id,
            alert.rule_id,
            alert.rule_title,
            alert.severity,
            alert.event_record_id,
            alert.event_id,
            alert.channel,
            alert.computer,
            alert.timestamp,
            json.dumps(alert.attack_techniques, ensure_ascii=False),
            json.dumps(alert.matched_fields, ensure_ascii=False, default=str),
            alert.ontology_version,
            json.dumps(alert.raw_event, ensure_ascii=False, default=str),
            datetime.now(timezone.utc).isoformat(),
        )


def _loads(v: Any) -> Any:
    if v is None:
        return None
    if isinstance(v, str):
        try:
            return json.loads(v)
        except json.JSONDecodeError:
            return v
    return v
