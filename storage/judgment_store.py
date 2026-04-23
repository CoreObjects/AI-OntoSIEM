"""判决持久化（组件 6）— DuckDB。

与 alert_store 同一约定：主键幂等 + Python 端 JSON 聚合。
"""
from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List

import duckdb

from reasoning.judgment_engine import Judgment

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = ROOT / "data" / "judgments.duckdb"


class JudgmentStore:
    def __init__(self, db_path: Path = DEFAULT_DB) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._con = duckdb.connect(str(self._db_path))
        self._con.execute("""
            CREATE TABLE IF NOT EXISTS judgments (
                judgment_id       VARCHAR PRIMARY KEY,
                alert_id          VARCHAR,
                verdict           VARCHAR,
                confidence        DOUBLE,
                reasoning_steps   JSON,
                evidence_refs     JSON,
                attack_chain      JSON,
                next_steps        JSON,
                ontology_version  VARCHAR,
                semantic_gap      JSON,
                needs_review      BOOLEAN,
                created_at        VARCHAR,
                inserted_at       TIMESTAMP
            )
        """)

    # -------- 写入 --------

    def insert(self, j: Judgment) -> None:
        with self._lock:
            self._con.execute(
                "INSERT INTO judgments VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT DO NOTHING",
                self._to_row(j),
            )

    def insert_many(self, items: Iterable[Judgment]) -> None:
        rows = [self._to_row(j) for j in items]
        if not rows:
            return
        with self._lock:
            self._con.executemany(
                "INSERT INTO judgments VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT DO NOTHING",
                rows,
            )

    # -------- 读取 --------

    def count(self) -> int:
        with self._lock:
            return int(self._con.execute("SELECT COUNT(*) FROM judgments").fetchone()[0])

    def list_recent(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._con.execute(
                "SELECT judgment_id, alert_id, verdict, confidence, reasoning_steps, "
                "evidence_refs, attack_chain, next_steps, ontology_version, "
                "semantic_gap, needs_review, created_at "
                "FROM judgments ORDER BY inserted_at DESC LIMIT ?",
                [limit],
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def list_needs_review(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._con.execute(
                "SELECT judgment_id, alert_id, verdict, confidence, reasoning_steps, "
                "evidence_refs, attack_chain, next_steps, ontology_version, "
                "semantic_gap, needs_review, created_at "
                "FROM judgments WHERE needs_review = TRUE "
                "ORDER BY inserted_at DESC LIMIT ?",
                [limit],
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def count_by_verdict(self) -> Dict[str, int]:
        with self._lock:
            rows = self._con.execute(
                "SELECT verdict, COUNT(*) FROM judgments GROUP BY verdict"
            ).fetchall()
        return {str(r[0]): int(r[1]) for r in rows}

    def clear(self) -> None:
        with self._lock:
            self._con.execute("DELETE FROM judgments")

    def close(self) -> None:
        with self._lock:
            self._con.close()

    # -------- 内部 --------

    @staticmethod
    def _to_row(j: Judgment) -> tuple:
        return (
            j.judgment_id, j.alert_id, j.verdict, float(j.confidence),
            json.dumps(j.reasoning_steps, ensure_ascii=False),
            json.dumps(j.evidence_refs, ensure_ascii=False),
            json.dumps(j.attack_chain, ensure_ascii=False),
            json.dumps(j.next_steps, ensure_ascii=False),
            j.ontology_version,
            json.dumps(j.semantic_gap, ensure_ascii=False) if j.semantic_gap else None,
            bool(j.needs_review),
            j.created_at,
            datetime.now(timezone.utc).isoformat(),
        )

    @staticmethod
    def _row_to_dict(r: tuple) -> Dict[str, Any]:
        def _l(v):
            if v is None:
                return None
            if isinstance(v, str):
                try:
                    return json.loads(v)
                except json.JSONDecodeError:
                    return v
            return v

        return {
            "judgment_id": r[0],
            "alert_id": r[1],
            "verdict": r[2],
            "confidence": float(r[3]) if r[3] is not None else None,
            "reasoning_steps": _l(r[4]),
            "evidence_refs": _l(r[5]),
            "attack_chain": _l(r[6]),
            "next_steps": _l(r[7]),
            "ontology_version": r[8],
            "semantic_gap": _l(r[9]),
            "needs_review": bool(r[10]),
            "created_at": r[11],
        }
