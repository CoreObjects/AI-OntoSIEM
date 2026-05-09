"""组件 10 Day 2：候选 parser 存储（DuckDB）。

状态机：pending → approved（写 YAML）/ rejected（入审核反面记录）

与 ProposalStore 同一约定：主键幂等 INSERT、JSON 列 round-trip、close 释放连接。
"""
from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import duckdb

from evolution.parser_generator import CandidateParser

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = ROOT / "data" / "candidate_parsers.duckdb"


class CandidateParserStore:
    def __init__(self, db_path: Path = DEFAULT_DB) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._con = duckdb.connect(str(self._db_path))
        self._con.execute("""
            CREATE TABLE IF NOT EXISTS candidate_parsers (
                candidate_id                    VARCHAR PRIMARY KEY,
                triggered_by_ontology_version   VARCHAR,
                triggered_by_proposal_id        VARCHAR,
                target_node_type                VARCHAR,
                source_events                   JSON,
                rules                           JSON,
                sample_count                    INTEGER,
                confidence                      DOUBLE,
                explanation                     VARCHAR,
                stripped_relations              JSON,
                status                          VARCHAR,
                yaml_path                       VARCHAR,
                rejection_reason                VARCHAR,
                created_at                      VARCHAR,
                updated_at                      TIMESTAMP
            )
        """)

    # -------- 写入 --------

    def insert(self, c: CandidateParser) -> None:
        with self._lock:
            self._con.execute(
                "INSERT INTO candidate_parsers ("
                "candidate_id, triggered_by_ontology_version, triggered_by_proposal_id, "
                "target_node_type, source_events, rules, sample_count, confidence, "
                "explanation, stripped_relations, status, yaml_path, rejection_reason, "
                "created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT DO NOTHING",
                self._to_row(c),
            )

    def insert_many(self, items: Iterable[CandidateParser]) -> None:
        rows = [self._to_row(c) for c in items]
        if not rows:
            return
        with self._lock:
            self._con.executemany(
                "INSERT INTO candidate_parsers ("
                "candidate_id, triggered_by_ontology_version, triggered_by_proposal_id, "
                "target_node_type, source_events, rules, sample_count, confidence, "
                "explanation, stripped_relations, status, yaml_path, rejection_reason, "
                "created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT DO NOTHING",
                rows,
            )

    # -------- 状态更新 --------

    def mark_approved(self, candidate_id: str, *, yaml_path: str) -> bool:
        with self._lock:
            if not self._exists(candidate_id):
                return False
            self._con.execute(
                "UPDATE candidate_parsers SET status = 'approved', yaml_path = ?, "
                "updated_at = ? WHERE candidate_id = ?",
                [yaml_path, datetime.now(timezone.utc), candidate_id],
            )
        return True

    def mark_rejected(self, candidate_id: str, *, reason: str) -> bool:
        with self._lock:
            if not self._exists(candidate_id):
                return False
            self._con.execute(
                "UPDATE candidate_parsers SET status = 'rejected', "
                "rejection_reason = ?, updated_at = ? WHERE candidate_id = ?",
                [reason, datetime.now(timezone.utc), candidate_id],
            )
        return True

    def _exists(self, candidate_id: str) -> bool:
        n = self._con.execute(
            "SELECT COUNT(*) FROM candidate_parsers WHERE candidate_id = ?",
            [candidate_id],
        ).fetchone()[0]
        return int(n) > 0

    # -------- 读取 --------

    def count(self) -> int:
        with self._lock:
            return int(self._con.execute(
                "SELECT COUNT(*) FROM candidate_parsers"
            ).fetchone()[0])

    def count_by_status(self) -> Dict[str, int]:
        with self._lock:
            rows = self._con.execute(
                "SELECT status, COUNT(*) FROM candidate_parsers GROUP BY status"
            ).fetchall()
        return {str(r[0]): int(r[1]) for r in rows}

    def get(self, candidate_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            rows = self._con.execute(
                self._SELECT_COLS + " WHERE candidate_id = ?",
                [candidate_id],
            ).fetchall()
        if not rows:
            return None
        return self._row_to_dict(rows[0])

    def list_by_status(self, status: str, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._con.execute(
                self._SELECT_COLS + " WHERE status = ? ORDER BY created_at DESC LIMIT ?",
                [status, limit],
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def list_by_proposal(self, proposal_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._con.execute(
                self._SELECT_COLS + " WHERE triggered_by_proposal_id = ? "
                "ORDER BY created_at DESC LIMIT ?",
                [proposal_id, limit],
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def as_candidate(self, candidate_id: str) -> Optional[CandidateParser]:
        d = self.get(candidate_id)
        if d is None:
            return None
        return CandidateParser(
            candidate_id=d["candidate_id"],
            triggered_by_ontology_version=d["triggered_by_ontology_version"] or "1.0",
            triggered_by_proposal_id=d["triggered_by_proposal_id"] or "",
            target_node_type=d["target_node_type"] or "",
            source_events=d["source_events"] or [],
            rules=d["rules"] or [],
            sample_count=int(d["sample_count"] or 0),
            confidence=float(d["confidence"] or 0.0),
            explanation=d["explanation"] or "",
            stripped_relations=d["stripped_relations"] or [],
            status=d["status"] or "pending",
            created_at=d["created_at"] or "",
        )

    def close(self) -> None:
        with self._lock:
            self._con.close()

    # -------- 内部 --------

    _SELECT_COLS = (
        "SELECT candidate_id, triggered_by_ontology_version, triggered_by_proposal_id, "
        "target_node_type, source_events, rules, sample_count, confidence, "
        "explanation, stripped_relations, status, yaml_path, rejection_reason, "
        "created_at FROM candidate_parsers"
    )

    @staticmethod
    def _to_row(c: CandidateParser) -> tuple:
        return (
            c.candidate_id,
            c.triggered_by_ontology_version,
            c.triggered_by_proposal_id,
            c.target_node_type,
            json.dumps(c.source_events, ensure_ascii=False),
            json.dumps(c.rules, ensure_ascii=False),
            int(c.sample_count),
            float(c.confidence),
            c.explanation,
            json.dumps(c.stripped_relations, ensure_ascii=False),
            c.status,
            None,            # yaml_path（落库前为空）
            None,            # rejection_reason
            c.created_at,
            datetime.now(timezone.utc),
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
            "candidate_id": r[0],
            "triggered_by_ontology_version": r[1],
            "triggered_by_proposal_id": r[2],
            "target_node_type": r[3],
            "source_events": _l(r[4]),
            "rules": _l(r[5]),
            "sample_count": int(r[6] or 0),
            "confidence": float(r[7] or 0.0),
            "explanation": r[8],
            "stripped_relations": _l(r[9]),
            "status": r[10],
            "yaml_path": r[11],
            "rejection_reason": r[12],
            "created_at": r[13],
        }
