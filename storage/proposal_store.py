"""组件 8 提议存储（DuckDB）。

与 alert_store / judgment_store 同一约定：
  - 主键（proposal_id）幂等 INSERT
  - 状态机：pending → approved / rejected / modified / deferred
  - rejection_names() 提供反面样本库查询（供 ProposalEngine 消费）
"""
from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import duckdb

from evolution.proposer import Proposal

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = ROOT / "data" / "proposals.duckdb"


class ProposalStore:
    def __init__(self, db_path: Path = DEFAULT_DB) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._con = duckdb.connect(str(self._db_path))
        self._con.execute("""
            CREATE TABLE IF NOT EXISTS proposals (
                proposal_id            VARCHAR PRIMARY KEY,
                proposal_type          VARCHAR,
                name                   VARCHAR,
                semantic_definition    VARCHAR,
                supporting_evidence    JSON,
                overlap_analysis       JSON,
                attack_mapping         JSON,
                source_signals         JSON,
                ontology_base_version  VARCHAR,
                status                 VARCHAR,
                rejection_reason       VARCHAR,
                created_at             VARCHAR,
                updated_at             TIMESTAMP,
                defer_count            INTEGER DEFAULT 0
            )
        """)
        # 向后兼容：老 DB 无 defer_count
        try:
            self._con.execute("ALTER TABLE proposals ADD COLUMN defer_count INTEGER DEFAULT 0")
        except duckdb.CatalogException:
            pass

    # -------- 写入 --------

    def insert(self, p: Proposal) -> None:
        with self._lock:
            self._con.execute(
                "INSERT INTO proposals (proposal_id, proposal_type, name, semantic_definition, "
                "supporting_evidence, overlap_analysis, attack_mapping, source_signals, "
                "ontology_base_version, status, rejection_reason, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT DO NOTHING",
                self._to_row(p),
            )

    def insert_many(self, items: Iterable[Proposal]) -> None:
        rows = [self._to_row(p) for p in items]
        if not rows:
            return
        with self._lock:
            self._con.executemany(
                "INSERT INTO proposals (proposal_id, proposal_type, name, semantic_definition, "
                "supporting_evidence, overlap_analysis, attack_mapping, source_signals, "
                "ontology_base_version, status, rejection_reason, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT DO NOTHING",
                rows,
            )

    # -------- 状态更新 --------

    def mark_approved(self, proposal_id: str) -> bool:
        return self._update_status(proposal_id, "approved")

    def mark_rejected(self, proposal_id: str, *, reason: str) -> bool:
        return self._update_status(proposal_id, "rejected", reason=reason)

    def mark_deferred(self, proposal_id: str) -> bool:
        return self._update_status(proposal_id, "deferred")

    def get(self, proposal_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            rows = self._con.execute(
                "SELECT proposal_id, proposal_type, name, semantic_definition, "
                "supporting_evidence, overlap_analysis, attack_mapping, source_signals, "
                "ontology_base_version, status, rejection_reason, created_at, "
                "COALESCE(defer_count, 0) "
                "FROM proposals WHERE proposal_id = ?",
                [proposal_id],
            ).fetchall()
        if not rows:
            return None
        d = self._row_to_dict(rows[0])
        d["defer_count"] = int(rows[0][12] or 0)
        return d

    def increment_defer(self, proposal_id: str) -> Optional[int]:
        """defer_count += 1，返回新值。unknown id 返回 None。"""
        with self._lock:
            if not self._exists(proposal_id):
                return None
            self._con.execute(
                "UPDATE proposals SET defer_count = COALESCE(defer_count, 0) + 1, "
                "status = 'deferred', updated_at = ? WHERE proposal_id = ?",
                [datetime.now(timezone.utc), proposal_id],
            )
            new_count = self._con.execute(
                "SELECT defer_count FROM proposals WHERE proposal_id = ?",
                [proposal_id],
            ).fetchone()[0]
        return int(new_count or 0)

    def as_proposal(self, proposal_id: str):
        """把一行重构成 Proposal 对象（给 upgrader 用）。"""
        from evolution.proposer import Proposal
        d = self.get(proposal_id)
        if d is None:
            return None
        return Proposal(
            proposal_id=d["proposal_id"],
            proposal_type=d["proposal_type"],
            name=d["name"],
            semantic_definition=d["semantic_definition"] or "",
            supporting_evidence=d["supporting_evidence"] or [],
            overlap_analysis=d["overlap_analysis"] or {},
            attack_mapping=d["attack_mapping"] or [],
            source_signals=d["source_signals"] or [],
            ontology_base_version=d["ontology_base_version"] or "1.0",
            status=d["status"] or "pending",
            rejection_reason=d.get("rejection_reason"),
            created_at=d.get("created_at") or "",
        )

    def mark_modified(
        self,
        proposal_id: str,
        *,
        new_name: Optional[str] = None,
        new_definition: Optional[str] = None,
    ) -> bool:
        with self._lock:
            if not self._exists(proposal_id):
                return False
            now = datetime.now(timezone.utc)
            updates = ["status = 'modified'", "updated_at = ?"]
            params: List[Any] = [now]
            if new_name is not None:
                updates.append("name = ?")
                params.append(new_name)
            if new_definition is not None:
                updates.append("semantic_definition = ?")
                params.append(new_definition)
            params.append(proposal_id)
            sql = f"UPDATE proposals SET {', '.join(updates)} WHERE proposal_id = ?"
            self._con.execute(sql, params)
        return True

    def _update_status(self, proposal_id: str, status: str,
                       *, reason: Optional[str] = None) -> bool:
        with self._lock:
            if not self._exists(proposal_id):
                return False
            now = datetime.now(timezone.utc)
            self._con.execute(
                "UPDATE proposals SET status = ?, rejection_reason = ?, updated_at = ? "
                "WHERE proposal_id = ?",
                [status, reason, now, proposal_id],
            )
        return True

    def _exists(self, proposal_id: str) -> bool:
        n = self._con.execute(
            "SELECT COUNT(*) FROM proposals WHERE proposal_id = ?", [proposal_id]
        ).fetchone()[0]
        return int(n) > 0

    # -------- 读取 --------

    def count(self) -> int:
        with self._lock:
            return int(self._con.execute("SELECT COUNT(*) FROM proposals").fetchone()[0])

    def count_by_status(self) -> Dict[str, int]:
        with self._lock:
            rows = self._con.execute(
                "SELECT status, COUNT(*) FROM proposals GROUP BY status"
            ).fetchall()
        return {str(r[0]): int(r[1]) for r in rows}

    def list_by_status(self, status: str, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._con.execute(
                "SELECT proposal_id, proposal_type, name, semantic_definition, "
                "supporting_evidence, overlap_analysis, attack_mapping, source_signals, "
                "ontology_base_version, status, rejection_reason, created_at "
                "FROM proposals WHERE status = ? ORDER BY created_at DESC LIMIT ?",
                [status, limit],
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def rejection_names(self) -> List[str]:
        """给 ProposalEngine 当反面样本库输入。"""
        with self._lock:
            rows = self._con.execute(
                "SELECT DISTINCT name FROM proposals WHERE status = 'rejected'"
            ).fetchall()
        return [r[0] for r in rows]

    def close(self) -> None:
        with self._lock:
            self._con.close()

    # -------- 内部 --------

    @staticmethod
    def _to_row(p: Proposal) -> tuple:
        return (
            p.proposal_id, p.proposal_type, p.name, p.semantic_definition,
            json.dumps(p.supporting_evidence, ensure_ascii=False, default=str),
            json.dumps(p.overlap_analysis, ensure_ascii=False),
            json.dumps(p.attack_mapping, ensure_ascii=False),
            json.dumps(p.source_signals, ensure_ascii=False),
            p.ontology_base_version, p.status, p.rejection_reason,
            p.created_at,
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
            "proposal_id": r[0],
            "proposal_type": r[1],
            "name": r[2],
            "semantic_definition": r[3],
            "supporting_evidence": _l(r[4]),
            "overlap_analysis": _l(r[5]),
            "attack_mapping": _l(r[6]),
            "source_signals": _l(r[7]),
            "ontology_base_version": r[8],
            "status": r[9],
            "rejection_reason": r[10],
            "created_at": r[11],
        }
