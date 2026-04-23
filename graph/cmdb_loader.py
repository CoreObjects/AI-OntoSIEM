"""CMDB/IAM 声明源加载器。

本体 v1.0 硬约束：User 节点和 owns 边只能来自 CMDB/IAM，不从日志推断。
本模块是 User+owns 的唯一入口。

YAML 格式：
    source: "cmdb"
    declared_at: "2026-04-22T00:00:00Z"
    users:
      - user_id: "u1001"
        display_name: "Alice Chen"
        department: "Finance"
        email: "alice@corp.com"
        accounts:
          - sid: "S-1-5-21-..."
          - domain: "CORP"
            username: "alice_admin"   # 无 SID 时可用
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

import yaml

from graph.entity_resolver import resolve_account
from graph.store import GraphStore

logger = logging.getLogger(__name__)


def load_cmdb(path: Path, store: GraphStore) -> Dict[str, int]:
    with Path(path).open("r", encoding="utf-8") as f:
        doc = yaml.safe_load(f) or {}
    source = doc.get("source", "cmdb")
    declared_at = doc.get("declared_at") or datetime.now(timezone.utc).isoformat()

    stats = {"users_created": 0, "users_merged": 0,
             "owns_created": 0, "owns_merged": 0, "owns_skipped": 0}

    for u in doc.get("users") or []:
        user_id = str(u.get("user_id") or "")
        if not user_id:
            continue
        attrs = {
            "user_id": user_id,
            "display_name": u.get("display_name") or user_id,
        }
        for k in ("department", "email", "role", "manager"):
            if u.get(k):
                attrs[k] = u[k]

        existed = store.has_node("User", user_id)
        store.upsert_entity(
            "User", user_id, attrs=attrs,
            timestamp=declared_at, source=source,
        )
        stats["users_merged" if existed else "users_created"] += 1

        for acct in u.get("accounts") or []:
            sid = acct.get("sid")
            domain = acct.get("domain")
            username = acct.get("username")
            try:
                r = resolve_account(sid=sid, domain=domain, username=username)
            except ValueError:
                stats["owns_skipped"] += 1
                continue
            if not store.has_node("Account", r.canonical_id):
                # 图里没见过此 Account（日志里从没出现）→ 暂不建 owns 边
                # 降级理由：owns 必须指向真实可观测的 Account，避免悬空
                stats["owns_skipped"] += 1
                continue
            existed_edge = any(
                e["edge_type"] == "owns" and e["to_id"] == r.canonical_id
                for e in store.out_edges("User", user_id)
            )
            store.upsert_relation(
                edge_type="owns",
                from_type="User", from_id=user_id,
                to_type="Account", to_id=r.canonical_id,
                timestamp=declared_at, source=source,
            )
            stats["owns_merged" if existed_edge else "owns_created"] += 1

    return stats
