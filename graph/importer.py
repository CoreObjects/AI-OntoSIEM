"""从 parsed_events.duckdb 导入实体 + 关系到 GraphStore。

职责：
  - 读 entities / relations 两张表
  - 按 timestamp 升序灌入（保证 first_seen/last_seen 语义正确）
  - 关系端点缺失时跳过并计数，不 crash
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict

import duckdb

from graph.entity_resolver import resolve_account, resolve_host, resolve_process
from graph.store import GraphStore

logger = logging.getLogger(__name__)


def _canonicalize(node_type: str, node_id: str, attrs: Dict[str, Any]):
    """调 resolver 算 canonical_id / confidence。失败则回退到 parser 原值。"""
    try:
        if node_type == "Account":
            r = resolve_account(
                sid=attrs.get("sid"),
                domain=attrs.get("domain"),
                username=attrs.get("username"),
            )
            return r.canonical_id, r.confidence
        if node_type == "Host":
            r = resolve_host(attrs.get("hostname") or node_id)
            return r.canonical_id, r.confidence
        if node_type == "Process" and attrs.get("pid") and attrs.get("image_name"):
            host = attrs.get("host") or attrs.get("computer") or node_id.split(":", 1)[0]
            r = resolve_process(
                pid=str(attrs["pid"]),
                image_name=attrs["image_name"],
                start_time=attrs.get("start_time"),
                host=host,
            )
            return r.canonical_id, r.confidence
    except Exception:
        pass
    return node_id, 1.0


def _loads(v: Any) -> Dict[str, Any]:
    if v is None:
        return {}
    if isinstance(v, dict):
        return dict(v)
    if isinstance(v, str):
        try:
            return json.loads(v)
        except json.JSONDecodeError:
            return {}
    return {}


def _iso(ts: Any) -> str:
    if ts is None:
        return ""
    if hasattr(ts, "isoformat"):
        return ts.isoformat()
    return str(ts)


def import_parsed_db(db_path: Path, store: GraphStore) -> Dict[str, int]:
    """从 parsed_events.duckdb 导入到 store，返回统计。"""
    con = duckdb.connect(str(db_path), read_only=True)

    stats: Dict[str, int] = {
        "entities_read": 0,
        "entities_merged": 0,
        "entities_rejected": 0,
        "relations_read": 0,
        "relations_merged": 0,
        "relations_skipped": 0,
    }

    # (node_type, parser_node_id) → canonical_node_id，关系翻译用
    canon_map: Dict[tuple, str] = {}

    # ---- entities ----
    rows = con.execute(
        "SELECT node_type, node_id, attrs, meta, timestamp FROM entities ORDER BY timestamp"
    ).fetchall()
    for r in rows:
        stats["entities_read"] += 1
        node_type, parser_node_id = r[0], r[1]
        attrs = _loads(r[2])
        meta = _loads(r[3])
        ts = _iso(r[4])
        source = meta.get("source", "log")
        canonical_id, confidence = _canonicalize(node_type, parser_node_id, attrs)
        canon_map[(node_type, parser_node_id)] = canonical_id
        try:
            existed = store.has_node(node_type, canonical_id)
            store.upsert_entity(
                node_type=node_type, node_id=canonical_id,
                attrs=attrs,
                timestamp=ts, source=source, confidence=confidence,
            )
            if existed:
                stats["entities_merged"] += 1
        except Exception:
            logger.exception("Failed to import entity %s:%s", node_type, parser_node_id)
            stats["entities_rejected"] += 1

    # ---- relations ----
    rows = con.execute(
        "SELECT edge_type, from_type, from_id, to_type, to_id, attrs, timestamp "
        "FROM relations ORDER BY timestamp"
    ).fetchall()
    for r in rows:
        stats["relations_read"] += 1
        edge_type, from_type, from_id_p, to_type, to_id_p = r[0], r[1], r[2], r[3], r[4]
        from_id = canon_map.get((from_type, from_id_p), from_id_p)
        to_id = canon_map.get((to_type, to_id_p), to_id_p)
        attrs = _loads(r[5])
        ts = _iso(r[6])
        if not store.has_node(from_type, from_id) or not store.has_node(to_type, to_id):
            stats["relations_skipped"] += 1
            continue
        # 同 (from, to, edge_type) 已存在则视为合并
        existed_before = len([
            e for e in store.out_edges(from_type, from_id)
            if e["edge_type"] == edge_type
            and e["to_type"] == to_type and e["to_id"] == to_id
        ]) > 0
        try:
            store.upsert_relation(
                edge_type=edge_type,
                from_type=from_type, from_id=from_id,
                to_type=to_type, to_id=to_id,
                timestamp=ts,
                source=attrs.pop("_source", "log"),
                attrs=attrs,
            )
            if existed_before:
                stats["relations_merged"] += 1
        except Exception:
            logger.exception("Failed to import relation %s", edge_type)
            stats["relations_skipped"] += 1

    con.close()
    return stats
