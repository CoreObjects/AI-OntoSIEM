"""组件 5 知识图谱层：NetworkX 封装 + 实体合并 + 元字段维护。

设计约束（需求文档 §4.5 + ontology v1.0）：
  - User 节点只能来自 CMDB/IAM（硬约束）
  - owns 边只能声明来源（硬约束，LLM 不得创建）
  - 每个节点/边必带 meta：first_seen / last_seen / confidence / source / ontology_version
  - 同一主键的节点重复添加 → 合并而非重复
  - 关系时效性按类型分档（time_decay.py 处理）
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

import networkx as nx

from graph.time_decay import decay_for_edge, is_edge_valid

logger = logging.getLogger(__name__)


# =========================================================
# 硬约束
# =========================================================

USER_ALLOWED_SOURCES = {"cmdb", "iam", "manual"}
OWNS_ALLOWED_SOURCES = {"cmdb", "iam", "declared", "manual"}


class HardConstraintViolation(Exception):
    """违反本体硬约束（需求 §4.2/§4.5）。"""


# =========================================================
# GraphStore
# =========================================================

class GraphStore:
    """NetworkX MultiDiGraph 封装 + 消歧。

    NetworkX 节点键：`{node_type}:{node_id}`（避免不同类型同 id 碰撞）。
    """

    def __init__(self, ontology_version: str = "1.0") -> None:
        self._g: nx.MultiDiGraph = nx.MultiDiGraph()
        self._ontology_version = ontology_version

    @property
    def ontology_version(self) -> str:
        return self._ontology_version

    # -------- 本体变更订阅（核心差异点：变更横切全系统）--------

    def subscribe_to_ontology(self, ontology_service, backfill_fn=None) -> None:
        """订阅 OntologyService 变更。

        当本体版本升级时：
          1) 更新 store 内部 ontology_version（后续 upsert 会记录新版本）
          2) 若新本体引入新节点/边类型，调用 backfill_fn(new_nodes, new_edges, store)
             让上层（阶段 3 的演化闭环）把异常池事件回填进图。
        """
        def _on_upgrade(old, new) -> None:
            old_nodes = set(getattr(old, "nodes", {}) or {}) if old else set()
            old_edges = set(getattr(old, "edges", {}) or {}) if old else set()
            new_nodes = set(getattr(new, "nodes", {}) or {})
            new_edges = set(getattr(new, "edges", {}) or {})
            self._ontology_version = getattr(new, "version", self._ontology_version)
            diff_nodes = new_nodes - old_nodes
            diff_edges = new_edges - old_edges
            if backfill_fn is not None and (diff_nodes or diff_edges):
                try:
                    backfill_fn(diff_nodes, diff_edges, self)
                except Exception:
                    logger.exception("backfill_fn raised during ontology upgrade")

        ontology_service.subscribe(_on_upgrade)

    # -------- 基础统计 --------

    def node_count(self) -> int:
        return self._g.number_of_nodes()

    def edge_count(self) -> int:
        return self._g.number_of_edges()

    # -------- 节点增删查 --------

    def upsert_entity(
        self,
        node_type: str,
        node_id: str,
        attrs: Optional[Dict[str, Any]] = None,
        *,
        timestamp: str,
        source: str,
        confidence: float = 1.0,
    ) -> str:
        """新增或合并实体。返回 NetworkX 节点键。"""
        self._check_node_source(node_type, source)

        key = self._node_key(node_type, node_id)
        attrs = dict(attrs or {})

        if key in self._g:
            existing = self._g.nodes[key]
            merged_attrs = dict(existing["attrs"])
            merged_attrs.update({k: v for k, v in attrs.items() if v is not None})
            meta = dict(existing["meta"])
            meta["first_seen"] = min(meta["first_seen"], timestamp)
            meta["last_seen"] = max(meta["last_seen"], timestamp)
            meta["confidence"] = max(meta["confidence"], confidence)
            meta["ontology_version"] = self._ontology_version
            self._g.nodes[key]["attrs"] = merged_attrs
            self._g.nodes[key]["meta"] = meta
        else:
            self._g.add_node(
                key,
                node_type=node_type,
                node_id=node_id,
                attrs=attrs,
                meta={
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                    "confidence": confidence,
                    "source": source,
                    "ontology_version": self._ontology_version,
                },
            )
        return key

    def get_node(self, node_type: str, node_id: str) -> Dict[str, Any]:
        key = self._node_key(node_type, node_id)
        if key not in self._g:
            raise KeyError(f"node not found: {key}")
        return dict(self._g.nodes[key])

    def has_node(self, node_type: str, node_id: str) -> bool:
        return self._node_key(node_type, node_id) in self._g

    # -------- 边增删查 --------

    def upsert_relation(
        self,
        edge_type: str,
        from_type: str, from_id: str,
        to_type: str, to_id: str,
        *,
        timestamp: str,
        source: str,
        confidence: float = 1.0,
        attrs: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._check_edge_source(edge_type, source)

        fkey = self._node_key(from_type, from_id)
        tkey = self._node_key(to_type, to_id)
        if fkey not in self._g or tkey not in self._g:
            raise KeyError(f"endpoint missing: {fkey} -> {tkey}")

        # 同 (from, to, edge_type) 的边视作同一关系，合并 meta
        for _, _, k, data in self._g.out_edges(fkey, keys=True, data=True):
            if data.get("edge_type") == edge_type and _ == fkey and k is not None:
                pass  # 遍历语义不直接给 (u,v) 匹配；改用 subgraph
        existing_key = self._find_edge(fkey, tkey, edge_type)
        if existing_key is not None:
            data = self._g.edges[fkey, tkey, existing_key]
            meta = dict(data["meta"])
            meta["first_seen"] = min(meta["first_seen"], timestamp)
            meta["last_seen"] = max(meta["last_seen"], timestamp)
            meta["confidence"] = max(meta["confidence"], confidence)
            meta["ontology_version"] = self._ontology_version
            if attrs:
                merged = dict(data["attrs"])
                merged.update({k: v for k, v in attrs.items() if v is not None})
                data["attrs"] = merged
            data["meta"] = meta
        else:
            self._g.add_edge(
                fkey, tkey,
                key=f"{edge_type}::{fkey}->{tkey}",
                edge_type=edge_type,
                attrs=dict(attrs or {}),
                meta={
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                    "confidence": confidence,
                    "source": source,
                    "ontology_version": self._ontology_version,
                },
            )

    # -------- 查询 API --------

    def list_nodes_by_type(self, node_type: str) -> list:
        out = []
        for key, data in self._g.nodes(data=True):
            if data.get("node_type") == node_type:
                out.append(self._node_view(key, data))
        return out

    def out_edges(self, from_type: str, from_id: str, *, valid_at: Optional[datetime] = None) -> list:
        fkey = self._node_key(from_type, from_id)
        if fkey not in self._g:
            return []
        out = []
        for _, tkey, data in self._g.out_edges(fkey, data=True):
            if valid_at is not None and not self._edge_valid(data, valid_at):
                continue
            out.append(self._edge_view(fkey, tkey, data))
        return out

    def in_edges(self, to_type: str, to_id: str, *, valid_at: Optional[datetime] = None) -> list:
        tkey = self._node_key(to_type, to_id)
        if tkey not in self._g:
            return []
        out = []
        for fkey, _, data in self._g.in_edges(tkey, data=True):
            if valid_at is not None and not self._edge_valid(data, valid_at):
                continue
            out.append(self._edge_view(fkey, tkey, data))
        return out

    @staticmethod
    def _edge_valid(data: Dict[str, Any], now: datetime) -> bool:
        spec = decay_for_edge(data.get("edge_type"))
        return is_edge_valid(data.get("meta") or {}, spec, now)

    def subgraph_around(
        self,
        node_type: str,
        node_id: str,
        depth: int = 1,
    ) -> Dict[str, Any]:
        """以 (node_type, node_id) 为中心返回 N 跳无向子图。

        返回 {"nodes": [...], "edges": [...]} 字典形式，便于 LLM 序列化。
        """
        center = self._node_key(node_type, node_id)
        if center not in self._g:
            return {"nodes": [], "edges": []}

        visited = {center}
        frontier = {center}
        for _ in range(max(0, depth)):
            next_frontier = set()
            for key in frontier:
                for nb in self._g.successors(key):
                    if nb not in visited:
                        next_frontier.add(nb)
                for nb in self._g.predecessors(key):
                    if nb not in visited:
                        next_frontier.add(nb)
            visited |= next_frontier
            frontier = next_frontier

        nodes = [self._node_view(k, self._g.nodes[k]) for k in visited]
        edges = []
        for u in visited:
            for _, v, data in self._g.out_edges(u, data=True):
                if v in visited:
                    edges.append(self._edge_view(u, v, data))
        return {"nodes": nodes, "edges": edges}

    @staticmethod
    def _node_view(key: str, data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "key": key,
            "node_type": data.get("node_type"),
            "node_id": data.get("node_id"),
            "attrs": dict(data.get("attrs") or {}),
            "meta": dict(data.get("meta") or {}),
        }

    @staticmethod
    def _edge_view(fkey: str, tkey: str, data: Dict[str, Any]) -> Dict[str, Any]:
        from_type, from_id = fkey.split(":", 1)
        to_type, to_id = tkey.split(":", 1)
        return {
            "edge_type": data.get("edge_type"),
            "from_type": from_type, "from_id": from_id,
            "to_type": to_type, "to_id": to_id,
            "attrs": dict(data.get("attrs") or {}),
            "meta": dict(data.get("meta") or {}),
        }

    # -------- 内部 --------

    @staticmethod
    def _node_key(node_type: str, node_id: str) -> str:
        return f"{node_type}:{node_id}"

    def _find_edge(self, fkey: str, tkey: str, edge_type: str) -> Optional[str]:
        if not self._g.has_edge(fkey, tkey):
            return None
        for k, data in self._g[fkey][tkey].items():
            if data.get("edge_type") == edge_type:
                return k
        return None

    @staticmethod
    def _check_node_source(node_type: str, source: str) -> None:
        if node_type == "User" and source not in USER_ALLOWED_SOURCES:
            raise HardConstraintViolation(
                f"User node must come from CMDB/IAM, got source={source!r}"
            )

    @staticmethod
    def _check_edge_source(edge_type: str, source: str) -> None:
        if edge_type == "owns" and source not in OWNS_ALLOWED_SOURCES:
            raise HardConstraintViolation(
                f"owns edge must be declared (cmdb/iam), got source={source!r}"
            )
