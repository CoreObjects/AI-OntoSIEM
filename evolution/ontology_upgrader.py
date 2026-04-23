"""组件 9 核心：approved Proposal → 新本体 YAML + 版本 +0.1 + 订阅回调。

职责：
  - 读当前 ontology YAML（通常是最新版）
  - 按 proposal_type 插入新元素（node / edge / attr）
  - 保留元字段规约 + attack_anchors 合并
  - 写入 v{bumped}.yaml；不覆盖老版本（演化史可回溯）
  - 可选：触发 OntologyService.reload() → 广播订阅者（parser / graph）

严格约束：
  - 只接受 status == 'approved' 的 Proposal
  - 不允许与现有元素同名
  - attr 类型必须指定 target node
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

logger = logging.getLogger(__name__)

_STANDARD_META_ATTRS = [
    "first_seen", "last_seen", "confidence", "source", "ontology_version"
]
_VERSION_RE = re.compile(r"^(\d+)\.(\d+)$")


class UpgradeViolation(RuntimeError):
    """违反本体升级约束（proposal 未通过审核 / 重复 / 目标缺失 / 格式错）。"""


# =========================================================
# 工具
# =========================================================

def bump_version(v: str) -> str:
    """v1.0 → v1.1；v1.9 → v1.10。"""
    m = _VERSION_RE.match(v.strip().lstrip("v"))
    if not m:
        raise ValueError(f"invalid version: {v!r}")
    major, minor = int(m.group(1)), int(m.group(2))
    return f"{major}.{minor + 1}"


def _latest_yaml(dir_: Path) -> Path:
    candidates = list(dir_.glob("v*.yaml"))
    if not candidates:
        raise FileNotFoundError(f"no v*.yaml in {dir_}")

    def _key(p: Path):
        m = re.match(r"^v(\d+)\.(\d+)\.yaml$", p.name)
        return (int(m.group(1)), int(m.group(2))) if m else (0, 0)

    return max(candidates, key=_key)


# =========================================================
# OntologyUpgrader
# =========================================================

class OntologyUpgrader:
    def __init__(self, ontology_dir: Path, service=None) -> None:
        self._dir = Path(ontology_dir)
        self._service = service

    # -------- Public API --------

    def apply(
        self,
        proposal,
        *,
        edge_endpoints: Optional[Dict[str, str]] = None,
        attr_target_node: Optional[str] = None,
    ) -> Path:
        if proposal.status != "approved":
            raise UpgradeViolation(
                f"only approved proposals can upgrade ontology; got status={proposal.status!r}"
            )

        latest_path = _latest_yaml(self._dir)
        with latest_path.open("r", encoding="utf-8") as f:
            doc: Dict[str, Any] = yaml.safe_load(f) or {}

        new_version = bump_version(str(doc.get("version", "1.0")))

        if proposal.proposal_type == "node":
            self._add_node(doc, proposal)
        elif proposal.proposal_type == "edge":
            if not edge_endpoints or "from" not in edge_endpoints or "to" not in edge_endpoints:
                raise UpgradeViolation(
                    "edge proposal requires edge_endpoints={'from':..., 'to':...}"
                )
            self._add_edge(doc, proposal, edge_endpoints)
        elif proposal.proposal_type == "attr":
            if not attr_target_node:
                raise UpgradeViolation(
                    "attr proposal requires attr_target_node"
                )
            self._add_attr(doc, proposal, attr_target_node)
        else:
            raise UpgradeViolation(
                f"unknown proposal_type: {proposal.proposal_type!r}"
            )

        # 合并 attack_mapping → attack_anchors（去重）
        self._merge_attack_anchors(doc, proposal)

        # 版本元数据
        doc["version"] = new_version
        doc["created_by"] = f"ontology_upgrader (proposal {proposal.proposal_id[:8]})"
        history = doc.setdefault("evolution_history", [])
        history.append({
            "version": new_version,
            "base_version": proposal.ontology_base_version,
            "proposal_id": proposal.proposal_id,
            "proposal_type": proposal.proposal_type,
            "name": proposal.name,
            "applied_at": _now_iso(),
        })

        out_path = self._dir / f"v{new_version}.yaml"
        with out_path.open("w", encoding="utf-8") as f:
            yaml.safe_dump(doc, f, allow_unicode=True, sort_keys=False)

        logger.info("Ontology upgraded %s -> %s (proposal %s: %s %s)",
                    doc.get("created", ""), new_version,
                    proposal.proposal_id, proposal.proposal_type, proposal.name)

        # 触发订阅
        if self._service is not None:
            self._service.reload()
        return out_path

    # -------- 内部 --------

    def _add_node(self, doc: Dict[str, Any], p) -> None:
        nodes = doc.setdefault("nodes", {})
        edges = doc.get("edges") or {}
        if p.name in nodes or p.name in edges:
            raise UpgradeViolation(f"name collision: {p.name!r} already in ontology")
        nodes[p.name] = {
            "description": p.semantic_definition,
            "required_attrs": [],           # 演化生成的新节点先不强制必填
            "optional_attrs": [],
            "meta_attrs": list(_STANDARD_META_ATTRS),
            "notes": [
                f"added by proposal {p.proposal_id[:8]}",
                f"source_signals: {p.source_signals}",
                f"attack_mapping: {p.attack_mapping}",
            ],
        }

    def _add_edge(self, doc: Dict[str, Any], p, endpoints: Dict[str, str]) -> None:
        edges = doc.setdefault("edges", {})
        nodes = doc.get("nodes") or {}
        if p.name in edges or p.name in nodes:
            raise UpgradeViolation(f"name collision: {p.name!r} already in ontology")
        f_type, t_type = endpoints["from"], endpoints["to"]
        if f_type not in nodes:
            raise UpgradeViolation(f"edge 'from' type {f_type!r} not in ontology")
        # to 允许同次升级新增的节点；若都不在就拒
        if t_type not in nodes:
            raise UpgradeViolation(f"edge 'to' type {t_type!r} not in ontology")
        edges[p.name] = {
            "from": f_type,
            "to": t_type,
            "description": p.semantic_definition,
            "cardinality": "N:M",
            "time_decay": "none",
            "confidence_source": "logged",
            "meta_attrs": list(_STANDARD_META_ATTRS),
            "notes": [
                f"added by proposal {p.proposal_id[:8]}",
                f"attack_mapping: {p.attack_mapping}",
            ],
        }

    def _add_attr(self, doc: Dict[str, Any], p, target: str) -> None:
        nodes = doc.get("nodes") or {}
        if target not in nodes:
            raise UpgradeViolation(f"attr target node {target!r} not in ontology")
        node = nodes[target]
        opt = node.setdefault("optional_attrs", [])
        if p.name in opt:
            raise UpgradeViolation(
                f"attr {p.name!r} already on {target!r}"
            )
        # required_attrs 也要去重检查
        if p.name in (node.get("required_attrs") or []):
            raise UpgradeViolation(
                f"attr {p.name!r} already required on {target!r}"
            )
        opt.append(p.name)
        note = (
            f"attr {p.name} added by proposal {p.proposal_id[:8]} "
            f"(def: {p.semantic_definition})"
        )
        node.setdefault("notes", []).append(note)

    @staticmethod
    def _merge_attack_anchors(doc: Dict[str, Any], p) -> None:
        anchors = doc.setdefault("attack_anchors", [])
        existing = {a["id"] for a in anchors if isinstance(a, dict)}
        for tech in p.attack_mapping or []:
            if tech in existing:
                continue
            anchors.append({"id": tech, "name": f"(from proposal {p.proposal_id[:8]})"})
            existing.add(tech)


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
