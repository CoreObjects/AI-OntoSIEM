"""组件 9 审核四级决策动作（UI 与 store/upgrader 的胶水层）。

动作：
  approve_and_upgrade(store, pid, upgrader, **hints) → Path  产出新 YAML
  reject(store, pid, reason)                                拒绝入反面样本库
  defer(store, pid, max_cycles=2)                            延后（超限强制 reject）
  modify_and_upgrade(store, pid, upgrader, new_name, new_definition, **hints)

还提供：
  backlog_status(store) → {"pending":int, "level":str, "pause_new_proposals":bool}
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Optional

from evolution.proposer import Proposal

logger = logging.getLogger(__name__)

_BACKLOG_WARN = 10
_BACKLOG_RED = 20


# =========================================================
# 内部工具
# =========================================================

def _load_or_raise(store, proposal_id: str) -> Proposal:
    p = store.as_proposal(proposal_id)
    if p is None:
        raise KeyError(f"no such proposal: {proposal_id!r}")
    return p


# =========================================================
# 动作 · approved
# =========================================================

def approve_and_upgrade(
    store,
    proposal_id: str,
    upgrader,
    *,
    edge_endpoints: Optional[Dict[str, str]] = None,
    attr_target_node: Optional[str] = None,
) -> Path:
    p = _load_or_raise(store, proposal_id)
    p.status = "approved"
    new_path = upgrader.apply(
        p,
        edge_endpoints=edge_endpoints,
        attr_target_node=attr_target_node,
    )
    store.mark_approved(proposal_id)
    logger.info("proposal %s approved → ontology %s", proposal_id, new_path.name)
    return new_path


# =========================================================
# 动作 · reject
# =========================================================

def reject(store, proposal_id: str, *, reason: str) -> None:
    # 存在性检查
    _load_or_raise(store, proposal_id)
    store.mark_rejected(proposal_id, reason=reason)
    logger.info("proposal %s rejected: %s", proposal_id, reason)


# =========================================================
# 动作 · defer（超周期强制 reject）
# =========================================================

def defer(
    store,
    proposal_id: str,
    *,
    max_cycles: int = 2,
) -> Dict[str, Any]:
    current = store.get(proposal_id)
    if current is None:
        raise KeyError(f"no such proposal: {proposal_id!r}")

    cur_count = int(current.get("defer_count") or 0)
    if cur_count >= max_cycles:
        # 已延后到上限，强制 reject
        store.mark_rejected(
            proposal_id,
            reason=f"deferred over limit ({max_cycles} cycles)",
        )
        return {"status": "rejected", "defer_count": cur_count}

    new_count = store.increment_defer(proposal_id)
    return {"status": "deferred", "defer_count": int(new_count or 0)}


# =========================================================
# 动作 · modify + upgrade
# =========================================================

def modify_and_upgrade(
    store,
    proposal_id: str,
    upgrader,
    *,
    new_name: str,
    new_definition: str,
    edge_endpoints: Optional[Dict[str, str]] = None,
    attr_target_node: Optional[str] = None,
) -> Path:
    p = _load_or_raise(store, proposal_id)
    # 更新字段
    p.name = new_name
    p.semantic_definition = new_definition
    p.status = "approved"
    new_path = upgrader.apply(
        p,
        edge_endpoints=edge_endpoints,
        attr_target_node=attr_target_node,
    )
    store.mark_modified(proposal_id, new_name=new_name, new_definition=new_definition)
    logger.info("proposal %s modified and approved → %s (name=%s)",
                proposal_id, new_path.name, new_name)
    return new_path


# =========================================================
# 积压告警
# =========================================================

def backlog_status(store) -> Dict[str, Any]:
    counts = store.count_by_status()
    pending = int(counts.get("pending", 0))
    if pending > _BACKLOG_RED:
        level = "red"
    elif pending > _BACKLOG_WARN:
        level = "yellow"
    else:
        level = "green"
    return {
        "pending": pending,
        "level": level,
        "pause_new_proposals": level == "red",
    }
