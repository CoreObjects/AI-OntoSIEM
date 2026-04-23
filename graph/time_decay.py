"""关系时效性规约解析与判定（需求 §4.5，本体 v1.0 time_decay 字段）。

支持的规约字符串：
  - "none"          永不失效
  - "<N>d"          绝对 TTL：first_seen + Nd 之后失效
  - "<N>d_sliding"  滑动窗口：last_seen + Nd 之后失效（有活动即续期）

默认：若本体未声明，按 "none"。
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional


@dataclass(frozen=True)
class DecaySpec:
    never_decays: bool
    window_days: Optional[int] = None
    sliding: bool = False


_RE_SLIDING = re.compile(r"^(\d+)d_sliding$")
_RE_ABSOLUTE = re.compile(r"^(\d+)d$")


def parse_decay_spec(spec: Optional[str]) -> DecaySpec:
    if spec is None or str(spec).lower() == "none":
        return DecaySpec(never_decays=True)
    s = str(spec).strip().lower()
    m = _RE_SLIDING.match(s)
    if m:
        return DecaySpec(never_decays=False, window_days=int(m.group(1)), sliding=True)
    m = _RE_ABSOLUTE.match(s)
    if m:
        return DecaySpec(never_decays=False, window_days=int(m.group(1)), sliding=False)
    raise ValueError(f"invalid time_decay spec: {spec!r}")


def _parse_ts(ts: str) -> datetime:
    """解析 ISO8601；支持 'Z' 后缀。"""
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts)


def is_edge_valid(meta: Dict, spec: DecaySpec, now: datetime) -> bool:
    if spec.never_decays:
        return True
    base_key = "last_seen" if spec.sliding else "first_seen"
    base = _parse_ts(meta[base_key])
    if base.tzinfo is None:
        base = base.replace(tzinfo=timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    expiry = base + timedelta(days=spec.window_days or 0)
    return now <= expiry


# =========================================================
# 默认规约映射（从 ontology/v1.0.yaml 的 time_decay 字段，写死以便启动无需本体）
# =========================================================

DEFAULT_EDGE_DECAY: Dict[str, str] = {
    "owns":             "none",
    "authenticated_as": "90d",
    "logged_into":      "30d_sliding",
    "spawned":          "none",
    "executed_on":      "none",
    "connected_to":     "7d",
}


def decay_for_edge(edge_type: str, ontology=None) -> DecaySpec:
    """优先从 ontology 取 time_decay；否则用默认映射。"""
    if ontology is not None:
        e = ontology.edges.get(edge_type)
        if e and "time_decay" in e:
            try:
                return parse_decay_spec(e["time_decay"])
            except ValueError:
                pass
    return parse_decay_spec(DEFAULT_EDGE_DECAY.get(edge_type, "none"))
