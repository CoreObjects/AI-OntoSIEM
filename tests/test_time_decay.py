"""关系时效性（需求 §4.5 + ontology v1.0）：
  owns              : none       (永久)
  authenticated_as  : 90d        (绝对 TTL，从 first_seen 起算)
  logged_into       : 30d_sliding (滑动窗口，从 last_seen 起算)
  spawned           : none
  executed_on       : none
  connected_to      : 7d
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


# =========================================================
# 解析 time_decay 规约
# =========================================================

def test_parse_decay_none() -> None:
    from graph.time_decay import parse_decay_spec
    d = parse_decay_spec("none")
    assert d.never_decays is True


def test_parse_decay_absolute_ttl_90d() -> None:
    from graph.time_decay import parse_decay_spec
    d = parse_decay_spec("90d")
    assert d.never_decays is False
    assert d.window_days == 90
    assert d.sliding is False


def test_parse_decay_sliding_30d() -> None:
    from graph.time_decay import parse_decay_spec
    d = parse_decay_spec("30d_sliding")
    assert d.window_days == 30
    assert d.sliding is True


# =========================================================
# 时效判定：is_edge_valid(meta, spec, now)
# =========================================================

def _meta(first_seen: datetime, last_seen: datetime) -> dict:
    return {
        "first_seen": _iso(first_seen),
        "last_seen": _iso(last_seen),
        "confidence": 1.0,
        "source": "log",
        "ontology_version": "1.0",
    }


def test_owns_never_decays() -> None:
    from graph.time_decay import is_edge_valid, parse_decay_spec
    spec = parse_decay_spec("none")
    first = datetime(2020, 1, 1, tzinfo=timezone.utc)
    meta = _meta(first, first)
    now = datetime(2030, 1, 1, tzinfo=timezone.utc)
    assert is_edge_valid(meta, spec, now) is True


def test_authenticated_as_valid_inside_90d() -> None:
    from graph.time_decay import is_edge_valid, parse_decay_spec
    spec = parse_decay_spec("90d")
    first = datetime(2026, 4, 1, tzinfo=timezone.utc)
    now = first + timedelta(days=60)
    assert is_edge_valid(_meta(first, first), spec, now) is True


def test_authenticated_as_expired_after_90d() -> None:
    from graph.time_decay import is_edge_valid, parse_decay_spec
    spec = parse_decay_spec("90d")
    first = datetime(2026, 4, 1, tzinfo=timezone.utc)
    now = first + timedelta(days=91)
    assert is_edge_valid(_meta(first, first), spec, now) is False


def test_logged_into_sliding_renewed_by_activity() -> None:
    """30d 滑动：如果 last_seen 在 now - 30d 之后，仍有效（即使 first_seen 是半年前）。"""
    from graph.time_decay import is_edge_valid, parse_decay_spec
    spec = parse_decay_spec("30d_sliding")
    first = datetime(2026, 1, 1, tzinfo=timezone.utc)
    last = datetime(2026, 4, 10, tzinfo=timezone.utc)
    now = datetime(2026, 4, 15, tzinfo=timezone.utc)
    assert is_edge_valid(_meta(first, last), spec, now) is True


def test_logged_into_sliding_expires_when_inactive() -> None:
    from graph.time_decay import is_edge_valid, parse_decay_spec
    spec = parse_decay_spec("30d_sliding")
    first = datetime(2026, 1, 1, tzinfo=timezone.utc)
    last = datetime(2026, 2, 1, tzinfo=timezone.utc)
    now = datetime(2026, 4, 15, tzinfo=timezone.utc)
    assert is_edge_valid(_meta(first, last), spec, now) is False


def test_connected_to_7d_expires_quickly() -> None:
    from graph.time_decay import is_edge_valid, parse_decay_spec
    spec = parse_decay_spec("7d")
    first = datetime(2026, 4, 1, tzinfo=timezone.utc)
    now = first + timedelta(days=8)
    assert is_edge_valid(_meta(first, first), spec, now) is False


# =========================================================
# 集成：GraphStore 出边过滤（valid_at）
# =========================================================

def test_out_edges_filters_by_valid_at() -> None:
    """out_edges 支持 valid_at 参数，按本体 time_decay 过滤过期边。"""
    from graph.store import GraphStore
    g = GraphStore(ontology_version="1.0")
    g.upsert_entity("Account", "S-1-5-21-1-2001", attrs={"sid": "S-1-5-21-1-2001"},
                    timestamp="2026-01-15T00:00:00Z", source="log")
    g.upsert_entity("Host", "FIN-SRV-01", attrs={"hostname": "FIN-SRV-01"},
                    timestamp="2026-01-15T00:00:00Z", source="log")
    # 上一次登录 2 月 1 日
    g.upsert_relation("logged_into",
                      "Account", "S-1-5-21-1-2001",
                      "Host", "FIN-SRV-01",
                      timestamp="2026-02-01T00:00:00Z", source="log")
    now = datetime(2026, 4, 15, tzinfo=timezone.utc)
    all_edges = g.out_edges("Account", "S-1-5-21-1-2001")
    valid_edges = g.out_edges("Account", "S-1-5-21-1-2001", valid_at=now)
    assert len(all_edges) == 1
    # 30d 滑动窗口，距今 73 天无活动 → 过期
    assert len(valid_edges) == 0
