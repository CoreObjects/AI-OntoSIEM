"""组件 7 演化信号中枢完整版：聚合 + 冷热分级 + 待处理 + 消费标记。

基础 API（会话 3 已做）：
  report_signal / count_all / count_by_type / list_recent / clear

本会话新增（组件 7 完整版）：
  list_aggregations(window_hours, min_count)
  list_pending(window_hours, threshold)
  list_by_priority(priority, limit)
  mark_processed(aggregation_key)
  count_by_priority()
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


# =========================================================
# fixture 工具
# =========================================================

def _hub(tmp_path: Path):
    from evolution.signal_hub import SignalHub
    return SignalHub(db_path=tmp_path / "sig.duckdb")


def _emit(hub, source, type_, payload=None, *,
          agg_key=None, priority=None, when: datetime = None):
    return hub.report_signal(
        source_layer=source, signal_type=type_,
        payload=payload or {"x": 1},
        aggregation_key=agg_key, priority=priority,
        timestamp=when, ontology_version="1.0",
    )


def _now() -> datetime:
    return datetime.now(timezone.utc)


# =========================================================
# 聚合查询
# =========================================================

def test_list_aggregations_groups_by_aggregation_key(tmp_path: Path) -> None:
    hub = _hub(tmp_path)
    for _ in range(3):
        _emit(hub, "data", "unparseable_event",
              agg_key="data:unparseable_event:4698")
    for _ in range(5):
        _emit(hub, "data", "unparseable_event",
              agg_key="data:unparseable_event:4702")
    _emit(hub, "reasoning", "semantic_gap",
          agg_key="reasoning:semantic_gap:ScheduledTask")

    groups = hub.list_aggregations()
    counts = {g["aggregation_key"]: g["count"] for g in groups}
    assert counts["data:unparseable_event:4698"] == 3
    assert counts["data:unparseable_event:4702"] == 5
    assert counts["reasoning:semantic_gap:ScheduledTask"] == 1


def test_list_aggregations_carries_metadata(tmp_path: Path) -> None:
    """聚合项应带 source_layer / signal_type / priority / first_seen / last_seen。"""
    hub = _hub(tmp_path)
    base = _now()
    _emit(hub, "data", "unparseable_event",
          agg_key="data:unparseable_event:4698",
          when=base - timedelta(hours=10))
    _emit(hub, "data", "unparseable_event",
          agg_key="data:unparseable_event:4698",
          when=base - timedelta(hours=1))

    g = hub.list_aggregations()[0]
    assert g["source_layer"] == "data"
    assert g["signal_type"] == "unparseable_event"
    assert g["priority"] == "hot"
    assert g["first_seen"] <= g["last_seen"]


def test_list_aggregations_window_filter(tmp_path: Path) -> None:
    """window_hours 过滤：超出窗口的不计入。"""
    hub = _hub(tmp_path)
    now = _now()
    # 窗口外（48h 前）
    _emit(hub, "data", "unparseable_event",
          agg_key="old", when=now - timedelta(hours=48))
    # 窗口内（10h 前）
    _emit(hub, "data", "unparseable_event",
          agg_key="new", when=now - timedelta(hours=10))

    keys = {g["aggregation_key"] for g in hub.list_aggregations(window_hours=24)}
    assert "new" in keys
    assert "old" not in keys


def test_list_aggregations_min_count_threshold(tmp_path: Path) -> None:
    hub = _hub(tmp_path)
    for _ in range(3):
        _emit(hub, "data", "unparseable_event", agg_key="small")
    for _ in range(22):
        _emit(hub, "data", "unparseable_event", agg_key="big")

    small_keys = {g["aggregation_key"] for g in hub.list_aggregations(min_count=1)}
    big_keys = {g["aggregation_key"] for g in hub.list_aggregations(min_count=20)}
    assert "small" in small_keys and "big" in small_keys
    assert "big" in big_keys
    assert "small" not in big_keys


# =========================================================
# 待处理：窗口内 >= threshold 的聚合
# =========================================================

def test_list_pending_returns_only_over_threshold(tmp_path: Path) -> None:
    hub = _hub(tmp_path)
    for _ in range(19):
        _emit(hub, "data", "unparseable_event", agg_key="k1")
    for _ in range(21):
        _emit(hub, "data", "unparseable_event", agg_key="k2")

    pending = hub.list_pending(threshold=20)
    keys = {p["aggregation_key"] for p in pending}
    assert keys == {"k2"}


def test_list_pending_respects_window(tmp_path: Path) -> None:
    hub = _hub(tmp_path)
    now = _now()
    for _ in range(30):
        _emit(hub, "data", "unparseable_event",
              agg_key="old", when=now - timedelta(hours=48))
    # 24h 窗口内不足阈值
    pending = hub.list_pending(window_hours=24, threshold=20)
    assert pending == []


# =========================================================
# 冷热分级查询
# =========================================================

def test_list_by_priority_hot(tmp_path: Path) -> None:
    hub = _hub(tmp_path)
    # unparseable_event 默认 priority=hot
    _emit(hub, "data", "unparseable_event", agg_key="a")
    # orphan_entity 默认 priority=warm
    _emit(hub, "data", "orphan_entity", agg_key="b")
    # coverage_deficit 默认 priority=cold
    _emit(hub, "evaluation", "coverage_deficit", agg_key="c")

    hot = hub.list_by_priority("hot")
    warm = hub.list_by_priority("warm")
    cold = hub.list_by_priority("cold")

    assert [r["signal_type"] for r in hot] == ["unparseable_event"]
    assert [r["signal_type"] for r in warm] == ["orphan_entity"]
    assert [r["signal_type"] for r in cold] == ["coverage_deficit"]


def test_count_by_priority(tmp_path: Path) -> None:
    hub = _hub(tmp_path)
    for _ in range(3):
        _emit(hub, "data", "unparseable_event")
    for _ in range(2):
        _emit(hub, "data", "orphan_entity")
    _emit(hub, "evaluation", "coverage_deficit")

    counts = hub.count_by_priority()
    assert counts == {"hot": 3, "warm": 2, "cold": 1}


def test_list_by_priority_limit(tmp_path: Path) -> None:
    hub = _hub(tmp_path)
    for _ in range(10):
        _emit(hub, "data", "unparseable_event")
    rows = hub.list_by_priority("hot", limit=3)
    assert len(rows) == 3


# =========================================================
# 消费标记：演化机制处理完后标记已处理
# =========================================================

def test_mark_processed_removes_group_from_pending(tmp_path: Path) -> None:
    hub = _hub(tmp_path)
    for _ in range(25):
        _emit(hub, "data", "unparseable_event",
              agg_key="data:unparseable_event:4698")

    assert len(hub.list_pending(threshold=20)) == 1
    n = hub.mark_processed("data:unparseable_event:4698")
    assert n == 25
    assert hub.list_pending(threshold=20) == []


def test_mark_processed_unknown_key_returns_zero(tmp_path: Path) -> None:
    hub = _hub(tmp_path)
    assert hub.mark_processed("no-such-key") == 0


def test_list_aggregations_include_processed_flag(tmp_path: Path) -> None:
    """聚合视图里应显式区分已处理与未处理。"""
    hub = _hub(tmp_path)
    for _ in range(5):
        _emit(hub, "data", "unparseable_event", agg_key="done")
    for _ in range(3):
        _emit(hub, "data", "unparseable_event", agg_key="todo")
    hub.mark_processed("done")

    groups = {g["aggregation_key"]: g for g in hub.list_aggregations()}
    assert groups["done"]["processed"] is True
    assert groups["todo"]["processed"] is False


# =========================================================
# 向后兼容：老 DB（无 processed_at 列）打开不 crash
# =========================================================

def test_open_preexisting_db_without_processed_column(tmp_path: Path) -> None:
    """模拟旧版本建的 signals.duckdb（没有 processed_at 列），新版 SignalHub 打开应自动 ALTER 添加。"""
    import duckdb
    from evolution.signal_hub import SignalHub

    db = tmp_path / "legacy.duckdb"
    con = duckdb.connect(str(db))
    con.execute("""
        CREATE TABLE signals (
            signal_id        VARCHAR PRIMARY KEY,
            timestamp        TIMESTAMP,
            source_layer     VARCHAR,
            signal_type      VARCHAR,
            priority         VARCHAR,
            payload          JSON,
            aggregation_key  VARCHAR,
            ontology_version VARCHAR
        )
    """)
    con.close()

    # 打开不应 crash
    hub = SignalHub(db_path=db)
    _emit(hub, "data", "unparseable_event", agg_key="k1")
    assert hub.count_all() == 1
