"""阶段 4 A 段：评测看板（Streamlit）。

需求文档 §6.4：4 个核心数字必须在首页一眼可见 + 演化前后对比。

运行：
    streamlit run ui/dashboard.py

数据源：
  - data/judgments.duckdb            （v1.0 时代研判，"before"）
  - data/judgments_after_replay.duckdb（v1.1 时代重判，"after"，可缺）
  - data/alerts.duckdb               （rule_id 用来对 ground_truth）
  - data/ground_truth.yaml           （人工真值表）
  - data/anomaly_pool.duckdb         （异常池规模）
  - data/parsed_events.duckdb        （成功解析事件数）
  - data/signals.duckdb              （manual_annotation 反馈信号）
  - data/replay_reports/validator_*.json  （演化前后对比，取最新）
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import duckdb              # noqa: E402
import streamlit as st     # noqa: E402

from evolution.metrics import (         # noqa: E402
    MetricsSnapshot, collect_metrics, load_ground_truth,
)
from evolution.signal_hub import get_hub              # noqa: E402
from storage.anomaly_pool import AnomalyPool          # noqa: E402
from storage.judgment_store import JudgmentStore      # noqa: E402

ALERTS_DB = ROOT / "data" / "alerts.duckdb"
JUDGMENTS_DB = ROOT / "data" / "judgments.duckdb"
JUDGMENTS_AFTER_DB = ROOT / "data" / "judgments_after_replay.duckdb"
PARSED_DB = ROOT / "data" / "parsed_events.duckdb"
SIGNALS_DB = ROOT / "data" / "signals.duckdb"
GROUND_TRUTH = ROOT / "data" / "ground_truth.yaml"
REPORTS_DIR = ROOT / "data" / "replay_reports"


# =========================================================
# 页面
# =========================================================

def render_page() -> None:
    """独立运行入口（streamlit run ui/dashboard.py）。"""
    st.set_page_config(page_title="AI-OntoSIEM · 评测看板",
                       layout="wide")
    render_content()


def render_content() -> None:
    """页面内容；可被 ui/main.py 的 tab 容器嵌入（不调 set_page_config）。"""
    st.title("📊 评测看板")
    st.caption("4 个核心数字 + 演化前后对比 · 决策层一眼可见")

    snap_before, snap_after = _load_snapshots()

    # 顶部 4 个核心数字
    _render_top_metrics(snap_after if snap_after is not None else snap_before)

    st.divider()

    # 演化前后对比
    if snap_before is not None and snap_after is not None:
        _render_evolution_diff(snap_before, snap_after)
        st.divider()

    # 拆分（accuracy by rule / pool by event_id）
    _render_breakdowns(snap_after if snap_after is not None else snap_before)


# =========================================================
# 顶部 4 数字
# =========================================================

def _render_top_metrics(snap: Optional[MetricsSnapshot]) -> None:
    st.subheader("核心数字")
    if snap is None:
        st.warning("还没有数据。先跑 `python scripts/run_judgments.py` 产生 judgments。")
        return

    cols = st.columns(4)
    with cols[0]:
        st.metric(
            "研判准确率",
            f"{snap.judgment_accuracy * 100:.1f}%",
            delta=f"{snap.accuracy_correct}/{snap.accuracy_total} 条",
            delta_color="off",
        )
    with cols[1]:
        st.metric(
            "反馈采纳率",
            f"{snap.feedback_adoption * 100:.1f}%",
            delta=f"👍 {snap.feedback_thumbs_up} · 👎 {snap.feedback_thumbs_down}",
            delta_color="off",
        )
    with cols[2]:
        st.metric(
            "本体覆盖率",
            f"{snap.ontology_coverage * 100:.1f}%",
            delta=f"{snap.parsed_event_count} / {snap.total_event_count} 事件",
            delta_color="off",
        )
    with cols[3]:
        st.metric(
            "异常池规模",
            snap.anomaly_pool_size_open,
            delta=f"{snap.anomaly_pool_size_total} 总积累",
            delta_color="off",
        )

    st.caption(f"snapshot 时间：{snap.timestamp}")


# =========================================================
# 演化前后对比
# =========================================================

def _render_evolution_diff(before: MetricsSnapshot, after: MetricsSnapshot) -> None:
    st.subheader("演化前后对比 · v1.0 → v1.1")
    cols = st.columns(4)

    def _fmt_delta(b: float, a: float, *, percent: bool = False) -> str:
        delta = a - b
        if percent:
            return f"{delta * 100:+.1f}pp"
        return f"{delta:+.0f}"

    with cols[0]:
        st.metric("研判准确率",
                  f"{after.judgment_accuracy * 100:.1f}%",
                  delta=_fmt_delta(before.judgment_accuracy,
                                   after.judgment_accuracy, percent=True))
    with cols[1]:
        # 反馈采纳率通常 0（demo 还没人点反馈）
        st.metric("反馈采纳率",
                  f"{after.feedback_adoption * 100:.1f}%",
                  delta=_fmt_delta(before.feedback_adoption,
                                   after.feedback_adoption, percent=True))
    with cols[2]:
        st.metric("本体覆盖率",
                  f"{after.ontology_coverage * 100:.1f}%",
                  delta=_fmt_delta(before.ontology_coverage,
                                   after.ontology_coverage, percent=True))
    with cols[3]:
        st.metric("异常池 open 规模",
                  after.anomaly_pool_size_open,
                  delta=_fmt_delta(before.anomaly_pool_size_open,
                                   after.anomaly_pool_size_open),
                  delta_color="inverse")  # 越少越好

    # ValidatorReport 加成（如果有）
    if after.evolution_diff:
        ed = after.evolution_diff
        st.markdown("**详细 diff（来自 ValidatorReport）**")
        ec = st.columns(4)
        with ec[0]:
            st.metric("verdict 升级", ed.get("verdict_upgraded", 0))
        with ec[1]:
            st.metric("verdict 降级", ed.get("verdict_downgraded", 0),
                      delta_color="inverse")
        with ec[2]:
            st.metric("semantic_gap 清除", ed.get("semantic_gap_cleared", 0))
        with ec[3]:
            st.metric("semantic_gap 持续", ed.get("semantic_gap_persisted", 0),
                      delta_color="inverse")
        # evidence_refs 平均
        st.caption(
            f"evidence_refs 平均：{ed.get('avg_evidence_refs_before', 0):.2f} → "
            f"{ed.get('avg_evidence_refs_after', 0):.2f}"
        )


# =========================================================
# 拆分
# =========================================================

def _render_breakdowns(snap: Optional[MetricsSnapshot]) -> None:
    if snap is None:
        return
    st.subheader("拆分")
    left, right = st.columns(2)

    with left:
        st.markdown("**按规则的研判准确率**")
        if not snap.accuracy_breakdown:
            st.caption("(空)")
        else:
            for rule_id, (correct, total) in sorted(
                snap.accuracy_breakdown.items()
            ):
                bar = "█" * correct + "░" * (total - correct)
                pct = correct / max(total, 1) * 100
                st.markdown(f"- `{rule_id}`: {correct}/{total} "
                            f"({pct:.0f}%) `{bar}`")

    with right:
        st.markdown("**异常池 open 按 event_id**")
        if not snap.anomaly_pool_size_open_by_event_id:
            st.caption("(空)")
        else:
            for eid, n in sorted(
                snap.anomaly_pool_size_open_by_event_id.items(),
                key=lambda kv: -kv[1],
            ):
                st.markdown(f"- event_id=`{eid}`: {n}")


# =========================================================
# 数据加载
# =========================================================

def _load_snapshots() -> tuple[Optional[MetricsSnapshot], Optional[MetricsSnapshot]]:
    """返回 (before/v1.0, after/v1.1)。任一文件缺失则该 snapshot 为 None。"""
    snap_before = _load_snapshot(judgments_db=JUDGMENTS_DB)
    snap_after = None
    if JUDGMENTS_AFTER_DB.exists():
        snap_after = _load_snapshot(judgments_db=JUDGMENTS_AFTER_DB,
                                    include_validator_report=True)
    return snap_before, snap_after


def _load_snapshot(
    *,
    judgments_db: Path,
    include_validator_report: bool = False,
) -> Optional[MetricsSnapshot]:
    if not judgments_db.exists() or not ALERTS_DB.exists():
        return None

    js = JudgmentStore(db_path=judgments_db)
    judgments = js.list_recent(limit=1000)
    js.close()

    alerts = _load_alerts()
    gt = load_ground_truth(GROUND_TRUTH)
    signals = _load_signals()

    parsed_count = _count_parsed_events()

    pool_open = pool_total = 0
    pool_by_eid: Dict[int, int] = {}
    if (ROOT / "data" / "anomaly_pool.duckdb").exists():
        p = AnomalyPool()
        pool_open = p.size_open()
        pool_total = p.size_total()
        pool_by_eid = p.count_by_event_id()
        p.close()

    evolution_diff = None
    if include_validator_report:
        evolution_diff = _load_latest_validator_report()

    return collect_metrics(
        judgments=judgments, alerts=alerts, ground_truth=gt,
        signals=signals,
        parsed_event_count=parsed_count,
        anomaly_pool_size_open=pool_open,
        anomaly_pool_size_total=pool_total,
        anomaly_pool_size_open_by_event_id=pool_by_eid,
        evolution_diff=evolution_diff,
    )


def _load_alerts() -> List[Dict[str, Any]]:
    if not ALERTS_DB.exists():
        return []
    con = duckdb.connect(str(ALERTS_DB), read_only=True)
    rows = con.execute(
        "SELECT alert_id, rule_id, computer FROM alerts"
    ).fetchall()
    con.close()
    return [{"alert_id": r[0], "rule_id": r[1], "computer": r[2]} for r in rows]


def _load_signals() -> List[Dict[str, Any]]:
    """读 signals.duckdb。

    必须经由 signal_hub 的单例连接 —— 告警研判页的 get_hub() 对同一文件持有
    读写连接并常驻整个进程，这里若另开 read_only 连接会触发 DuckDB
    "同进程同文件配置不一致" 冲突（main.py 三页签同进程整合后的真实 bug）。
    """
    if not SIGNALS_DB.exists():
        return []
    try:
        recent = get_hub().list_recent(limit=100000)
    except Exception:
        return []
    out = []
    for s in recent:
        payload = s.get("payload")
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError:
                payload = {}
        out.append({
            "signal_type": s.get("signal_type"),
            "payload": payload or {},
            "source_layer": s.get("source_layer"),
            "priority": s.get("priority"),
        })
    return out


def _count_parsed_events() -> int:
    if not PARSED_DB.exists():
        return 0
    con = duckdb.connect(str(PARSED_DB), read_only=True)
    try:
        n = con.execute(
            "SELECT COUNT(DISTINCT record_id) FROM entities"
        ).fetchone()[0]
    except duckdb.CatalogException:
        n = 0
    con.close()
    return int(n or 0)


def _load_latest_validator_report() -> Optional[Dict[str, Any]]:
    if not REPORTS_DIR.exists():
        return None
    files = sorted(REPORTS_DIR.glob("validator_*.json"))
    if not files:
        return None
    try:
        with files[-1].open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


if __name__ == "__main__":
    render_page()
