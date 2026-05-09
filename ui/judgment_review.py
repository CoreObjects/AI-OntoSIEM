"""阶段 4 B 段：告警研判页（Streamlit）。

需求文档 §6.4：
  - 左：告警列表（rule + severity + 时间 + computer）
  - 中：AI 研判卡片（verdict + 推理链 + evidence_refs）
  - 右：图谱片段（与 evidence 节点 + Host 邻居）
  - 底：👍/👎 反馈按钮 → manual_annotation 信号 → 看板"反馈采纳率"会动

运行：
    streamlit run ui/judgment_review.py

数据源：
  - data/alerts.duckdb（告警列表）
  - data/judgments.duckdb（v1.0）
  - data/judgments_after_replay.duckdb（v1.1，优先显示）
  - data/parsed_events.duckdb + cmdb.yaml（重建图谱）
  - data/anomaly_pool.duckdb（用于 ScheduledTask 节点已 backfill 进图）
  - data/signals.duckdb（写反馈）
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

from core.ontology_service import get_service                # noqa: E402
from evolution.feedback import record_feedback               # noqa: E402
from evolution.signal_hub import get_hub                     # noqa: E402
from graph.cmdb_loader import load_cmdb                      # noqa: E402
from graph.importer import import_parsed_db                  # noqa: E402
from graph.store import GraphStore                           # noqa: E402
from storage.judgment_store import JudgmentStore             # noqa: E402

ALERTS_DB = ROOT / "data" / "alerts.duckdb"
PARSED_DB = ROOT / "data" / "parsed_events.duckdb"
JUDGMENTS_DB = ROOT / "data" / "judgments.duckdb"
JUDGMENTS_AFTER_DB = ROOT / "data" / "judgments_after_replay.duckdb"
CMDB_FILE = ROOT / "ontology" / "cmdb.yaml"


# =========================================================
# 页面
# =========================================================

def render_page() -> None:
    st.set_page_config(page_title="AI-OntoSIEM · 告警研判",
                       layout="wide")
    st.title("🛡️ 告警研判 · AI-OntoSIEM")
    st.caption(
        "左：告警列表 / 中：AI 研判 + 推理链 + 证据回指 / 右：相关图谱片段。"
        "底部 👍/👎 触发 manual_annotation 信号回流到看板。"
    )

    alerts = _load_alerts()
    if not alerts:
        st.warning("没有告警数据。先跑 `python scripts/run_detection.py`。")
        return

    judgments_map = _load_judgments_map()
    g = _cached_graph()

    # 默认选中第一条
    if "selected_alert_id" not in st.session_state:
        st.session_state["selected_alert_id"] = alerts[0]["alert_id"]

    left, middle, right = st.columns([1, 2, 1.5])

    with left:
        _render_alert_list(alerts, judgments_map)

    selected_id = st.session_state["selected_alert_id"]
    selected_alert = next((a for a in alerts if a["alert_id"] == selected_id), None)
    selected_judgment = judgments_map.get(selected_id) if selected_alert else None

    with middle:
        _render_judgment_card(selected_alert, selected_judgment)
        _render_feedback_panel(selected_alert, selected_judgment)

    with right:
        _render_graph_fragment(selected_alert, selected_judgment, g)


# =========================================================
# 左：告警列表
# =========================================================

def _render_alert_list(alerts: List[Dict[str, Any]],
                       judgments_map: Dict[str, Dict[str, Any]]) -> None:
    st.subheader(f"告警 ({len(alerts)})")
    sel = st.session_state.get("selected_alert_id")

    for a in alerts:
        aid = a["alert_id"]
        j = judgments_map.get(aid)
        verdict_str = (j.get("verdict") if j else "(no judgment)")
        gap = "🕳" if (j and j.get("semantic_gap")) else ""
        review = "🔁" if (j and j.get("needs_review")) else ""
        is_sel = (aid == sel)

        # button + caption 双行展示
        label = f"{'▶ ' if is_sel else '  '}{a['rule_id']}  · {a.get('severity','')}"
        if st.button(label, key=f"alert-btn-{aid}",
                     use_container_width=True,
                     type=("primary" if is_sel else "secondary")):
            st.session_state["selected_alert_id"] = aid
            st.rerun()
        st.caption(f"  {a.get('computer','?')} · {verdict_str} {gap}{review} · "
                   f"{str(a.get('timestamp', ''))[:16]}")


# =========================================================
# 中：研判卡片
# =========================================================

def _render_judgment_card(alert: Optional[Dict[str, Any]],
                          judgment: Optional[Dict[str, Any]]) -> None:
    if alert is None:
        st.info("从左侧选一条告警查看研判。")
        return

    st.subheader(f"📋 {alert.get('rule_title') or alert['rule_id']}")
    st.caption(
        f"alert_id=`{alert['alert_id'][:8]}`  · severity={alert.get('severity')} "
        f" · computer=`{alert.get('computer')}`  · 时间={str(alert.get('timestamp',''))[:19]}"
    )

    if judgment is None:
        st.warning("此告警尚未研判。运行 `python scripts/run_judgments.py` 后再来。")
        return

    # verdict + confidence
    verdict = judgment.get("verdict", "")
    conf = float(judgment.get("confidence") or 0)
    color_map = {"malicious": "🔴", "suspicious": "🟡", "benign": "🟢", "unknown": "⚪"}
    icon = color_map.get(verdict, "⚪")
    ver_cols = st.columns([1, 1, 1])
    with ver_cols[0]:
        st.metric("verdict", f"{icon} {verdict}")
    with ver_cols[1]:
        st.metric("confidence", f"{conf:.2f}")
    with ver_cols[2]:
        st.metric("ontology", f"v{judgment.get('ontology_version', '?')}")
    if judgment.get("needs_review"):
        st.warning("🔁 needs_review = True (低置信，等人工复核)")

    # reasoning_steps
    st.markdown("**推理链**")
    for i, s in enumerate(judgment.get("reasoning_steps") or [], 1):
        st.markdown(f"  {i}. {s}")

    # evidence_refs
    st.markdown(f"**Evidence refs ({len(judgment.get('evidence_refs') or [])})**")
    for ref in judgment.get("evidence_refs") or []:
        st.markdown(f"  - `{ref.get('type'):14s}` → `{ref.get('ref')}`")

    # attack_chain
    if judgment.get("attack_chain"):
        st.markdown("**ATT&CK 攻击链**")
        st.markdown("  " + " → ".join(f"`{t}`" for t in judgment["attack_chain"]))

    # next_steps
    if judgment.get("next_steps"):
        with st.expander(f"📋 next_steps ({len(judgment['next_steps'])})"):
            for s in judgment["next_steps"]:
                st.markdown(f"- {s}")

    # semantic_gap
    if judgment.get("semantic_gap"):
        with st.expander("🕳 semantic_gap（LLM 报本体缺失）"):
            st.json(judgment["semantic_gap"], expanded=True)


# =========================================================
# 右：图谱片段
# =========================================================

def _render_graph_fragment(alert: Optional[Dict[str, Any]],
                           judgment: Optional[Dict[str, Any]],
                           graph: Optional[GraphStore]) -> None:
    st.subheader("🕸 图谱片段")
    if alert is None or graph is None:
        st.caption("无可显示")
        return

    computer = alert.get("computer")
    if not computer:
        st.caption("alert.computer 为空")
        return

    if not graph.has_node("Host", computer):
        st.caption(f"图谱里找不到 Host:{computer}")
        return

    sub = graph.subgraph_around("Host", computer, depth=1)
    nodes = sub.get("nodes", [])
    edges = sub.get("edges", [])

    if not nodes:
        st.caption("子图为空")
        return

    # 按类型分组展示
    by_type: Dict[str, List[Dict[str, Any]]] = {}
    for n in nodes:
        by_type.setdefault(n.get("node_type", "?"), []).append(n)

    st.caption(f"中心 Host:{computer} · {len(nodes)} 节点 · {len(edges)} 边")
    for t in ["Host", "Account", "User", "Process", "ScheduledTask", "NetworkEndpoint"]:
        ns = by_type.get(t) or []
        if not ns:
            continue
        with st.expander(f"{t} ({len(ns)})", expanded=(t in {"Host", "Account", "ScheduledTask"})):
            for n in ns[:15]:
                attrs = n.get("attrs") or {}
                bf = attrs.get("backfilled")
                marker = " 🆕" if bf else ""
                node_id = n.get("node_id", "?")
                short = node_id if len(node_id) < 60 else (node_id[:57] + "…")
                st.markdown(f"- `{short}`{marker}")
                # 选 1-2 个有用 attrs 缩略显示
                useful = []
                for k in ("username", "task_name", "image_name", "ip", "hostname"):
                    v = attrs.get(k)
                    if v:
                        useful.append(f"{k}=`{str(v)[:40]}`")
                if useful:
                    st.caption("  " + " · ".join(useful))

    # 孤岛 ScheduledTask 节点（同主机但还没边连入子图 — v1.2 演化前的过渡态）
    sched_orphans = [
        n for n in graph.list_nodes_by_type("ScheduledTask")
        if str(n.get("node_id", "")).startswith(f"{computer}:")
        and n.get("node_id") not in {x.get("node_id") for x in nodes}
    ]
    if sched_orphans:
        with st.expander(
            f"🆕 孤岛 ScheduledTask 节点（{len(sched_orphans)} · 同主机但暂无边连入；"
            f"v1.2 演化加 `schedules` 边后会接入）",
            expanded=True,
        ):
            for n in sched_orphans[:10]:
                attrs = n.get("attrs") or {}
                tn = attrs.get("task_name") or n.get("node_id")
                bf = " (backfilled)" if attrs.get("backfilled") else ""
                st.markdown(f"- `{tn}`{bf}")

    # evidence_refs 中引用的 graph_node 高亮
    if judgment:
        ref_nodes = [r["ref"] for r in (judgment.get("evidence_refs") or [])
                     if r.get("type") == "graph_node"]
        if ref_nodes:
            st.markdown("**LLM 在 evidence_refs 里引用的图节点**")
            for r in ref_nodes:
                st.markdown(f"- ↗ `{r}`")


# =========================================================
# 底：反馈面板
# =========================================================

def _render_feedback_panel(alert: Optional[Dict[str, Any]],
                           judgment: Optional[Dict[str, Any]]) -> None:
    if alert is None or judgment is None:
        return

    st.markdown("---")
    st.markdown("**审核员反馈**")
    notes = st.text_input(
        "反馈说明（可选）",
        key=f"notes-{judgment.get('judgment_id','')}",
        placeholder="如：LSASS dump 应该判 malicious，AI 过度保守了",
    )
    cols = st.columns(4)
    hub = _cached_hub()
    jid = judgment.get("judgment_id") or ""
    aid = alert.get("alert_id") or ""

    with cols[0]:
        if st.button("👍 同意", key=f"thumbs-up-{jid}", type="primary",
                     use_container_width=True):
            try:
                record_feedback(hub, judgment_id=jid, feedback="up",
                                alert_id=aid,
                                notes=notes or None)
                st.success("✓ 反馈已写入 manual_annotation 信号（看板会立即统计）")
            except Exception as exc:
                st.error(f"反馈失败：{exc}")
    with cols[1]:
        if st.button("👎 不同意", key=f"thumbs-down-{jid}",
                     use_container_width=True):
            try:
                record_feedback(hub, judgment_id=jid, feedback="down",
                                alert_id=aid,
                                notes=notes or None)
                st.success("✓ 反馈已写入（拒判已统计到 reject 路径）")
            except Exception as exc:
                st.error(f"反馈失败：{exc}")


# =========================================================
# 数据加载（被 smoke test 引用）
# =========================================================

def _load_alerts() -> List[Dict[str, Any]]:
    if not ALERTS_DB.exists():
        return []
    con = duckdb.connect(str(ALERTS_DB), read_only=True)
    rows = con.execute(
        "SELECT alert_id, rule_id, rule_title, severity, computer, "
        "timestamp, attack_techniques FROM alerts ORDER BY timestamp"
    ).fetchall()
    con.close()

    def _l(v):
        if isinstance(v, str):
            try:
                return json.loads(v)
            except json.JSONDecodeError:
                return v
        return v

    return [
        {
            "alert_id": r[0], "rule_id": r[1], "rule_title": r[2],
            "severity": r[3], "computer": r[4], "timestamp": str(r[5]),
            "attack_techniques": _l(r[6]) or [],
        }
        for r in rows
    ]


def _load_judgments_map() -> Dict[str, Dict[str, Any]]:
    """alert_id → judgment dict；优先 v1.1，回退 v1.0。"""
    out: Dict[str, Dict[str, Any]] = {}

    # v1.0 先填底
    if JUDGMENTS_DB.exists():
        s = JudgmentStore(db_path=JUDGMENTS_DB)
        for j in s.list_recent(limit=1000):
            out[j["alert_id"]] = j
        s.close()

    # v1.1 覆盖（如有）
    if JUDGMENTS_AFTER_DB.exists():
        s = JudgmentStore(db_path=JUDGMENTS_AFTER_DB)
        for j in s.list_recent(limit=1000):
            out[j["alert_id"]] = j
        s.close()

    return out


# =========================================================
# 缓存（会话级单例）
# =========================================================

@st.cache_resource
def _cached_graph() -> Optional[GraphStore]:
    """重建图：parsed_events + cmdb + 异常池回放（含 ScheduledTask 节点）。"""
    if not PARSED_DB.exists():
        return None
    onto = get_service().get_current()
    g = GraphStore(ontology_version=onto.version)
    import_parsed_db(PARSED_DB, g)
    if CMDB_FILE.exists():
        load_cmdb(CMDB_FILE, g)

    # 把异常池里 4698/4702 中已成功 parse 的也回灌进图（保证 ScheduledTask 可见）
    pool_db = ROOT / "data" / "anomaly_pool.duckdb"
    if pool_db.exists():
        from parsers.windows_parser import (
            GENERATED_MAPPINGS_DIR, MAPPINGS_DIR, ParserConfig, WindowsParser,
        )
        from evolution.replay_engine import _NoOpAnomalyPool, _NoOpSignalHub
        cfg = ParserConfig.load_all([MAPPINGS_DIR, GENERATED_MAPPINGS_DIR])
        parser = WindowsParser(
            ontology=onto, config=cfg,
            anomaly_pool=_NoOpAnomalyPool(),
            signal_hub=_NoOpSignalHub(),
        )
        con = duckdb.connect(str(pool_db), read_only=True)
        rows = con.execute("SELECT raw_event FROM anomaly_pool").fetchall()
        con.close()
        for (raw_json,) in rows:
            raw = json.loads(raw_json) if isinstance(raw_json, str) else raw_json
            res = parser.parse_event(raw)
            if not res.success:
                continue
            for e in res.entities:
                try:
                    g.upsert_entity(
                        node_type=e.node_type, node_id=e.node_id,
                        attrs=dict(e.attrs),
                        timestamp=e.timestamp,
                        source=str(e.meta.get("source", "log")),
                        confidence=float(e.meta.get("confidence", 1.0)),
                    )
                except Exception:
                    pass
            for rel in res.relations:
                try:
                    g.upsert_relation(
                        edge_type=rel.edge_type,
                        from_type=rel.from_type, from_id=rel.from_id,
                        to_type=rel.to_type, to_id=rel.to_id,
                        timestamp=rel.timestamp,
                        source="log", confidence=1.0,
                        attrs=dict(rel.attrs),
                    )
                except Exception:
                    pass
    return g


@st.cache_resource
def _cached_hub():
    return get_hub()


if __name__ == "__main__":
    render_page()
