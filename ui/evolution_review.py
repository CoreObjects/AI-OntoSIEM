"""组件 9 演化审核页（Streamlit）。

运行：
    streamlit run ui/evolution_review.py

UI 直接读 data/proposals.duckdb，审核员点按钮触发 evolution/review_actions 里的动作。
审核通过 → OntologyUpgrader 写新 YAML → OntologyService 订阅者（GraphStore / Parser）自动响应。
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import streamlit as st  # noqa: E402

from core.ontology_service import get_service  # noqa: E402
from evolution.ontology_upgrader import OntologyUpgrader  # noqa: E402
from evolution.review_actions import (  # noqa: E402
    approve_and_upgrade,
    backlog_status,
    defer,
    modify_and_upgrade,
    reject,
)
from storage.proposal_store import ProposalStore  # noqa: E402


# =========================================================
# 页面构造（独立函数，便于 smoke test）
# =========================================================

def render_page() -> None:
    """独立运行入口（streamlit run ui/evolution_review.py）。"""
    st.set_page_config(page_title="AI-OntoSIEM · 演化审核", layout="wide")
    render_content()


def render_content() -> None:
    """页面内容；可被 ui/main.py 的 tab 容器嵌入。"""
    st.title("📐 本体演化提议审核")

    svc = _cached_service()
    onto = svc.get_current()
    view = _load_view()        # 短连接读完即关，不持有 proposals.duckdb
    status = view["backlog"]

    # 顶部：积压告警 + 当前本体版本
    cols = st.columns(4)
    with cols[0]:
        st.metric("当前本体版本", f"v{onto.version}")
    with cols[1]:
        st.metric("节点类型数", len(onto.nodes))
    with cols[2]:
        st.metric("关系类型数", len(onto.edges))
    with cols[3]:
        st.metric("待审核提议", status["pending"])

    if status["level"] == "red":
        st.error(f"⛔ 积压红色告警：{status['pending']} 条待审核，新提议已暂停")
    elif status["level"] == "yellow":
        st.warning(f"⚠️ 积压黄色告警：{status['pending']} 条待审核")

    st.divider()

    # pending 列表
    pending = view["pending"]
    if not pending:
        st.success("🎉 当前没有待审核提议。运行 `python scripts/run_proposals.py` 产生新提议。")
        _render_history(view["counts"], view["history"])
        return

    for row in pending:
        _render_card(row)

    _render_history(view["counts"], view["history"])


# =========================================================
# 卡片渲染
# =========================================================

def _render_card(row: dict) -> None:
    pid = row["proposal_id"]
    with st.container(border=True):
        title_cols = st.columns([1, 3, 1])
        with title_cols[0]:
            st.markdown(f"**类型**\n\n`{row['proposal_type']}`")
        with title_cols[1]:
            st.markdown(f"**🆕 {row['name']}**")
            st.caption(row["semantic_definition"] or "(无语义定义)")
        with title_cols[2]:
            st.caption(f"id: {pid[:8]}")
            st.caption(f"based on v{row['ontology_base_version']}")

        info_cols = st.columns(3)
        with info_cols[0]:
            st.markdown("**ATT&CK 映射**")
            for t in row["attack_mapping"] or []:
                st.markdown(f"- `{t}`")
        with info_cols[1]:
            st.markdown("**重叠度分析**")
            for k, v in sorted((row["overlap_analysis"] or {}).items(),
                               key=lambda kv: -kv[1]):
                bar = "█" * int(v * 10)
                st.markdown(f"- {k}: `{v:.2f}` {bar}")
        with info_cols[2]:
            st.markdown("**来源信号**")
            for s in row["source_signals"] or []:
                st.markdown(f"- `{s}`")

        with st.expander(f"🧾 支持证据（{len(row['supporting_evidence'] or [])} 条）"):
            for ev in row["supporting_evidence"] or []:
                st.json(ev, expanded=False)

        # 额外输入（边/属性类型需要 hints）
        edge_from, edge_to, attr_target = None, None, None
        if row["proposal_type"] == "edge":
            cc = st.columns(2)
            with cc[0]:
                edge_from = st.text_input(f"from 节点", key=f"ef-{pid}", value="Host")
            with cc[1]:
                edge_to = st.text_input(f"to 节点", key=f"et-{pid}", value="Process")
        elif row["proposal_type"] == "attr":
            attr_target = st.text_input(
                "attr 附加到哪个节点", key=f"at-{pid}", value="NetworkEndpoint"
            )

        # 四级决策按钮
        btn_cols = st.columns(4)
        with btn_cols[0]:
            if st.button("✅ 通过", key=f"approve-{pid}", type="primary"):
                try:
                    hints = {}
                    if row["proposal_type"] == "edge":
                        hints["edge_endpoints"] = {"from": edge_from, "to": edge_to}
                    elif row["proposal_type"] == "attr":
                        hints["attr_target_node"] = attr_target
                    new_path = _do_approve(pid, **hints)
                    st.success(f"已通过 · 本体升级到 {new_path.name}")
                    st.rerun()
                except Exception as exc:
                    st.error(f"升级失败：{exc}")

        with btn_cols[1]:
            with st.popover("✏️ 修改后通过"):
                new_name = st.text_input("新名称", value=row["name"], key=f"mn-{pid}")
                new_def = st.text_area("修正后的语义定义",
                                       value=row["semantic_definition"] or "",
                                       key=f"md-{pid}")
                if st.button("提交修正并升级", key=f"msub-{pid}"):
                    try:
                        hints = {}
                        if row["proposal_type"] == "edge":
                            hints["edge_endpoints"] = {"from": edge_from, "to": edge_to}
                        elif row["proposal_type"] == "attr":
                            hints["attr_target_node"] = attr_target
                        new_path = _do_modify(
                            pid, new_name=new_name, new_definition=new_def, **hints,
                        )
                        st.success(f"修改后通过 · 本体升级到 {new_path.name}")
                        st.rerun()
                    except Exception as exc:
                        st.error(f"升级失败：{exc}")

        with btn_cols[2]:
            with st.popover("❌ 拒绝"):
                rsn = st.text_area("拒绝理由", key=f"rr-{pid}")
                if st.button("确认拒绝", key=f"rsub-{pid}"):
                    try:
                        _do_reject(pid, reason=rsn or "(无理由)")
                        st.success("已拒绝，入反面样本库")
                        st.rerun()
                    except Exception as exc:
                        st.error(str(exc))

        with btn_cols[3]:
            if st.button(f"⏳ 延后 (当前 {row.get('defer_count', 0)}/2)",
                         key=f"defer-{pid}"):
                try:
                    res = _do_defer(pid, max_cycles=2)
                    if res["status"] == "rejected":
                        st.warning(f"已达延后上限 · 自动拒绝（defer_count={res['defer_count']}）")
                    else:
                        st.info(f"已延后 · defer_count={res['defer_count']}")
                    st.rerun()
                except Exception as exc:
                    st.error(str(exc))


# =========================================================
# 历史记录展示
# =========================================================

def _render_history(counts: Dict[str, int],
                    history: Dict[str, list]) -> None:
    st.divider()
    st.subheader("历史记录")
    hc = st.columns(4)
    with hc[0]:
        st.metric("已通过", counts.get("approved", 0))
    with hc[1]:
        st.metric("已修改通过", counts.get("modified", 0))
    with hc[2]:
        st.metric("已拒绝", counts.get("rejected", 0))
    with hc[3]:
        st.metric("延后中", counts.get("deferred", 0))

    for status_label, status_key in [
        ("✅ 已通过", "approved"),
        ("✏️ 修改后通过", "modified"),
        ("❌ 已拒绝", "rejected"),
        ("⏳ 延后", "deferred"),
    ]:
        with st.expander(f"{status_label}（{counts.get(status_key, 0)}）"):
            for r in history.get(status_key, []):
                with st.container(border=True):
                    st.markdown(f"**{r['name']}** ({r['proposal_type']}) · "
                                f"{r.get('rejection_reason') or ''}")
                    st.caption(r["semantic_definition"] or "")


# =========================================================
# 数据访问（短连接：开→用→关，UI 不持有 proposals.duckdb）
# =========================================================

def _open_store(db_path: Optional[Path] = None) -> ProposalStore:
    return ProposalStore(db_path) if db_path else ProposalStore()


def _load_view(*, db_path: Optional[Path] = None) -> Dict[str, Any]:
    """一次性读出渲染需要的全部提议数据，读完即关连接。"""
    store = _open_store(db_path)
    try:
        return {
            "backlog": backlog_status(store),
            "pending": store.list_by_status("pending"),
            "counts": store.count_by_status(),
            "history": {
                k: store.list_by_status(k, limit=50)
                for k in ("approved", "modified", "rejected", "deferred")
            },
        }
    finally:
        store.close()


def _do_approve(pid: str, *, edge_endpoints=None, attr_target_node=None,
                db_path: Optional[Path] = None) -> Path:
    svc = _cached_service()
    store = _open_store(db_path)
    try:
        upgrader = OntologyUpgrader(ontology_dir=ROOT / "ontology", service=svc)
        return approve_and_upgrade(
            store, pid, upgrader,
            edge_endpoints=edge_endpoints, attr_target_node=attr_target_node,
        )
    finally:
        store.close()


def _do_modify(pid: str, *, new_name: str, new_definition: str,
               edge_endpoints=None, attr_target_node=None,
               db_path: Optional[Path] = None) -> Path:
    svc = _cached_service()
    store = _open_store(db_path)
    try:
        upgrader = OntologyUpgrader(ontology_dir=ROOT / "ontology", service=svc)
        return modify_and_upgrade(
            store, pid, upgrader,
            new_name=new_name, new_definition=new_definition,
            edge_endpoints=edge_endpoints, attr_target_node=attr_target_node,
        )
    finally:
        store.close()


def _do_reject(pid: str, *, reason: str, db_path: Optional[Path] = None) -> None:
    store = _open_store(db_path)
    try:
        reject(store, pid, reason=reason)
    finally:
        store.close()


def _do_defer(pid: str, *, max_cycles: int = 2,
              db_path: Optional[Path] = None) -> Dict[str, Any]:
    store = _open_store(db_path)
    try:
        return defer(store, pid, max_cycles=max_cycles)
    finally:
        store.close()


# =========================================================
# 缓存 helper（仅本体服务 —— 无 DuckDB 连接，可安全常驻）
# =========================================================

@st.cache_resource
def _cached_service():
    return get_service()


# Streamlit 通过 `streamlit run ui/evolution_review.py` 把脚本作为 __main__ 执行
# 直接 import 此模块（smoke test）不应触发 UI 渲染
if __name__ == "__main__":
    render_page()
