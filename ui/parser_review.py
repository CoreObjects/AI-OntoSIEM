"""组件 10 Day 2：候选 parser 审核页（Streamlit）。

运行：
    streamlit run ui/parser_review.py

UI 直接读 data/candidate_parsers.duckdb，审核员点按钮 → evolution.parser_review_actions
驱动状态机 + 写 parsers/generated/<id>.yaml。
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import streamlit as st  # noqa: E402

from core.ontology_service import get_service                # noqa: E402
from evolution.parser_review_actions import (                # noqa: E402
    CandidateNotPending, approve_and_apply,
    preview_candidate_parsing, reject_candidate,
)
from storage.anomaly_pool import AnomalyPool                 # noqa: E402
from storage.candidate_parser_store import CandidateParserStore  # noqa: E402


# =========================================================
# 页面构造
# =========================================================

def render_page() -> None:
    """独立运行入口（streamlit run ui/parser_review.py）。"""
    st.set_page_config(page_title="AI-OntoSIEM · Parser 候选审核", layout="wide")
    render_content()


def render_content() -> None:
    """页面内容；可被 ui/main.py 的 tab 容器嵌入。"""
    st.title("🔧 候选 Parser 审核")
    st.caption(
        "组件 10：基于 approved 提议 + 异常池样本，LLM 生成候选 parser；"
        "审核员先看抽样回放成功率，再决定 approve / reject。"
    )

    svc = _cached_service()
    onto = svc.get_current()
    view = _load_view()        # 短连接读完即关，不持有 candidate_parsers.duckdb
    counts = view["counts"]

    cols = st.columns(4)
    with cols[0]:
        st.metric("当前本体版本", f"v{onto.version}")
    with cols[1]:
        st.metric("待审核候选", counts.get("pending", 0))
    with cols[2]:
        st.metric("已通过", counts.get("approved", 0))
    with cols[3]:
        st.metric("已拒绝", counts.get("rejected", 0))

    # 生成候选 Parser（基于已通过提议）—— 替代终端 generate_parser.py
    if st.button("🤖 生成候选 Parser（基于已通过提议 · 真调 LLM ~3K tokens）",
                 key="btn-gen-candidate"):
        with st.spinner("LLM 生成候选 parser 中..."):
            from evolution.pipeline_ops import generate_candidates
            res = generate_candidates()
        if res.inserted:
            st.success(f"✓ 生成 {res.inserted} 条候选 parser")
        elif res.skipped:
            st.info("已通过提议都已有 active 候选，未重复生成。")
        else:
            st.warning("没有可生成候选的已通过提议；先到「🆕 提议审核」approve。")
        st.rerun()

    st.divider()

    pending = view["pending"]
    if not pending:
        st.success("🎉 当前没有待审核候选。点上方【🤖 生成候选 Parser】产生新候选。")
        _render_history(view["counts"], view["history"])
        return

    for row in pending:
        _render_candidate_card(row, onto)

    _render_history(view["counts"], view["history"])


# =========================================================
# 候选卡片
# =========================================================

def _render_candidate_card(row: dict, onto) -> None:
    cid = row["candidate_id"]
    cid_short = cid[:8]
    with st.container(border=True):
        title_cols = st.columns([2, 1, 1])
        with title_cols[0]:
            st.markdown(f"**🆕 target: `{row['target_node_type']}`**")
            st.caption(
                f"based on v{row['triggered_by_ontology_version']} · "
                f"proposal {row['triggered_by_proposal_id'][:8]}"
            )
        with title_cols[1]:
            st.metric("LLM confidence", f"{row['confidence']:.2f}")
        with title_cols[2]:
            st.metric("样本数", row["sample_count"])

        # source_events
        if row.get("source_events"):
            ev_str = ", ".join(
                f"{e.get('event_id')}/{e.get('channel')}"
                for e in row["source_events"]
            )
            st.markdown(f"**source_events:** `{ev_str}`")

        # rules（每条规则展开）
        with st.expander(f"📋 候选 rules（{len(row['rules'] or [])} 条）", expanded=True):
            for rule in row["rules"] or []:
                st.markdown(f"### `{rule['name']}`  ·  event_id={rule['event_id']}  channel={rule['channel']}")
                st.caption(rule.get("description") or "")
                st.markdown("**entities**")
                for ent in rule.get("entities") or []:
                    rk = ent.get("ref_name") or ent["node"]
                    st.markdown(f"- `[{rk}]` **{ent['node']}** id_expr=`{ent['id_expr']}`")
                    for k, v in (ent.get("attrs") or {}).items():
                        st.markdown(f"   • `{k}`: `{v}`")
                if rule.get("relations"):
                    st.markdown("**relations**")
                    for rel in rule["relations"]:
                        st.markdown(
                            f"- `{rel['edge']}`: {rel['from_ref']} → {rel['to_ref']}"
                        )

        # stripped_relations（LLM 想建但被闸门拦下）
        if row.get("stripped_relations"):
            with st.expander(
                f"🚫 被闸门 strip 的 relations（{len(row['stripped_relations'])} 条 — 给审核员看 LLM 想干啥）"
            ):
                for s in row["stripped_relations"]:
                    st.markdown(
                        f"- **{s['edge']}**: {s.get('from_ref')} → {s.get('to_ref')}"
                    )
                    st.caption(f"  reason: {s['reason']}")

        # explanation
        if row.get("explanation"):
            with st.expander("📝 LLM explanation"):
                st.markdown(row["explanation"])

        # 抽样回放预览
        st.markdown("---")
        preview_cols = st.columns([1, 3])
        with preview_cols[0]:
            n_preview = st.number_input(
                "预览样本数", min_value=1, max_value=50, value=5,
                key=f"npre-{cid}",
            )
        with preview_cols[1]:
            if st.button("▶ 跑抽样回放", key=f"pre-{cid}"):
                _run_preview(cid_short, row, n_preview, onto)

        # 决策按钮
        st.markdown("---")
        btn_cols = st.columns(2)
        with btn_cols[0]:
            if st.button("✅ Approve & Apply", key=f"app-{cid}", type="primary"):
                try:
                    yaml_path = _do_approve(cid)
                    st.success(f"已通过 · 写入 {yaml_path.name}")
                    st.rerun()
                except CandidateNotPending as exc:
                    st.warning(str(exc))
                except Exception as exc:
                    st.error(f"审核失败：{exc}")
        with btn_cols[1]:
            with st.popover("❌ Reject"):
                rsn = st.text_area("拒绝理由", key=f"rsn-{cid}",
                                   placeholder="如：抽样回放成功率不足；LLM 仍存在幻觉")
                if st.button("确认拒绝", key=f"rej-{cid}"):
                    try:
                        _do_reject(cid, reason=rsn or "(无理由)")
                        st.success("已拒绝")
                        st.rerun()
                    except Exception as exc:
                        st.error(str(exc))


def _run_preview(cid_short: str, row: dict, n: int, onto) -> None:
    """从异常池取 n 条样本，对候选规则做 dry-run 抽样回放（短连接）。"""
    report = _do_preview(row["candidate_id"], row.get("source_events"), int(n), onto)
    if report is None:
        st.error("找不到候选")
        return
    if report.get("_empty"):
        st.warning("异常池没有匹配 source_events 的样本")
        return

    st.markdown(f"**抽样回放结果（{cid_short}）**")
    rcols = st.columns(3)
    with rcols[0]:
        st.metric("总数", report["total"])
    with rcols[1]:
        st.metric("成功", report["success_count"])
    with rcols[2]:
        st.metric("成功率", f"{report['success_rate'] * 100:.0f}%")

    if report["parsed_samples"]:
        with st.expander(f"✅ 解析样例（前 {len(report['parsed_samples'])} 条）"):
            for ps in report["parsed_samples"]:
                st.markdown(f"- record_id={ps['record_id']}")
                for ent in ps["entities"]:
                    st.caption(f"   {ent['node_type']}: `{ent['node_id']}` attrs={ent['attrs']}")
                for rel in ps["relations"]:
                    st.caption(f"   {rel['edge_type']}: {rel['from']} → {rel['to']}")
    if report["failures"]:
        with st.expander(f"❌ 失败（{len(report['failures'])} 条）"):
            for f in report["failures"]:
                st.markdown(f"- record_id={f['record_id']} event_id={f['event_id']}")
                st.caption(f"   {f['reason']}")


# =========================================================
# 历史
# =========================================================

def _render_history(counts: Dict[str, int],
                    history: Dict[str, list]) -> None:
    st.divider()
    st.subheader("历史记录")
    cols = st.columns(2)
    with cols[0]:
        st.metric("已通过 (applied)", counts.get("approved", 0))
    with cols[1]:
        st.metric("已拒绝", counts.get("rejected", 0))

    for label, status_key in [
        ("✅ 已通过", "approved"),
        ("❌ 已拒绝", "rejected"),
    ]:
        with st.expander(f"{label}（{counts.get(status_key, 0)}）"):
            for r in history.get(status_key, []):
                with st.container(border=True):
                    st.markdown(
                        f"**{r['target_node_type']}** "
                        f"({r['candidate_id'][:8]}) · "
                        f"v{r['triggered_by_ontology_version']}"
                    )
                    if r.get("yaml_path"):
                        st.caption(f"YAML: `{r['yaml_path']}`")
                    if r.get("rejection_reason"):
                        st.caption(f"理由: {r['rejection_reason']}")


# =========================================================
# 数据访问（短连接：开→用→关，UI 不持有 duckdb）
# =========================================================

def _load_view(*, db_path: Optional[Path] = None) -> Dict[str, Any]:
    store = CandidateParserStore(db_path) if db_path else CandidateParserStore()
    try:
        return {
            "counts": store.count_by_status(),
            "pending": store.list_by_status("pending"),
            "history": {
                k: store.list_by_status(k, limit=50)
                for k in ("approved", "rejected")
            },
        }
    finally:
        store.close()


def _do_approve(cid: str, *, db_path: Optional[Path] = None) -> Path:
    store = CandidateParserStore(db_path) if db_path else CandidateParserStore()
    try:
        return approve_and_apply(store, cid)
    finally:
        store.close()


def _do_reject(cid: str, *, reason: str, db_path: Optional[Path] = None) -> None:
    store = CandidateParserStore(db_path) if db_path else CandidateParserStore()
    try:
        reject_candidate(store, cid, reason=reason)
    finally:
        store.close()


def _do_preview(cid: str, source_events, n: int, onto, *,
                store_db: Optional[Path] = None,
                pool_db: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """短连接：开 store + pool → 取样 → dry-run → 关。返回 report；
    候选不存在返回 None；无匹配样本返回 {"_empty": True}。"""
    store = CandidateParserStore(store_db) if store_db else CandidateParserStore()
    pool = AnomalyPool(pool_db) if pool_db else AnomalyPool()
    try:
        candidate = store.as_candidate(cid)
        if candidate is None:
            return None
        samples = []
        for ev in source_events or []:
            eid = ev.get("event_id")
            if eid is None:
                continue
            samples.extend(pool.list_by_event_id(int(eid), limit=int(n)))
        if not samples:
            return {"_empty": True}
        return preview_candidate_parsing(candidate, samples[:int(n)], ontology=onto)
    finally:
        pool.close()
        store.close()


# =========================================================
# 缓存（仅本体服务 —— 无 DuckDB 连接，可安全常驻）
# =========================================================

@st.cache_resource
def _cached_service():
    return get_service()


if __name__ == "__main__":
    render_page()
