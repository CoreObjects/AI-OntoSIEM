"""组件 10：回放与验证页（Streamlit）。

把原先三个终端脚本做成 UI 按钮，演示全程零终端：
  ① 回放异常池      → pipeline_ops.replay_pool       （异常池 32→10）
  ② 回放重判 + 对比 → pipeline_ops.rejudge_and_compare（真调 LLM，实时进度条）
  ③ 回滚检查        → pipeline_ops.latest_rollback_assessment

运行：
    streamlit run ui/replay_review.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import streamlit as st  # noqa: E402

from core.ontology_service import get_service  # noqa: E402


# =========================================================
# 页面
# =========================================================

def render_page() -> None:
    st.set_page_config(page_title="AI-OntoSIEM · 回放与验证", layout="wide")
    render_content()


def render_content() -> None:
    st.title("🔁 回放与验证")
    st.caption("演化应用后三步：回放异常池 → 回放重判对比 → 回滚检查。全程无需终端。")

    onto = _cached_service().get_current()
    if "ScheduledTask" not in (onto.nodes or {}):
        st.warning(
            f"当前本体 v{onto.version} 还没有 ScheduledTask 节点。"
            "请先到「🆕 提议审核」approve ScheduledTask、再到「🔧 候选 Parser」"
            "生成并 Apply，然后回这里回放。"
        )

    _render_replay_step()
    st.divider()
    _render_rejudge_step()
    st.divider()
    _render_rollback_step()


# =========================================================
# ① 回放异常池
# =========================================================

def _render_replay_step() -> None:
    st.subheader("① 回放异常池")
    st.caption("用已应用的新 parser 回放异常池里 backfilled=False 的事件，回填进图谱。")

    if st.button("▶ 回放异常池", type="primary", key="btn-replay"):
        with st.spinner("回放中（重建图 + 灌入 ScheduledTask 节点）..."):
            from evolution.pipeline_ops import replay_pool
            res = replay_pool()
        st.session_state["replay_result"] = {
            "pool_before": res.pool_before,
            "pool_after": res.pool_after,
            "backfilled": res.report.backfilled,
            "scheduledtask": res.scheduledtask_count,
        }
        _clear_graph_cache()
        st.rerun()

    rr = st.session_state.get("replay_result")
    if rr:
        cols = st.columns(3)
        with cols[0]:
            st.metric("异常池规模", rr["pool_after"],
                      delta=rr["pool_after"] - rr["pool_before"],
                      delta_color="inverse")
        with cols[1]:
            st.metric("本轮回填", rr["backfilled"])
        with cols[2]:
            st.metric("ScheduledTask 节点", rr["scheduledtask"])
        st.success(f"异常池 {rr['pool_before']} → {rr['pool_after']}。"
                   "到「🛡️ 告警研判」点【🔄 重建图谱】即可看到孤岛 ScheduledTask 节点。")


# =========================================================
# ② 回放重判 + 演化前后对比
# =========================================================

def _render_rejudge_step() -> None:
    st.subheader("② 回放重判 + 演化前后对比")
    st.caption("真调 LLM 用升级后的图谱重判全部告警，与 v1.0 老判决做 diff。"
               "约 4 分钟，~53K tokens。")

    if st.button("🔬 回放重判 + 对比（真调 LLM）", key="btn-rejudge"):
        prog = st.progress(0.0, text="准备重判...")
        log = st.empty()
        lines = []

        def _cb(i, n, alert, judgment):
            verdict = judgment.verdict if judgment else "FAILED"
            prog.progress(i / max(n, 1),
                          text=f"重判 {i}/{n}：{alert.rule_id} → {verdict}")
            lines.append(f"- [{i}/{n}] `{alert.rule_id}` → **{verdict}**")
            log.markdown("\n".join(lines))

        from evolution.pipeline_ops import rejudge_and_compare
        report = rejudge_and_compare(progress_cb=_cb)
        st.session_state["validator_report"] = report.to_dict()
        _clear_graph_cache()
        st.rerun()

    vr = st.session_state.get("validator_report")
    if vr:
        _render_validator_report(vr)


def _render_validator_report(vr: dict) -> None:
    st.markdown(f"**v{vr['ontology_version_before']} → v{vr['ontology_version_after']} · "
                f"重判 {vr['rejudged_count']} 条**")
    cols = st.columns(4)
    with cols[0]:
        st.metric("异常池", vr["pool_open_after"],
                  delta=vr["pool_open_after"] - vr["pool_open_before"],
                  delta_color="inverse")
    with cols[1]:
        st.metric("verdict 升级 / 降级",
                  f"{vr['verdict_upgraded']} / {vr['verdict_downgraded']}")
    with cols[2]:
        st.metric("semantic_gap 清除 / 持续",
                  f"{vr['semantic_gap_cleared']} / {vr['semantic_gap_persisted']}")
    with cols[3]:
        st.metric("evidence_refs 均值",
                  f"{vr['avg_evidence_refs_after']:.2f}",
                  delta=f"{vr['avg_evidence_refs_after'] - vr['avg_evidence_refs_before']:+.2f}")

    changes = vr.get("verdict_changes") or []
    downgraded = [c for c in changes if c.get("after_verdict") and
                  _level(c["before_verdict"]) > _level(c["after_verdict"])]
    if downgraded:
        st.error(f"⚠️ {len(downgraded)} 条被降级（演化的真实代价 · R5 分析师信任风险）：")
        for c in downgraded:
            st.markdown(
                f"- `{c['alert_id'][:8]}` "
                f"{c['before_verdict']}({c['before_confidence']:.2f}) → "
                f"**{c['after_verdict']}({c['after_confidence']:.2f})**"
            )
    else:
        st.info("本轮没有 verdict 被降级 —— 是「安全增量」（LLM 重判非确定性，每次可能不同）。")

    with st.expander(f"全部 {len(changes)} 条重判明细"):
        for c in changes:
            arrow = "→"
            st.markdown(
                f"- `{c['alert_id'][:8]}` "
                f"{c['before_verdict']}({c['before_confidence']:.2f}) {arrow} "
                f"{c['after_verdict']}({c['after_confidence']:.2f}) · "
                f"refs {c['before_evidence_count']}→{c['after_evidence_count']}"
            )


# =========================================================
# ③ 回滚检查
# =========================================================

def _render_rollback_step() -> None:
    st.subheader("③ 回滚检查")
    st.caption("读最新对比报告，按指标恶化（verdict 净降级 / semantic_gap 持续未清）"
               "判断是否产出回滚提议。从不自动回滚 —— 仅产候选给审核员。")

    if st.button("🛡 回滚检查", key="btn-rollback"):
        from evolution.pipeline_ops import latest_rollback_assessment
        p = latest_rollback_assessment()
        st.session_state["rollback_proposal"] = (
            p.to_dict() if p is not None else {"_none": True}
        )
        st.rerun()

    rb = st.session_state.get("rollback_proposal")
    if not rb:
        return
    if rb.get("_none"):
        st.success("✓ 不触发回滚（指标无显著恶化，或还没有对比报告）。")
        return

    sev = rb.get("severity", "warning").upper()
    box = st.error if sev == "CRITICAL" else st.warning
    box(f"⚠️ RollbackProposal · {sev}")
    st.markdown(f"**目标版本**：回滚到 v{rb['target_version']}（当前 v{rb['current_version']}）")
    st.markdown("**触发理由**：")
    for line in (rb.get("rationale") or "").splitlines():
        if line.strip():
            st.markdown(f"  {line}")
    st.caption("如确认回滚：删 ontology/v{} 对应 yaml + 重启 → 服务自动回到上一版。"
               .format(rb["current_version"]))


# =========================================================
# helpers
# =========================================================

_VERDICT_LEVEL = {"benign": 0, "suspicious": 1, "malicious": 2}


def _level(v: str) -> int:
    return _VERDICT_LEVEL.get(v, 0)


def _clear_graph_cache() -> None:
    """回放/重判后图谱变了，清掉告警研判页的 _cached_graph 让它重建。"""
    try:
        from ui.judgment_review import _cached_graph
        _cached_graph.clear()
    except Exception:
        pass


@st.cache_resource
def _cached_service():
    return get_service()


if __name__ == "__main__":
    render_page()
