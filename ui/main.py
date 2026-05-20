"""阶段 4 C 段：AI-OntoSIEM 统一入口（三页签整合）。

需求文档 §6.4：Streamlit 三页签
  - 📊 评测看板
  - 🛡️ 告警研判
  - 📐 本体演化（内部 sub-tab：提议审核 / 候选 Parser / 版本历史）

运行：
    streamlit run ui/main.py

每个子页保留独立 streamlit run 入口（向后兼容），main.py 通过 render_content()
嵌入。
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import streamlit as st  # noqa: E402
import yaml             # noqa: E402

from core.ontology_service import get_service       # noqa: E402

ONTOLOGY_DIR = ROOT / "ontology"


# =========================================================
# 主入口
# =========================================================

def main() -> None:
    st.set_page_config(
        page_title="AI-OntoSIEM",
        layout="wide",
        page_icon="🛡️",
    )

    # 顶部 banner
    cols = st.columns([3, 1])
    with cols[0]:
        st.markdown("# 🛡️ AI-OntoSIEM")
        st.caption("AI-native SIEM 原型 · 本体演化机制横切全系统 · "
                   "Demo 版（Qwen-Plus 后端）")
    with cols[1]:
        try:
            onto = get_service().get_current()
            st.metric("当前本体", f"v{onto.version}")
            st.caption(f"{len(onto.nodes)} 节点 · {len(onto.edges)} 边")
        except Exception:
            st.caption("(本体服务未初始化)")

    st.divider()

    tab_dash, tab_judge, tab_evo = st.tabs([
        "📊 评测看板",
        "🛡️ 告警研判",
        "📐 本体演化",
    ])

    with tab_dash:
        from ui.dashboard import render_content as r_dash
        r_dash()

    with tab_judge:
        from ui.judgment_review import render_content as r_judge
        r_judge()

    with tab_evo:
        _render_evolution_tab()


# =========================================================
# 演化 tab（内部 sub-tab）
# =========================================================

def _render_evolution_tab() -> None:
    sub_proposal, sub_parser, sub_replay, sub_history = st.tabs([
        "🆕 提议审核",
        "🔧 候选 Parser",
        "🔁 回放与验证",
        "📜 版本历史",
    ])

    with sub_proposal:
        from ui.evolution_review import render_content as r_prop
        r_prop()

    with sub_parser:
        from ui.parser_review import render_content as r_parser
        r_parser()

    with sub_replay:
        from ui.replay_review import render_content as r_replay
        r_replay()

    with sub_history:
        _render_version_history()


# =========================================================
# 版本历史
# =========================================================

def _load_evolution_history(ontology_dir: Path) -> List[Dict[str, Any]]:
    """读 ontology_dir 下所有 v*.yaml，按版本升序返回每版本的元数据。

    返回 [{version, path, created, created_by, nodes_count, edges_count,
           description, evolution_history}, ...]
    每个 history 条目对应该版本相对于之前版本新增了什么。
    """
    out: List[Dict[str, Any]] = []
    p = Path(ontology_dir)
    if not p.exists():
        return out

    for yaml_path in sorted(p.glob("v*.yaml")):
        try:
            with yaml_path.open("r", encoding="utf-8") as f:
                doc = yaml.safe_load(f) or {}
        except Exception:
            continue
        version = str(doc.get("version") or yaml_path.stem.lstrip("v"))
        out.append({
            "version": version,
            "path": str(yaml_path),
            "created": doc.get("created"),
            "created_by": doc.get("created_by"),
            "description": doc.get("description"),
            "nodes_count": len(doc.get("nodes") or {}),
            "edges_count": len(doc.get("edges") or {}),
            "evolution_history": doc.get("evolution_history") or [],
            "attack_anchors": doc.get("attack_anchors") or [],
            "node_names": list((doc.get("nodes") or {}).keys()),
            "edge_names": list((doc.get("edges") or {}).keys()),
        })

    def _key(h: Dict[str, Any]) -> tuple:
        v = h["version"]
        try:
            major, minor = v.split(".")
            return (int(major), int(minor))
        except Exception:
            return (0, 0)

    out.sort(key=_key)
    return out


def _render_version_history() -> None:
    st.markdown("## 📜 本体版本历史")
    st.caption("从初始 v1.0 到当前版本的全部演化记录 · 每次升级带 proposal_id 审计可回溯")

    history = _load_evolution_history(ONTOLOGY_DIR)
    if not history:
        st.warning("ontology/ 目录下找不到 v*.yaml")
        return

    # 顶部：版本时间线
    arrows = " → ".join(f"`v{h['version']}`" for h in history)
    st.markdown(f"**时间线**：{arrows}")

    st.divider()

    # 每个版本卡片
    for h in history:
        with st.container(border=True):
            cols = st.columns([1, 3])
            with cols[0]:
                st.markdown(f"### v{h['version']}")
                st.caption(h.get("created") or "-")
                st.metric("节点 / 边", f"{h['nodes_count']} / {h['edges_count']}")
            with cols[1]:
                st.markdown(f"**created_by**: `{h.get('created_by','?')}`")
                if h.get("description"):
                    st.caption(h["description"])

                # node / edge 列表
                with st.expander("nodes / edges"):
                    st.markdown(
                        f"**Nodes ({h['nodes_count']})**: "
                        + ", ".join(f"`{n}`" for n in h["node_names"])
                    )
                    st.markdown(
                        f"**Edges ({h['edges_count']})**: "
                        + ", ".join(f"`{e}`" for e in h["edge_names"])
                    )

                # 升级历史（哪些 proposal 进了这版）
                if h["evolution_history"]:
                    st.markdown("**升级记录**")
                    for entry in h["evolution_history"]:
                        eb = entry.get("base_version") or "?"
                        ev = entry.get("version") or "?"
                        ptype = entry.get("proposal_type") or "?"
                        name = entry.get("name") or "?"
                        pid = (entry.get("proposal_id") or "")[:8]
                        applied = entry.get("applied_at") or "?"
                        st.markdown(
                            f"- `v{eb}` → `v{ev}`：新增 **{ptype}** "
                            f"`{name}` (proposal {pid}) · {applied}"
                        )
                else:
                    st.caption("(初始版本，无升级记录)")


if __name__ == "__main__":
    main()
