"""UI 审核页 smoke test（只验证可导入、关键符号存在）。真正 UI 交互靠 streamlit run 人工验收。"""
from __future__ import annotations


def test_ui_module_imports_cleanly() -> None:
    import ui.evolution_review as ev
    assert callable(ev.render_page)


def test_ui_exports_expected_helpers() -> None:
    import ui.evolution_review as ev
    # 内部渲染函数存在
    assert callable(ev._render_card)
    assert callable(ev._render_history)
