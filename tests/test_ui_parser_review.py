"""组件 10 Day 2：parser 候选审核 UI smoke test。"""
from __future__ import annotations


def test_ui_module_imports_cleanly() -> None:
    import ui.parser_review as pr
    assert callable(pr.render_page)
    assert callable(pr.render_content)


def test_ui_exports_expected_helpers() -> None:
    import ui.parser_review as pr
    assert callable(pr._render_candidate_card)
    assert callable(pr._render_history)
