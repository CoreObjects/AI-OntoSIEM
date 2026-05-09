"""阶段 4 B 段：告警研判页 UI smoke test。"""
from __future__ import annotations


def test_ui_module_imports_cleanly() -> None:
    import ui.judgment_review as jr
    assert callable(jr.render_page)


def test_ui_exports_expected_helpers() -> None:
    import ui.judgment_review as jr
    assert callable(jr._render_alert_list)
    assert callable(jr._render_judgment_card)
    assert callable(jr._render_graph_fragment)
    assert callable(jr._render_feedback_panel)
    assert callable(jr._load_alerts)
    assert callable(jr._load_judgments_map)
