"""阶段 4 A 段：评测看板 UI smoke test。"""
from __future__ import annotations


def test_ui_module_imports_cleanly() -> None:
    import ui.dashboard as d
    assert callable(d.render_page)


def test_ui_exports_expected_helpers() -> None:
    import ui.dashboard as d
    assert callable(d._render_top_metrics)
    assert callable(d._render_evolution_diff)
    assert callable(d._render_breakdowns)
    assert callable(d._load_snapshot)
