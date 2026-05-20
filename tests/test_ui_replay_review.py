"""组件 10：回放与验证页 UI smoke test。"""
from __future__ import annotations


def test_ui_module_imports_cleanly() -> None:
    import ui.replay_review as rr
    assert callable(rr.render_page)
    assert callable(rr.render_content)


def test_ui_exports_expected_helpers() -> None:
    import ui.replay_review as rr
    assert callable(rr._render_replay_step)
    assert callable(rr._render_rejudge_step)
    assert callable(rr._render_rollback_step)
    assert callable(rr._render_validator_report)


def test_verdict_level_helper() -> None:
    import ui.replay_review as rr
    assert rr._level("malicious") > rr._level("suspicious") > rr._level("benign")
