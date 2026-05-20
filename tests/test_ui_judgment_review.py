"""阶段 4 B 段：告警研判页 UI smoke test。"""
from __future__ import annotations

import subprocess
import sys


def _external_open_ok(db) -> bool:
    code = "import duckdb,sys;c=duckdb.connect(sys.argv[1]);c.close()"
    return subprocess.run([sys.executable, "-c", code, str(db)]).returncode == 0


def test_ui_module_imports_cleanly() -> None:
    import ui.judgment_review as jr
    assert callable(jr.render_page)
    assert callable(jr.render_content)


def test_ui_exports_expected_helpers() -> None:
    import ui.judgment_review as jr
    assert callable(jr._render_alert_list)
    assert callable(jr._render_judgment_card)
    assert callable(jr._render_graph_fragment)
    assert callable(jr._render_feedback_panel)
    assert callable(jr._load_alerts)
    assert callable(jr._load_judgments_map)


def test_record_feedback_releases_lock(tmp_path) -> None:
    """反馈写入走短连接：写完不应再持有 signals.duckdb（否则 run_replay_validator 撞锁）。"""
    import ui.judgment_review as jr
    from evolution.signal_hub import SignalHub

    db = tmp_path / "signals.duckdb"
    jr._record_feedback_transient(
        judgment_id="j1", feedback="down", alert_id="a1", notes="x", db_path=db,
    )
    h = SignalHub(db)
    assert h.count_all() == 1
    h.close()
    assert _external_open_ok(db), "反馈写入后仍持有 signals.duckdb 锁"
