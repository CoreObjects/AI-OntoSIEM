"""阶段 4 A 段：评测看板 UI smoke test。"""
from __future__ import annotations


def test_ui_module_imports_cleanly() -> None:
    import ui.dashboard as d
    assert callable(d.render_page)
    assert callable(d.render_content)


def test_ui_exports_expected_helpers() -> None:
    import ui.dashboard as d
    assert callable(d._render_top_metrics)
    assert callable(d._render_evolution_diff)
    assert callable(d._render_breakdowns)
    assert callable(d._load_snapshot)


def test_load_signals_coexists_with_open_writer_hub(tmp_path, monkeypatch) -> None:
    """回归：dashboard 读 signals 与常驻读写 SignalHub 同进程共存不报错。

    根因 bug（main.py 三页签同进程整合后暴露）：告警研判页的 get_hub() 单例对
    signals.duckdb 持有读写连接并常驻整个进程，dashboard._load_signals 再用
    read_only=True 开同一文件 → DuckDB 同进程配置冲突 ConnectionException。
    修复：dashboard 经由同一个 hub 单例读，全进程只保留一条连接。
    """
    import ui.dashboard as dash
    from evolution import signal_hub
    from evolution.signal_hub import SignalHub

    db = tmp_path / "signals.duckdb"

    # 模拟告警研判页留下的常驻读写 hub（get_hub 单例持有读写连接，不关）
    prev_hub = signal_hub._default_hub
    hub = SignalHub(db)
    signal_hub._default_hub = hub
    hub.report_signal(
        "copilot", "manual_annotation",
        {"feedback": "up", "judgment_id": "j1"},
        aggregation_key="copilot:manual_annotation:up",
    )

    monkeypatch.setattr(dash, "SIGNALS_DB", db)
    try:
        sigs = dash._load_signals()   # 旧代码在此抛 ConnectionException
    finally:
        hub.close()
        signal_hub._default_hub = prev_hub

    fb = [s for s in sigs if s["signal_type"] == "manual_annotation"]
    assert len(fb) == 1
    assert fb[0]["payload"].get("feedback") == "up"
    assert fb[0]["source_layer"] == "copilot"
