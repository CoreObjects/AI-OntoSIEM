"""阶段 4 C 段：三页签整合 main.py smoke test。"""
from __future__ import annotations


def test_main_module_imports_cleanly() -> None:
    import ui.main as m
    assert callable(m.main)


def test_main_exports_helpers() -> None:
    import ui.main as m
    assert callable(m._render_evolution_tab)
    assert callable(m._render_version_history)


def test_load_evolution_history_returns_list_of_versions() -> None:
    """从 ontology/v*.yaml 加载版本时间线，按版本号升序。"""
    from pathlib import Path
    from ui.main import _load_evolution_history
    history = _load_evolution_history(Path("ontology"))
    # 至少含 v1.0
    assert any(h["version"] == "1.0" for h in history)


def test_load_evolution_history_returns_empty_for_missing_dir(tmp_path) -> None:
    from ui.main import _load_evolution_history
    history = _load_evolution_history(tmp_path / "nope")
    assert history == []
