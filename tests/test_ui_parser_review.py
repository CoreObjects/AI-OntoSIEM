"""组件 10 Day 2：parser 候选审核 UI smoke test。"""
from __future__ import annotations

import subprocess
import sys


def _external_open_ok(db) -> bool:
    code = "import duckdb,sys;c=duckdb.connect(sys.argv[1]);c.close()"
    return subprocess.run([sys.executable, "-c", code, str(db)]).returncode == 0


def _seed(db, **over):
    from evolution.parser_generator import CandidateParser
    from storage.candidate_parser_store import CandidateParserStore
    kwargs = dict(
        candidate_id="c1", triggered_by_ontology_version="1.1",
        triggered_by_proposal_id="p1", target_node_type="ScheduledTask",
        source_events=[{"event_id": 4698, "channel": "Security"}],
        rules=[{"name": "r", "event_id": 4698, "channel": "Security", "entities": []}],
        sample_count=3, confidence=0.85,
    )
    kwargs.update(over)
    s = CandidateParserStore(db)
    s.insert(CandidateParser(**kwargs))
    s.close()


def test_ui_module_imports_cleanly() -> None:
    import ui.parser_review as pr
    assert callable(pr.render_page)
    assert callable(pr.render_content)


def test_ui_exports_expected_helpers() -> None:
    import ui.parser_review as pr
    assert callable(pr._render_candidate_card)
    assert callable(pr._render_history)


def test_load_view_releases_lock(tmp_path) -> None:
    import ui.parser_review as pr
    db = tmp_path / "candidate_parsers.duckdb"
    _seed(db)
    view = pr._load_view(db_path=db)
    assert [r["candidate_id"] for r in view["pending"]] == ["c1"]
    assert _external_open_ok(db), "读取后仍持有 candidate_parsers.duckdb 锁"


def test_do_reject_releases_lock(tmp_path) -> None:
    import ui.parser_review as pr
    from storage.candidate_parser_store import CandidateParserStore
    db = tmp_path / "candidate_parsers.duckdb"
    _seed(db)
    pr._do_reject("c1", reason="nope", db_path=db)
    s2 = CandidateParserStore(db)
    assert any(r["candidate_id"] == "c1" for r in s2.list_by_status("rejected"))
    s2.close()
    assert _external_open_ok(db), "动作后仍持有 candidate_parsers.duckdb 锁"
