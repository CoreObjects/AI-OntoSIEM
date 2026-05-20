"""UI 审核页 smoke test（只验证可导入、关键符号存在）。真正 UI 交互靠 streamlit run 人工验收。"""
from __future__ import annotations

import subprocess
import sys


def _external_open_ok(db) -> bool:
    """另起进程尝试打开 duckdb 文件；成功 = 当前进程没有持有该文件的锁。"""
    code = "import duckdb,sys;c=duckdb.connect(sys.argv[1]);c.close()"
    return subprocess.run([sys.executable, "-c", code, str(db)]).returncode == 0


def test_ui_module_imports_cleanly() -> None:
    import ui.evolution_review as ev
    assert callable(ev.render_page)
    assert callable(ev.render_content)


def test_ui_exports_expected_helpers() -> None:
    import ui.evolution_review as ev
    # 内部渲染函数存在
    assert callable(ev._render_card)
    assert callable(ev._render_history)


def test_load_view_releases_lock(tmp_path) -> None:
    """渲染读取走短连接：读完不应再持有 proposals.duckdb，否则终端脚本撞跨进程锁。"""
    import ui.evolution_review as ev
    from evolution.proposer import Proposal
    from storage.proposal_store import ProposalStore

    db = tmp_path / "proposals.duckdb"
    s = ProposalStore(db)
    s.insert(Proposal(
        proposal_id="p1", proposal_type="node", name="ScheduledTask",
        semantic_definition="d", supporting_evidence=[{"x": 1}],
        overlap_analysis={"Process": 0.2}, attack_mapping=["T1053"],
        source_signals=["data:unparseable_event:4698"],
        ontology_base_version="1.0",
    ))
    s.close()

    view = ev._load_view(db_path=db)
    assert [r["proposal_id"] for r in view["pending"]] == ["p1"]
    assert view["backlog"]["pending"] == 1
    assert _external_open_ok(db), "读取后仍持有 proposals.duckdb 锁"


def test_do_reject_releases_lock(tmp_path) -> None:
    import ui.evolution_review as ev
    from evolution.proposer import Proposal
    from storage.proposal_store import ProposalStore

    db = tmp_path / "proposals.duckdb"
    s = ProposalStore(db)
    s.insert(Proposal(
        proposal_id="p1", proposal_type="node", name="X",
        semantic_definition="d", supporting_evidence=[], overlap_analysis={},
        attack_mapping=[], source_signals=[], ontology_base_version="1.0",
    ))
    s.close()

    ev._do_reject("p1", reason="nope", db_path=db)
    s2 = ProposalStore(db)
    assert s2.get("p1")["status"] == "rejected"
    s2.close()
    assert _external_open_ok(db), "动作后仍持有 proposals.duckdb 锁"
