"""审核四级决策动作（需求 §4.9）：
  approve_and_upgrade / reject / defer / modify_and_upgrade
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest


def _seed_ontology(dir_: Path) -> None:
    src = Path(__file__).resolve().parents[1] / "ontology" / "v1.0.yaml"
    shutil.copy(src, dir_ / "v1.0.yaml")


def _mk_pending_proposal(name="ScheduledTask", ptype="node", pid="p-1"):
    from evolution.proposer import Proposal
    return Proposal(
        proposal_id=pid,
        proposal_type=ptype,
        name=name,
        semantic_definition=f"{name} 的定义",
        supporting_evidence=[{"record_id": i, "excerpt": f"s{i}"} for i in range(3)],
        overlap_analysis={"Process": 0.3},
        attack_mapping=["T1053.005"],
        source_signals=["data:unparseable_event:4698"],
        ontology_base_version="1.0",
        status="pending",
    )


def _store(tmp_path: Path):
    from storage.proposal_store import ProposalStore
    return ProposalStore(db_path=tmp_path / "props.duckdb")


def _upgrader(onto_dir: Path):
    from evolution.ontology_upgrader import OntologyUpgrader
    return OntologyUpgrader(ontology_dir=onto_dir)


# =========================================================
# 通过 + 本体升级
# =========================================================

def test_approve_and_upgrade_creates_v11(tmp_path: Path) -> None:
    from evolution.review_actions import approve_and_upgrade

    onto = tmp_path / "ontology"; onto.mkdir()
    _seed_ontology(onto)
    s = _store(tmp_path)
    s.insert(_mk_pending_proposal(name="ScheduledTask"))

    upgrader = _upgrader(onto)
    new_path = approve_and_upgrade(s, "p-1", upgrader)

    assert new_path.name == "v1.1.yaml"
    # 状态应改为 approved
    assert s.list_by_status("approved")[0]["proposal_id"] == "p-1"
    s.close()


def test_approve_and_upgrade_edge_needs_endpoints(tmp_path: Path) -> None:
    from evolution.review_actions import approve_and_upgrade

    onto = tmp_path / "ontology"; onto.mkdir()
    _seed_ontology(onto)
    s = _store(tmp_path)
    s.insert(_mk_pending_proposal(name="schedules", ptype="edge"))

    upgrader = _upgrader(onto)
    new_path = approve_and_upgrade(
        s, "p-1", upgrader,
        edge_endpoints={"from": "Host", "to": "Process"},
    )
    assert new_path.name == "v1.1.yaml"
    s.close()


def test_approve_and_upgrade_attr_needs_target_node(tmp_path: Path) -> None:
    from evolution.review_actions import approve_and_upgrade

    onto = tmp_path / "ontology"; onto.mkdir()
    _seed_ontology(onto)
    s = _store(tmp_path)
    s.insert(_mk_pending_proposal(name="is_ephemeral", ptype="attr"))

    upgrader = _upgrader(onto)
    approve_and_upgrade(
        s, "p-1", upgrader,
        attr_target_node="NetworkEndpoint",
    )
    assert s.list_by_status("approved")[0]["name"] == "is_ephemeral"
    s.close()


# =========================================================
# 拒绝
# =========================================================

def test_reject_sets_status_and_reason(tmp_path: Path) -> None:
    from evolution.review_actions import reject
    s = _store(tmp_path)
    s.insert(_mk_pending_proposal())
    reject(s, "p-1", reason="与现有 Process 重叠过高")
    row = s.list_by_status("rejected")[0]
    assert row["rejection_reason"] == "与现有 Process 重叠过高"
    # 反面样本库应能查到
    assert "ScheduledTask" in s.rejection_names()
    s.close()


# =========================================================
# 延后：最多 2 周期；超过应强制拒
# =========================================================

def test_defer_tracks_count_and_force_reject_after_limit(tmp_path: Path) -> None:
    """第一次延后 → deferred；第二次延后 → deferred（累计 2）；第三次 → 自动 reject。"""
    from evolution.review_actions import defer
    s = _store(tmp_path)
    s.insert(_mk_pending_proposal())

    # 1 次
    rec1 = defer(s, "p-1", max_cycles=2)
    assert rec1["status"] == "deferred"
    assert rec1["defer_count"] == 1

    # 2 次（手动重置为 pending 模拟下一周期 UI 再次延后）
    s.mark_rejected("p-1", reason="")  # 清状态栏；只是为了 re-test 流程
    # 更干净：用独立 proposal 模拟
    s.insert(_mk_pending_proposal(pid="p-2"))
    defer(s, "p-2", max_cycles=2)
    rec2 = defer(s, "p-2", max_cycles=2)
    assert rec2["defer_count"] == 2
    # 第 3 次必须强制 reject
    rec3 = defer(s, "p-2", max_cycles=2)
    assert rec3["status"] == "rejected"
    assert rec3["defer_count"] == 2
    s.close()


# =========================================================
# 修改后通过
# =========================================================

def test_modify_and_upgrade_rewrites_name_and_creates_v11(tmp_path: Path) -> None:
    from evolution.review_actions import modify_and_upgrade

    onto = tmp_path / "ontology"; onto.mkdir()
    _seed_ontology(onto)
    s = _store(tmp_path)
    s.insert(_mk_pending_proposal(name="ScheduledTaskRaw"))

    upgrader = _upgrader(onto)
    new_path = modify_and_upgrade(
        s, "p-1", upgrader,
        new_name="ScheduledTask",
        new_definition="审核员修正后的 ScheduledTask 定义",
    )
    assert new_path.name == "v1.1.yaml"
    import yaml as _y
    doc = _y.safe_load(new_path.read_text(encoding="utf-8"))
    assert "ScheduledTask" in doc["nodes"]
    assert "审核员修正后的" in doc["nodes"]["ScheduledTask"]["description"]
    s.close()


# =========================================================
# 错误路径
# =========================================================

def test_actions_raise_on_unknown_id(tmp_path: Path) -> None:
    from evolution.review_actions import (
        approve_and_upgrade, reject, defer, modify_and_upgrade,
    )
    onto = tmp_path / "ontology"; onto.mkdir()
    _seed_ontology(onto)
    s = _store(tmp_path)
    up = _upgrader(onto)
    with pytest.raises(KeyError):
        approve_and_upgrade(s, "no-such", up)
    with pytest.raises(KeyError):
        reject(s, "no-such", reason="x")
    with pytest.raises(KeyError):
        defer(s, "no-such")
    with pytest.raises(KeyError):
        modify_and_upgrade(s, "no-such", up, new_name="X", new_definition="")
    s.close()


# =========================================================
# 积压告警
# =========================================================

def test_backlog_status_warn_and_pause(tmp_path: Path) -> None:
    from evolution.review_actions import backlog_status
    s = _store(tmp_path)
    for i in range(5):
        s.insert(_mk_pending_proposal(pid=f"p{i}", name=f"N{i}"))
    st = backlog_status(s)
    assert st["pending"] == 5
    assert st["level"] == "green"

    for i in range(10):
        s.insert(_mk_pending_proposal(pid=f"q{i}", name=f"M{i}"))
    st = backlog_status(s)
    assert st["pending"] == 15
    assert st["level"] == "yellow"   # > 10 告警

    for i in range(10):
        s.insert(_mk_pending_proposal(pid=f"r{i}", name=f"K{i}"))
    st = backlog_status(s)
    assert st["pending"] == 25
    assert st["level"] == "red"      # > 20 红色，暂停新提议
    assert st["pause_new_proposals"] is True
    s.close()
