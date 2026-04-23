"""组件 9 演化审核 · OntologyUpgrader 单测。

通过后生成新本体 YAML + 版本 +0.1 + 订阅者 reload。
"""
from __future__ import annotations

import shutil
from pathlib import Path
from textwrap import dedent

import pytest
import yaml


def _seed_v10(dst_dir: Path) -> None:
    """复制项目里的 v1.0.yaml 做基准本体。"""
    src = Path(__file__).resolve().parents[1] / "ontology" / "v1.0.yaml"
    shutil.copy(src, dst_dir / "v1.0.yaml")


def _mk_proposal(ptype="node", name="ScheduledTask", attach_to=None):
    from evolution.proposer import Proposal
    return Proposal(
        proposal_id="p-test",
        proposal_type=ptype,
        name=name,
        semantic_definition=f"{name} 的语义定义",
        supporting_evidence=[{"record_id": i, "excerpt": f"s{i}"} for i in range(3)],
        overlap_analysis={"Process": 0.3},
        attack_mapping=["T1053.005"],
        source_signals=["data:unparseable_event:4698"],
        ontology_base_version="1.0",
        status="approved",
    )


# =========================================================
# 版本号计算
# =========================================================

def test_bump_version_minor() -> None:
    from evolution.ontology_upgrader import bump_version
    assert bump_version("1.0") == "1.1"
    assert bump_version("1.9") == "1.10"
    assert bump_version("2.3") == "2.4"


def test_bump_version_rejects_invalid() -> None:
    from evolution.ontology_upgrader import bump_version
    with pytest.raises(ValueError):
        bump_version("abc")


# =========================================================
# 新增节点
# =========================================================

def test_upgrade_adds_new_node_type(tmp_path: Path) -> None:
    from evolution.ontology_upgrader import OntologyUpgrader
    _seed_v10(tmp_path)

    up = OntologyUpgrader(ontology_dir=tmp_path)
    p = _mk_proposal(ptype="node", name="ScheduledTask")
    new_path = up.apply(p)

    assert new_path.name == "v1.1.yaml"
    doc = yaml.safe_load(new_path.read_text(encoding="utf-8"))
    assert doc["version"] == "1.1"
    assert "ScheduledTask" in doc["nodes"]
    node = doc["nodes"]["ScheduledTask"]
    assert "ScheduledTask 的语义定义" in node["description"]
    # 新节点必有完整元字段规约
    assert set(node["meta_attrs"]) >= {"first_seen", "last_seen", "confidence",
                                        "source", "ontology_version"}


def test_upgrade_records_attack_mapping_on_new_node(tmp_path: Path) -> None:
    from evolution.ontology_upgrader import OntologyUpgrader
    _seed_v10(tmp_path)
    up = OntologyUpgrader(ontology_dir=tmp_path)
    p = _mk_proposal(ptype="node", name="ScheduledTask")
    new_path = up.apply(p)
    doc = yaml.safe_load(new_path.read_text(encoding="utf-8"))
    # 新增的 attack_anchors 应合并（不破坏原有）
    ids = [a["id"] for a in doc["attack_anchors"]]
    assert "T1053.005" in ids
    assert "T1078" in ids  # 原有不应丢


def test_upgrade_rejects_duplicate_node(tmp_path: Path) -> None:
    from evolution.ontology_upgrader import OntologyUpgrader, UpgradeViolation
    _seed_v10(tmp_path)
    up = OntologyUpgrader(ontology_dir=tmp_path)
    p = _mk_proposal(ptype="node", name="Account")  # 已存在
    with pytest.raises(UpgradeViolation, match="Account"):
        up.apply(p)


# =========================================================
# 新增边
# =========================================================

def test_upgrade_adds_new_edge(tmp_path: Path) -> None:
    from evolution.proposer import Proposal
    from evolution.ontology_upgrader import OntologyUpgrader
    _seed_v10(tmp_path)

    edge_proposal = Proposal(
        proposal_id="p-e",
        proposal_type="edge",
        name="schedules",
        semantic_definition="Host 上运行的 ScheduledTask 关联",
        supporting_evidence=[{"record_id": i, "excerpt": "x"} for i in range(3)],
        overlap_analysis={"spawned": 0.25},
        attack_mapping=["T1053.005"],
        source_signals=["data:unparseable_event:4698"],
        ontology_base_version="1.0",
        status="approved",
        # 边需要 from / to 端点（用 semantic_definition 不够；我们要求额外结构）
    )
    # 边端点必须是本体里已存在的节点。真实演化路径：先加 ScheduledTask 节点（v1.1），
    # 再在 v1.1 基础上加 schedules 边（v1.2）。此测试用 v1.0 已有节点对验证加边逻辑。
    up = OntologyUpgrader(ontology_dir=tmp_path)
    new_path = up.apply(edge_proposal,
                        edge_endpoints={"from": "Host", "to": "Process"})
    doc = yaml.safe_load(new_path.read_text(encoding="utf-8"))
    assert "schedules" in doc["edges"]
    assert doc["edges"]["schedules"]["from"] == "Host"
    assert doc["edges"]["schedules"]["to"] == "Process"


def test_upgrade_rejects_edge_when_endpoint_not_in_ontology(tmp_path: Path) -> None:
    from evolution.proposer import Proposal
    from evolution.ontology_upgrader import OntologyUpgrader, UpgradeViolation
    _seed_v10(tmp_path)
    p = Proposal(
        proposal_id="p-e", proposal_type="edge", name="schedules",
        semantic_definition="x",
        supporting_evidence=[{}] * 3, overlap_analysis={"x": 0.1},
        attack_mapping=[], source_signals=[], ontology_base_version="1.0",
        status="approved",
    )
    up = OntologyUpgrader(ontology_dir=tmp_path)
    with pytest.raises(UpgradeViolation):
        up.apply(p, edge_endpoints={"from": "Host", "to": "ScheduledTask"})


def test_multi_step_upgrade_node_then_edge(tmp_path: Path) -> None:
    """真实演化链：v1.0 + node ScheduledTask → v1.1；v1.1 + edge schedules → v1.2。"""
    from evolution.proposer import Proposal
    from evolution.ontology_upgrader import OntologyUpgrader
    _seed_v10(tmp_path)
    up = OntologyUpgrader(ontology_dir=tmp_path)

    # step 1
    up.apply(_mk_proposal(ptype="node", name="ScheduledTask"))

    # step 2 — 基于 v1.1（含 ScheduledTask）再加边
    edge_p = Proposal(
        proposal_id="p-e", proposal_type="edge", name="schedules",
        semantic_definition="Host 调度的 ScheduledTask",
        supporting_evidence=[{}] * 3, overlap_analysis={"spawned": 0.25},
        attack_mapping=["T1053.005"], source_signals=["x"],
        ontology_base_version="1.1", status="approved",
    )
    up.apply(edge_p, edge_endpoints={"from": "Host", "to": "ScheduledTask"})

    # v1.2 应存在且包含 schedules
    v12 = tmp_path / "v1.2.yaml"
    assert v12.exists()
    doc = yaml.safe_load(v12.read_text(encoding="utf-8"))
    assert doc["version"] == "1.2"
    assert "ScheduledTask" in doc["nodes"]  # v1.1 带过来
    assert "schedules" in doc["edges"]
    assert doc["edges"]["schedules"]["to"] == "ScheduledTask"


# =========================================================
# 新增属性（attach 到已有节点）
# =========================================================

def test_upgrade_adds_attr_to_existing_node(tmp_path: Path) -> None:
    from evolution.proposer import Proposal
    from evolution.ontology_upgrader import OntologyUpgrader
    _seed_v10(tmp_path)
    attr_proposal = Proposal(
        proposal_id="p-a",
        proposal_type="attr",
        name="is_ephemeral",
        semantic_definition="短命端点（C2 候选）",
        supporting_evidence=[{"record_id": i, "excerpt": "x"} for i in range(3)],
        overlap_analysis={"is_internal": 0.3},
        attack_mapping=["T1071.001"],
        source_signals=["reasoning:semantic_gap:NetworkEndpoint"],
        ontology_base_version="1.0",
        status="approved",
    )
    up = OntologyUpgrader(ontology_dir=tmp_path)
    new_path = up.apply(attr_proposal, attr_target_node="NetworkEndpoint")
    doc = yaml.safe_load(new_path.read_text(encoding="utf-8"))
    opt = doc["nodes"]["NetworkEndpoint"]["optional_attrs"]
    assert "is_ephemeral" in opt
    # 原有 optional_attrs 不应丢
    assert "asn" in opt and "geoip_country" in opt


def test_upgrade_rejects_attr_when_target_missing(tmp_path: Path) -> None:
    from evolution.proposer import Proposal
    from evolution.ontology_upgrader import OntologyUpgrader, UpgradeViolation
    _seed_v10(tmp_path)
    attr_proposal = Proposal(
        proposal_id="p-a",
        proposal_type="attr",
        name="is_ephemeral",
        semantic_definition="...",
        supporting_evidence=[{}] * 3,
        overlap_analysis={"x": 0.1},
        attack_mapping=[],
        source_signals=[],
        ontology_base_version="1.0",
        status="approved",
    )
    up = OntologyUpgrader(ontology_dir=tmp_path)
    with pytest.raises(UpgradeViolation):
        up.apply(attr_proposal, attr_target_node="NonExistentNode")


# =========================================================
# 订阅回调联动
# =========================================================

def test_upgrade_reload_triggers_service_subscribers(tmp_path: Path) -> None:
    """写完新 YAML 后调 ontology_service.reload()，订阅者应收到回调。"""
    from core.ontology_service import OntologyService
    from evolution.ontology_upgrader import OntologyUpgrader
    _seed_v10(tmp_path)

    svc = OntologyService(ontology_dir=tmp_path)
    notifications = []
    svc.subscribe(lambda old, new: notifications.append(
        (old.version if old else None, new.version)
    ))

    up = OntologyUpgrader(ontology_dir=tmp_path, service=svc)
    up.apply(_mk_proposal(ptype="node", name="ScheduledTask"))

    assert notifications == [("1.0", "1.1")]
    assert svc.get_current().version == "1.1"


# =========================================================
# 拒绝流程不产生新本体
# =========================================================

def test_apply_refuses_non_approved_proposal(tmp_path: Path) -> None:
    from evolution.ontology_upgrader import OntologyUpgrader, UpgradeViolation
    _seed_v10(tmp_path)
    p = _mk_proposal()
    p.status = "pending"
    up = OntologyUpgrader(ontology_dir=tmp_path)
    with pytest.raises(UpgradeViolation, match="approved"):
        up.apply(p)


def test_no_v11_created_if_proposal_rejected_upstream(tmp_path: Path) -> None:
    """审核 UI 调拒绝路径时根本不会调 upgrader；确保 upgrader 只接受 approved。"""
    from evolution.ontology_upgrader import OntologyUpgrader, UpgradeViolation
    _seed_v10(tmp_path)
    p = _mk_proposal()
    p.status = "rejected"
    p.rejection_reason = "overlap too high"
    up = OntologyUpgrader(ontology_dir=tmp_path)
    with pytest.raises(UpgradeViolation):
        up.apply(p)
    assert not (tmp_path / "v1.1.yaml").exists()
