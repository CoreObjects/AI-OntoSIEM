"""组件 2 本体注册中心单测。"""
from __future__ import annotations

import time
from pathlib import Path

import pytest
import yaml

from core.ontology_service import Ontology, OntologyService


ROOT = Path(__file__).resolve().parents[1]
ONTOLOGY_DIR = ROOT / "ontology"


@pytest.fixture()
def svc() -> OntologyService:
    return OntologyService(ONTOLOGY_DIR)


def test_loads_v1_0(svc: OntologyService) -> None:
    onto = svc.get_current()
    assert onto.version == "1.0"
    assert "User" in onto.nodes
    assert "Account" in onto.nodes
    assert "Host" in onto.nodes
    assert "Process" in onto.nodes
    assert "NetworkEndpoint" in onto.nodes
    assert len(onto.nodes) == 5


def test_all_six_edges_present(svc: OntologyService) -> None:
    onto = svc.get_current()
    expected = {"owns", "authenticated_as", "logged_into", "spawned", "executed_on", "connected_to"}
    assert set(onto.edges.keys()) == expected


def test_owns_edge_endpoints(svc: OntologyService) -> None:
    onto = svc.get_current()
    assert onto.edge_endpoints("owns") == ("User", "Account")


def test_required_attrs_account(svc: OntologyService) -> None:
    onto = svc.get_current()
    required = set(onto.required_attrs("Account"))
    assert required == {"sid", "domain", "username"}


def test_all_nodes_have_meta_attrs(svc: OntologyService) -> None:
    onto = svc.get_current()
    required_meta = {"first_seen", "last_seen", "confidence", "source", "ontology_version"}
    for name, node in onto.nodes.items():
        meta = set(node.get("meta_attrs") or [])
        assert required_meta.issubset(meta), f"{name} missing meta fields: {required_meta - meta}"


def test_all_edges_have_meta_attrs(svc: OntologyService) -> None:
    onto = svc.get_current()
    required_meta = {"first_seen", "last_seen", "confidence", "source", "ontology_version"}
    for name, edge in onto.edges.items():
        meta = set(edge.get("meta_attrs") or [])
        assert required_meta.issubset(meta), f"{name} missing meta fields: {required_meta - meta}"


def test_attack_anchors_present(svc: OntologyService) -> None:
    onto = svc.get_current()
    tech_ids = {a["id"] for a in onto.attack_anchors}
    assert {"T1078", "T1021", "T1055", "T1053", "T1570"}.issubset(tech_ids)


def test_no_scheduled_task_in_v1_0(svc: OntologyService) -> None:
    """v1.0 故意不含 ScheduledTask，这是 Demo 演化的锚点。"""
    onto = svc.get_current()
    assert "ScheduledTask" not in onto.nodes
    assert "created_task" not in onto.edges


def test_owns_time_decay_is_none(svc: OntologyService) -> None:
    """owns 必须永久；如果变成时效性关系，表示错误建模。"""
    onto = svc.get_current()
    assert onto.edges["owns"]["time_decay"] == "none"


def test_list_versions(svc: OntologyService) -> None:
    versions = svc.list_versions()
    assert "1.0" in versions


def test_get_version_returns_none_for_missing(svc: OntologyService) -> None:
    assert svc.get_version("99.9") is None


def test_subscribe_fires_on_reload(tmp_path: Path) -> None:
    """新增一个更高版本文件后，reload 应触发订阅回调。"""
    # 复制 v1.0 到临时目录
    src = (ONTOLOGY_DIR / "v1.0.yaml").read_text(encoding="utf-8")
    (tmp_path / "v1.0.yaml").write_text(src, encoding="utf-8")

    svc = OntologyService(tmp_path)
    received: list[tuple] = []
    svc.subscribe(lambda old, new: received.append((old.version if old else None, new.version)))

    # 新增 v1.1
    new_doc = yaml.safe_load(src)
    new_doc["version"] = "1.1"
    new_doc["description"] = "test upgrade"
    (tmp_path / "v1.1.yaml").write_text(yaml.safe_dump(new_doc, allow_unicode=True), encoding="utf-8")

    svc.reload()
    assert received, "subscriber was not notified"
    assert received[-1] == ("1.0", "1.1")


def test_reload_no_version_change_no_notify(tmp_path: Path) -> None:
    src = (ONTOLOGY_DIR / "v1.0.yaml").read_text(encoding="utf-8")
    (tmp_path / "v1.0.yaml").write_text(src, encoding="utf-8")
    svc = OntologyService(tmp_path)
    count = {"n": 0}
    svc.subscribe(lambda old, new: count.__setitem__("n", count["n"] + 1))
    svc.reload()  # 没有新版本
    assert count["n"] == 0


def test_ontology_is_immutable(svc: OntologyService) -> None:
    """Ontology dataclass 是 frozen 的。"""
    onto = svc.get_current()
    with pytest.raises((AttributeError, Exception)):
        onto.version = "2.0"  # type: ignore[misc]
