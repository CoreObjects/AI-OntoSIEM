"""组件 3 宽容解析器单测。"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.ontology_service import OntologyService
from evolution.signal_hub import SignalHub
from parsers.windows_parser import (
    ParserConfig,
    WindowsParser,
    resolve_expr,
)
from storage.anomaly_pool import AnomalyPool


ROOT = Path(__file__).resolve().parents[1]


# -------- resolve_expr 纯函数测试 --------

def test_resolve_const() -> None:
    assert resolve_expr("const:hello", {}) == "hello"


def test_resolve_top_level() -> None:
    ev = {"computer": "WIN-01", "timestamp": "2026-04-20T10:00Z"}
    assert resolve_expr("@computer", ev) == "WIN-01"
    assert resolve_expr("@timestamp", ev) == "2026-04-20T10:00Z"


def test_resolve_event_data_nested() -> None:
    ev = {"event_data": {"Foo": "bar", "Baz": 42}}
    assert resolve_expr("event_data.Foo", ev) == "bar"
    assert resolve_expr("event_data.Baz", ev) == 42


def test_resolve_event_data_string_json() -> None:
    ev = {"event_data": json.dumps({"X": "y"})}
    assert resolve_expr("event_data.X", ev) == "y"


def test_resolve_missing_field_returns_none() -> None:
    ev = {"event_data": {"A": 1}}
    assert resolve_expr("event_data.Missing", ev) is None


def test_resolve_compose() -> None:
    ev = {"computer": "H1", "event_data": {"PID": "100"}}
    assert resolve_expr("compose:@computer|event_data.PID|const:x", ev) == "H1:100:x"


def test_resolve_compose_missing_part_returns_none() -> None:
    ev = {"computer": "H1"}
    assert resolve_expr("compose:@computer|event_data.Missing", ev) is None


# -------- Parser 核心行为 --------

@pytest.fixture()
def isolated_env(tmp_path: Path) -> dict:
    """每个测试用独立的 anomaly_pool / signal_hub / parsed_events.duckdb。"""
    svc = OntologyService(ROOT / "ontology")
    cfg = ParserConfig.load_all([ROOT / "parsers" / "mappings"])
    anomaly = AnomalyPool(tmp_path / "anomaly.duckdb")
    hub = SignalHub(tmp_path / "signals.duckdb")
    parser = WindowsParser(
        ontology=svc.get_current(),
        config=cfg,
        anomaly_pool=anomaly,
        signal_hub=hub,
    )
    return {"parser": parser, "anomaly": anomaly, "hub": hub, "svc": svc, "cfg": cfg}


def _mk_event(event_id: int, channel: str = "Security", **event_data) -> dict:
    return {
        "event_id": event_id,
        "channel": channel,
        "provider": "Microsoft-Windows-Security-Auditing",
        "record_number": 42,
        "timestamp": "2026-04-20T10:00:00Z",
        "computer": "TEST-HOST",
        "event_data": event_data,
    }


def test_parse_4624_creates_account_host_and_relations(isolated_env) -> None:
    parser = isolated_env["parser"]
    ev = _mk_event(
        4624,
        TargetUserSid="S-1-5-21-1-1001",
        TargetUserName="alice",
        TargetDomainName="CORP",
        LogonType="2",
    )
    result = parser.parse_event(ev)
    assert result.success
    node_types = {e.node_type for e in result.entities}
    assert node_types == {"Account", "Host"}
    rels = {r.edge_type for r in result.relations}
    assert rels == {"logged_into", "authenticated_as"}


def test_parse_4624_logon_type_attached_to_relation(isolated_env) -> None:
    parser = isolated_env["parser"]
    ev = _mk_event(4624, TargetUserSid="S-1-5-21-1-1001",
                   TargetUserName="alice", TargetDomainName="CORP", LogonType="3")
    result = parser.parse_event(ev)
    logged_into = [r for r in result.relations if r.edge_type == "logged_into"][0]
    assert logged_into.attrs["logon_type"] == "3"


def test_parse_4688_creates_process_host_account(isolated_env) -> None:
    parser = isolated_env["parser"]
    ev = _mk_event(
        4688,
        SubjectUserSid="S-1-5-21-1-1001", SubjectUserName="alice", SubjectDomainName="CORP",
        NewProcessId="0x1234", NewProcessName="C:\\Windows\\System32\\cmd.exe",
        CommandLine="cmd.exe", ProcessId="0x1111",
    )
    result = parser.parse_event(ev)
    assert result.success
    types = {e.node_type for e in result.entities}
    assert {"Process", "Host", "Account"}.issubset(types)
    rels = {r.edge_type for r in result.relations}
    assert "executed_on" in rels


def test_parse_4698_goes_to_anomaly_pool(isolated_env) -> None:
    """⭐ Demo 核心：ScheduledTask 事件本体 v1.0 未覆盖，必须进异常池。"""
    parser = isolated_env["parser"]
    anomaly = isolated_env["anomaly"]
    hub = isolated_env["hub"]
    ev = _mk_event(
        4698,
        SubjectUserSid="S-1-5-21-1-2001", SubjectUserName="svc_backup",
        TaskName="\\MS_Telemetry_Update",
        TaskContent="<Task>...</Task>",
    )
    result = parser.parse_event(ev)
    assert not result.success
    assert "no rule" in (result.failure_reason or "").lower()
    # 进异常池
    assert anomaly.size_open() == 1
    open_records = anomaly.list_by_event_id(4698)
    assert len(open_records) == 1
    assert open_records[0]["record_id"] == 42
    # 发出 unparseable_event 信号
    by_type = hub.count_by_type()
    assert by_type.get("unparseable_event") == 1


def test_parse_4702_also_to_anomaly_pool(isolated_env) -> None:
    parser = isolated_env["parser"]
    anomaly = isolated_env["anomaly"]
    ev = _mk_event(
        4702,
        SubjectUserSid="S-1-5-21-1-2001", SubjectUserName="svc_backup",
        TaskName="\\Windows Defender\\Windows Defender Update",
        TaskContent="<Task>...</Task>",
    )
    result = parser.parse_event(ev)
    assert not result.success
    assert anomaly.size_open() == 1


def test_parse_sysmon_1_creates_spawned_relation(isolated_env) -> None:
    parser = isolated_env["parser"]
    ev = {
        "event_id": 1,
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "provider": "Microsoft-Windows-Sysmon",
        "record_number": 99,
        "timestamp": "2026-04-20T10:00:00Z",
        "computer": "TEST-HOST",
        "event_data": {
            "ProcessId": "5555",
            "Image": "C:\\Windows\\cmd.exe",
            "CommandLine": "cmd.exe /c dir",
            "Hashes": "SHA256=" + "0" * 64,
            "ParentProcessId": "4444",
            "ParentImage": "C:\\Windows\\explorer.exe",
            "ParentCommandLine": "explorer.exe",
        },
    }
    result = parser.parse_event(ev)
    assert result.success
    rels = {r.edge_type for r in result.relations}
    assert "spawned" in rels
    assert "executed_on" in rels
    # spawned 的两端都是 Process
    spawned = [r for r in result.relations if r.edge_type == "spawned"][0]
    assert spawned.from_type == "Process"
    assert spawned.to_type == "Process"


def test_parser_subscribes_to_ontology_upgrades(tmp_path: Path) -> None:
    """本体升级后，parser 应该 hot reload 配置（订阅回调被触发）。"""
    import yaml as pyyaml
    # 独立本体目录
    src = (ROOT / "ontology" / "v1.0.yaml").read_text(encoding="utf-8")
    onto_dir = tmp_path / "ontology"
    onto_dir.mkdir()
    (onto_dir / "v1.0.yaml").write_text(src, encoding="utf-8")

    svc = OntologyService(onto_dir)
    cfg = ParserConfig.load_all([ROOT / "parsers" / "mappings"])
    anomaly = AnomalyPool(tmp_path / "anomaly.duckdb")
    hub = SignalHub(tmp_path / "signals.duckdb")
    parser = WindowsParser(ontology=svc.get_current(), config=cfg,
                           anomaly_pool=anomaly, signal_hub=hub)
    # 手动挂订阅（因为 parser 用 ontology=... 构造时不会自动订阅）
    svc.subscribe(parser._on_ontology_upgrade)

    doc = pyyaml.safe_load(src)
    doc["version"] = "1.1"
    (onto_dir / "v1.1.yaml").write_text(pyyaml.safe_dump(doc, allow_unicode=True), encoding="utf-8")
    svc.reload()

    assert parser._ontology.version == "1.1"


def test_parser_config_loads_from_yaml() -> None:
    cfg = ParserConfig.load_all([ROOT / "parsers" / "mappings"])
    assert cfg.lookup(4624, "Security") is not None
    assert cfg.lookup(4688, "Security") is not None
    assert cfg.lookup(1, "Microsoft-Windows-Sysmon/Operational") is not None
    # 4698 必须没有（演化锚点）
    assert cfg.lookup(4698, "Security") is None
    assert cfg.lookup(4702, "Security") is None
