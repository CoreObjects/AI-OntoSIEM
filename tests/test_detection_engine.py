"""组件 4 检测引擎单测（TDD 驱动开发）。"""
from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest

ROOT = Path(__file__).resolve().parents[1]


# =========================================================
# SigmaRule: YAML 加载
# =========================================================

def test_rule_from_yaml_minimal(tmp_path: Path) -> None:
    """最小合法 YAML 能加载为 SigmaRule。"""
    from detection.engine import SigmaRule

    yaml_path = tmp_path / "r.yaml"
    yaml_path.write_text(dedent("""
        id: "rule-001"
        title: "Test Rule"
        description: "A test"
        level: "high"
        logsource:
          channel: "Security"
          product: "windows"
        event_ids: [4624]
        detection:
          selection:
            EventData.LogonType: 2
          condition: "selection"
        tags: ["attack.t1078"]
    """).strip(), encoding="utf-8")

    rule = SigmaRule.from_yaml(yaml_path)

    assert rule.id == "rule-001"
    assert rule.title == "Test Rule"
    assert rule.level == "high"
    assert rule.channel == "Security"
    assert rule.event_ids == [4624]
    assert rule.attack_techniques == ["T1078"]


# =========================================================
# SigmaRule.matches: 字段匹配（selection 子集）
# =========================================================

def _make_rule(selection: dict, event_ids=(4624,), channel="Security") -> "SigmaRule":
    from detection.engine import SigmaRule
    return SigmaRule(
        id="r", title="t", description="", level="medium",
        channel=channel, event_ids=list(event_ids),
        attack_techniques=["T1078"],
        selection=selection,
    )


def _ev(event_id=4624, channel="Security", event_data=None) -> dict:
    return {
        "event_id": event_id,
        "channel": channel,
        "computer": "H1",
        "record_number": 1,
        "timestamp": "2026-04-22T10:00:00Z",
        "event_data": event_data or {},
    }


def test_match_scalar_equal() -> None:
    rule = _make_rule({"EventData.LogonType": 2})
    assert rule.matches(_ev(event_data={"LogonType": 2})) is True
    assert rule.matches(_ev(event_data={"LogonType": 3})) is False


def test_match_list_means_or() -> None:
    rule = _make_rule({"EventData.LogonType": [2, 10]})
    assert rule.matches(_ev(event_data={"LogonType": 2})) is True
    assert rule.matches(_ev(event_data={"LogonType": 10})) is True
    assert rule.matches(_ev(event_data={"LogonType": 3})) is False


def test_match_missing_field_no_match() -> None:
    rule = _make_rule({"EventData.LogonType": 2})
    assert rule.matches(_ev(event_data={"Other": 1})) is False


def test_match_event_id_filter() -> None:
    rule = _make_rule({"EventData.LogonType": 2}, event_ids=(4624,))
    assert rule.matches(_ev(event_id=4625, event_data={"LogonType": 2})) is False


def test_match_channel_filter() -> None:
    rule = _make_rule({"EventData.LogonType": 2}, channel="Security")
    ev = _ev(event_data={"LogonType": 2})
    ev["channel"] = "System"
    assert rule.matches(ev) is False


def test_match_modifier_endswith() -> None:
    rule = _make_rule({"EventData.TargetUserName|endswith": "$"})
    assert rule.matches(_ev(event_data={"TargetUserName": "DC-01$"})) is True
    assert rule.matches(_ev(event_data={"TargetUserName": "alice"})) is False


def test_match_modifier_contains_case_insensitive() -> None:
    rule = _make_rule({"EventData.CommandLine|contains": "whoami"})
    assert rule.matches(_ev(event_data={"CommandLine": "cmd.exe /c WHOAMI /all"})) is True
    assert rule.matches(_ev(event_data={"CommandLine": "notepad.exe"})) is False


def test_match_modifier_startswith() -> None:
    rule = _make_rule({"EventData.Image|startswith": "C:\\Windows\\Temp\\"})
    assert rule.matches(_ev(event_data={"Image": "C:\\Windows\\Temp\\x.exe"})) is True
    assert rule.matches(_ev(event_data={"Image": "C:\\Program Files\\x.exe"})) is False


def test_match_all_selection_keys_must_match() -> None:
    """selection 下多个键 → AND。"""
    rule = _make_rule({
        "EventData.LogonType": 3,
        "EventData.TargetUserName|endswith": "$",
    })
    assert rule.matches(_ev(event_data={"LogonType": 3, "TargetUserName": "DC-01$"})) is True
    assert rule.matches(_ev(event_data={"LogonType": 3, "TargetUserName": "alice"})) is False
    assert rule.matches(_ev(event_data={"LogonType": 2, "TargetUserName": "DC-01$"})) is False


def test_match_top_level_field() -> None:
    """@computer / @timestamp 顶层字段也能匹配。"""
    rule = _make_rule({"@computer|endswith": "-SRV-01"})
    ev = _ev()
    ev["computer"] = "FIN-SRV-01"
    assert rule.matches(ev) is True
    ev["computer"] = "WIN-WKS-99"
    assert rule.matches(ev) is False


# =========================================================
# DetectionEngine: 规则加载 + 事件求值 + 告警产出
# =========================================================

def _write_rule(dir_: Path, filename: str, body: str) -> Path:
    p = dir_ / filename
    p.write_text(dedent(body).strip(), encoding="utf-8")
    return p


def test_engine_load_rules_from_dir(tmp_path: Path) -> None:
    from detection.engine import DetectionEngine

    _write_rule(tmp_path, "a.yaml", """
        id: "r-a"
        title: "A"
        description: "a"
        level: "medium"
        logsource: {channel: "Security"}
        event_ids: [4624]
        detection:
          selection:
            EventData.LogonType: 2
          condition: "selection"
        tags: ["attack.t1078"]
    """)
    _write_rule(tmp_path, "b.yaml", """
        id: "r-b"
        title: "B"
        description: "b"
        level: "high"
        logsource: {channel: "Security"}
        event_ids: [4625]
        detection:
          selection:
            EventData.LogonType: 3
          condition: "selection"
        tags: ["attack.t1110"]
    """)

    eng = DetectionEngine(rules_dir=tmp_path, ontology=None, signal_hub=None)
    assert len(eng.rules) == 2
    ids = {r.id for r in eng.rules}
    assert ids == {"r-a", "r-b"}


def test_engine_evaluate_event_returns_alert(tmp_path: Path) -> None:
    from detection.engine import DetectionEngine

    _write_rule(tmp_path, "a.yaml", """
        id: "r-a"
        title: "Interactive Logon"
        description: "x"
        level: "high"
        logsource: {channel: "Security"}
        event_ids: [4624]
        detection:
          selection:
            EventData.LogonType: 2
          condition: "selection"
        tags: ["attack.t1078"]
    """)

    eng = DetectionEngine(rules_dir=tmp_path, ontology=None, signal_hub=None)
    ev = _ev(event_data={"LogonType": 2})
    alerts = eng.evaluate_event(ev)

    assert len(alerts) == 1
    a = alerts[0]
    assert a.rule_id == "r-a"
    assert a.rule_title == "Interactive Logon"
    assert a.severity == "high"
    assert a.event_id == 4624
    assert a.computer == "H1"
    assert a.attack_techniques == ["T1078"]
    assert a.matched_fields == {"EventData.LogonType": 2}
    assert a.alert_id  # 非空字符串


def test_engine_no_match_returns_empty(tmp_path: Path) -> None:
    from detection.engine import DetectionEngine

    _write_rule(tmp_path, "a.yaml", """
        id: "r-a"
        title: "t"
        description: "x"
        level: "low"
        logsource: {channel: "Security"}
        event_ids: [4624]
        detection:
          selection: {EventData.LogonType: 2}
          condition: "selection"
        tags: []
    """)
    eng = DetectionEngine(rules_dir=tmp_path, ontology=None, signal_hub=None)
    assert eng.evaluate_event(_ev(event_data={"LogonType": 99})) == []


def test_engine_multiple_rules_hit_same_event(tmp_path: Path) -> None:
    from detection.engine import DetectionEngine

    _write_rule(tmp_path, "a.yaml", """
        id: "r-a"
        title: "a"
        description: "x"
        level: "high"
        logsource: {channel: "Security"}
        event_ids: [4624]
        detection: {selection: {EventData.LogonType: 2}, condition: "selection"}
        tags: ["attack.t1078"]
    """)
    _write_rule(tmp_path, "b.yaml", """
        id: "r-b"
        title: "b"
        description: "x"
        level: "medium"
        logsource: {channel: "Security"}
        event_ids: [4624]
        detection: {selection: {EventData.TargetUserName|endswith: "$"}, condition: "selection"}
        tags: ["attack.t1078"]
    """)

    eng = DetectionEngine(rules_dir=tmp_path, ontology=None, signal_hub=None)
    alerts = eng.evaluate_event(_ev(event_data={"LogonType": 2, "TargetUserName": "DC-01$"}))
    assert len(alerts) == 2
    assert {a.rule_id for a in alerts} == {"r-a", "r-b"}


# =========================================================
# 本体校验：ontology_refs 缺失 → rule_schema_mismatch 信号
# =========================================================

class _FakeOntology:
    def __init__(self, nodes, edges, version="1.0"):
        self.version = version
        self._nodes = set(nodes)
        self._edges = set(edges)

    def has_node(self, n: str) -> bool:
        return n in self._nodes

    def has_edge(self, e: str) -> bool:
        return e in self._edges


class _FakeSignalHub:
    def __init__(self):
        self.calls = []

    def report_signal(self, source_layer, signal_type, payload, **kw):
        self.calls.append({
            "source_layer": source_layer,
            "signal_type": signal_type,
            "payload": payload,
            **kw,
        })


def test_engine_ontology_refs_all_present_no_signal(tmp_path: Path) -> None:
    from detection.engine import DetectionEngine

    _write_rule(tmp_path, "a.yaml", """
        id: "r-ok"
        title: "ok"
        description: "x"
        level: "low"
        logsource: {channel: "Security"}
        event_ids: [4624]
        detection: {selection: {EventData.LogonType: 2}, condition: "selection"}
        tags: ["attack.t1078"]
        ontology_refs:
          nodes: [Account, Host]
          edges: [logged_into]
    """)
    onto = _FakeOntology(nodes={"Account", "Host"}, edges={"logged_into"})
    hub = _FakeSignalHub()
    DetectionEngine(rules_dir=tmp_path, ontology=onto, signal_hub=hub)
    assert hub.calls == []


def test_engine_ontology_missing_node_emits_signal(tmp_path: Path) -> None:
    from detection.engine import DetectionEngine

    _write_rule(tmp_path, "a.yaml", """
        id: "r-bad-node"
        title: "bad"
        description: "x"
        level: "low"
        logsource: {channel: "Security"}
        event_ids: [4624]
        detection: {selection: {EventData.LogonType: 2}, condition: "selection"}
        tags: ["attack.t1078"]
        ontology_refs:
          nodes: [ScheduledTask]
    """)
    onto = _FakeOntology(nodes={"Account", "Host"}, edges={"logged_into"})
    hub = _FakeSignalHub()
    DetectionEngine(rules_dir=tmp_path, ontology=onto, signal_hub=hub)

    assert len(hub.calls) == 1
    c = hub.calls[0]
    assert c["source_layer"] == "detection"
    assert c["signal_type"] == "rule_schema_mismatch"
    assert c["payload"]["rule_id"] == "r-bad-node"
    assert "ScheduledTask" in c["payload"]["missing_nodes"]


def test_engine_ontology_missing_edge_emits_signal(tmp_path: Path) -> None:
    from detection.engine import DetectionEngine

    _write_rule(tmp_path, "a.yaml", """
        id: "r-bad-edge"
        title: "bad edge"
        description: "x"
        level: "low"
        logsource: {channel: "Security"}
        event_ids: [4688]
        detection: {selection: {EventData.Image|endswith: "x.exe"}, condition: "selection"}
        tags: ["attack.t1053"]
        ontology_refs:
          nodes: [Process]
          edges: [scheduled_by]
    """)
    onto = _FakeOntology(nodes={"Process", "Host"}, edges={"spawned"})
    hub = _FakeSignalHub()
    DetectionEngine(rules_dir=tmp_path, ontology=onto, signal_hub=hub)

    assert len(hub.calls) == 1
    c = hub.calls[0]
    assert c["signal_type"] == "rule_schema_mismatch"
    assert "scheduled_by" in c["payload"]["missing_edges"]


def test_engine_ontology_missing_still_loads_rule(tmp_path: Path) -> None:
    """本体缺失不阻断规则加载（降级），规则仍然可评估。"""
    from detection.engine import DetectionEngine

    _write_rule(tmp_path, "a.yaml", """
        id: "r-bad"
        title: "bad"
        description: "x"
        level: "low"
        logsource: {channel: "Security"}
        event_ids: [4624]
        detection: {selection: {EventData.LogonType: 2}, condition: "selection"}
        tags: []
        ontology_refs:
          nodes: [NonExistent]
    """)
    eng = DetectionEngine(
        rules_dir=tmp_path,
        ontology=_FakeOntology(nodes={"Account"}, edges=set()),
        signal_hub=_FakeSignalHub(),
    )
    assert len(eng.rules) == 1
    alerts = eng.evaluate_event(_ev(event_data={"LogonType": 2}))
    assert len(alerts) == 1


def test_engine_evaluate_batch(tmp_path: Path) -> None:
    from detection.engine import DetectionEngine

    _write_rule(tmp_path, "a.yaml", """
        id: "r-a"
        title: "a"
        description: "x"
        level: "low"
        logsource: {channel: "Security"}
        event_ids: [4624]
        detection: {selection: {EventData.LogonType: 2}, condition: "selection"}
        tags: []
    """)
    eng = DetectionEngine(rules_dir=tmp_path, ontology=None, signal_hub=None)
    events = [
        _ev(event_data={"LogonType": 2}),
        _ev(event_data={"LogonType": 3}),
        _ev(event_data={"LogonType": 2}),
    ]
    alerts = eng.evaluate_batch(events)
    assert len(alerts) == 2


# =========================================================
# 生产规则集：detection/rules/*.yaml
# =========================================================

PROD_RULES_DIR = ROOT / "detection" / "rules"


def test_production_rules_count() -> None:
    """至少 6 条规则覆盖攻击链（task_plan 组件 4 要求 6-8 条）。"""
    from detection.engine import DetectionEngine
    eng = DetectionEngine(rules_dir=PROD_RULES_DIR, ontology=None, signal_hub=None)
    assert 6 <= len(eng.rules) <= 8, f"expected 6-8 rules, got {len(eng.rules)}"


def test_production_rules_cover_attack_chain() -> None:
    """每条规则都带 ATT&CK 标签；全集覆盖 T1003/T1078/T1021/T1059/T1570/T1055。"""
    from detection.engine import DetectionEngine
    eng = DetectionEngine(rules_dir=PROD_RULES_DIR, ontology=None, signal_hub=None)
    covered: set[str] = set()
    for r in eng.rules:
        assert r.attack_techniques, f"rule {r.id} has no attack tag"
        covered.update(r.attack_techniques)
    required = {"T1003", "T1078", "T1021", "T1059", "T1570", "T1055"}
    missing = required - covered
    assert not missing, f"attack techniques not covered by rules: {missing}"


def test_production_rule_r1_lsass_dump_hits() -> None:
    """R1 LSASS dump：Sysmon 10 TargetImage=lsass.exe + 危险 GrantedAccess。"""
    from detection.engine import DetectionEngine
    eng = DetectionEngine(rules_dir=PROD_RULES_DIR, ontology=None, signal_hub=None)
    malicious = {
        "event_id": 10,
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "computer": "HR-WS-01",
        "record_number": 1,
        "timestamp": "2026-04-16T03:45:03Z",
        "event_data": {
            "SourceImage": "C:\\Windows\\Temp\\procdump.exe",
            "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "GrantedAccess": "0x1410",
        },
    }
    alerts = eng.evaluate_event(malicious)
    assert any("T1003" in a.attack_techniques for a in alerts), f"no T1003 match: {[a.rule_id for a in alerts]}"


def test_production_rule_r2_service_account_from_workstation_hits() -> None:
    """R2 服务账户从工作站子网做网络登录。"""
    from detection.engine import DetectionEngine
    eng = DetectionEngine(rules_dir=PROD_RULES_DIR, ontology=None, signal_hub=None)
    malicious = {
        "event_id": 4624,
        "channel": "Security",
        "computer": "FIN-SRV-01",
        "record_number": 2,
        "timestamp": "2026-04-17T10:12:00Z",
        "event_data": {
            "TargetUserName": "svc_backup",
            "TargetDomainName": "CORP",
            "LogonType": "3",
            "IpAddress": "10.0.3.31",
            "LogonProcessName": "NtLmSsp",
            "AuthenticationPackageName": "NTLM",
        },
    }
    alerts = eng.evaluate_event(malicious)
    assert any("T1078" in a.attack_techniques for a in alerts), f"no T1078 match: {[a.rule_id for a in alerts]}"


def test_production_rule_r3_smb_lateral_hits() -> None:
    """R3 SMB/NTLM 横向移动：工作站 → 服务器。"""
    from detection.engine import DetectionEngine
    eng = DetectionEngine(rules_dir=PROD_RULES_DIR, ontology=None, signal_hub=None)
    malicious = {
        "event_id": 4624,
        "channel": "Security",
        "computer": "FIN-SRV-01",
        "record_number": 3,
        "timestamp": "2026-04-17T10:12:00Z",
        "event_data": {
            "TargetUserName": "svc_backup",
            "LogonType": "3",
            "LogonProcessName": "NtLmSsp",
            "AuthenticationPackageName": "NTLM",
            "IpAddress": "10.0.3.31",
        },
    }
    alerts = eng.evaluate_event(malicious)
    assert any("T1021" in a.attack_techniques for a in alerts), f"no T1021 match: {[a.rule_id for a in alerts]}"


def test_production_rule_r4_encoded_powershell_hits() -> None:
    """R4 可疑 PowerShell：-enc / -EncodedCommand。"""
    from detection.engine import DetectionEngine
    eng = DetectionEngine(rules_dir=PROD_RULES_DIR, ontology=None, signal_hub=None)
    malicious = {
        "event_id": 1,
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "computer": "HR-WS-01",
        "record_number": 4,
        "timestamp": "2026-04-15T14:23:01Z",
        "event_data": {
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4A...",
            "ParentImage": "C:\\Windows\\explorer.exe",
        },
    }
    alerts = eng.evaluate_event(malicious)
    assert any("T1059" in a.attack_techniques for a in alerts), f"no T1059 match: {[a.rule_id for a in alerts]}"


def test_production_rule_r5_admin_share_write_hits() -> None:
    """R5 管理员共享文件写入（T1570 横向工具传输）。"""
    from detection.engine import DetectionEngine
    eng = DetectionEngine(rules_dir=PROD_RULES_DIR, ontology=None, signal_hub=None)
    malicious = {
        "event_id": 5145,
        "channel": "Security",
        "computer": "FIN-SRV-01",
        "record_number": 5,
        "timestamp": "2026-04-19T02:30:02Z",
        "event_data": {
            "ShareName": "\\\\FIN-SRV-01\\C$",
            "RelativeTargetName": "Windows\\Temp\\tools.zip",
            "AccessMask": "0x2",
            "IpAddress": "10.0.3.31",
            "SubjectUserName": "svc_backup",
        },
    }
    alerts = eng.evaluate_event(malicious)
    assert any("T1570" in a.attack_techniques for a in alerts), f"no T1570 match: {[a.rule_id for a in alerts]}"


def test_production_rule_r6_remote_thread_injection_hits() -> None:
    """R6 远程线程注入（Sysmon 8）。"""
    from detection.engine import DetectionEngine
    eng = DetectionEngine(rules_dir=PROD_RULES_DIR, ontology=None, signal_hub=None)
    malicious = {
        "event_id": 8,
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "computer": "FIN-SRV-01",
        "record_number": 6,
        "timestamp": "2026-04-21T03:00:08Z",
        "event_data": {
            "SourceImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "TargetImage": "C:\\Windows\\explorer.exe",
        },
    }
    alerts = eng.evaluate_event(malicious)
    assert any("T1055" in a.attack_techniques for a in alerts), f"no T1055 match: {[a.rule_id for a in alerts]}"


def test_production_rules_no_false_positive_on_benign() -> None:
    """正常日志不应触发任何规则。"""
    from detection.engine import DetectionEngine
    eng = DetectionEngine(rules_dir=PROD_RULES_DIR, ontology=None, signal_hub=None)
    benign_events = [
        # 用户本地交互登录
        {
            "event_id": 4624, "channel": "Security", "computer": "HR-WS-01",
            "record_number": 100, "timestamp": "2026-04-17T09:00:00Z",
            "event_data": {
                "TargetUserName": "alice", "TargetDomainName": "CORP",
                "LogonType": "2", "IpAddress": "127.0.0.1",
                "LogonProcessName": "User32", "AuthenticationPackageName": "Negotiate",
            },
        },
        # SCCM 服务账户正常盘点（从 10.0.1.5 基础设施子网）
        {
            "event_id": 4624, "channel": "Security", "computer": "HR-WS-01",
            "record_number": 101, "timestamp": "2026-04-17T12:00:00Z",
            "event_data": {
                "TargetUserName": "svc_sccm", "TargetDomainName": "CORP",
                "LogonType": "3", "IpAddress": "10.0.1.5",
                "LogonProcessName": "NtLmSsp", "AuthenticationPackageName": "NTLM",
            },
        },
        # 合法 Office 应用启动
        {
            "event_id": 1, "channel": "Microsoft-Windows-Sysmon/Operational",
            "computer": "HR-WS-01", "record_number": 102, "timestamp": "2026-04-17T09:15:00Z",
            "event_data": {
                "Image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
                "CommandLine": '"C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE"',
                "ParentImage": "C:\\Windows\\explorer.exe",
            },
        },
        # 合法 Defender 访问 lsass（Windows 安全产品常态行为）
        {
            "event_id": 10, "channel": "Microsoft-Windows-Sysmon/Operational",
            "computer": "HR-WS-01", "record_number": 103, "timestamp": "2026-04-17T09:30:00Z",
            "event_data": {
                "SourceImage": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\MsMpEng.exe",
                "TargetImage": "C:\\Windows\\System32\\lsass.exe",
                "GrantedAccess": "0x1000",
            },
        },
    ]
    alerts = eng.evaluate_batch(benign_events)
    assert alerts == [], f"false positives: {[(a.rule_id, a.event_record_id) for a in alerts]}"
