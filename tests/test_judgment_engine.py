"""组件 6 认知推理层：judgment_engine 单测（TDD）。

策略：用 FakeLLMClient 注入 structured_json 返回值，避免打真实 Qwen API。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

import pytest


# =========================================================
# Fakes
# =========================================================

class FakeLLMClient:
    """记录 structured_json 的调用参数并返回预设响应。"""

    def __init__(self, response: Optional[Dict[str, Any]] = None):
        self._response = response or {
            "verdict": "suspicious",
            "confidence": 0.75,
            "reasoning_steps": ["step 1", "step 2"],
            "evidence_refs": [{"type": "matched_field", "ref": "EventData.LogonType"}],
            "attack_chain": ["T1078"],
            "next_steps": ["isolate host"],
        }
        self.calls: List[Dict[str, Any]] = []

    def structured_json(
        self, system: str, user: str, *,
        required_keys=(), validator=None,
        max_tokens=2048, temperature=0.1, max_retries=2,
    ) -> Dict[str, Any]:
        self.calls.append({
            "system": system, "user": user,
            "required_keys": set(required_keys),
        })
        missing = set(required_keys) - set(self._response.keys())
        if missing:
            raise RuntimeError(f"fake client response missing required {missing}")
        if validator is not None:
            err = validator(self._response)
            if err is not None:
                raise RuntimeError(f"validator failed in fake: {err}")
        return dict(self._response)


class FakeSignalHub:
    def __init__(self):
        self.calls: List[Dict[str, Any]] = []

    def report_signal(self, source_layer, signal_type, payload, **kw):
        self.calls.append({"source_layer": source_layer,
                           "signal_type": signal_type,
                           "payload": payload, **kw})


def _make_alert(record_number=1, computer="HR-WS-01", event_id=4624,
                matched_fields=None):
    from detection.engine import Alert
    return Alert(
        alert_id="al-1",
        rule_id="r2-anomalous-service-account-logon",
        rule_title="Service Account Network Logon From Workstation Subnet",
        severity="high",
        event_record_id=record_number,
        event_id=event_id,
        channel="Security",
        computer=computer,
        timestamp="2026-04-17T10:12:00Z",
        attack_techniques=["T1078"],
        matched_fields=matched_fields or {"EventData.LogonType": "3",
                                          "EventData.TargetUserName": "svc_backup"},
        ontology_version="1.0",
        raw_event={"event_id": event_id, "event_data": {"LogonType": "3"}},
    )


def _make_graph_with_attack():
    from graph.store import GraphStore
    g = GraphStore(ontology_version="1.0")
    ts = "2026-04-17T10:12:00Z"
    g.upsert_entity("Account", "S-1-5-21-1-2001",
                    attrs={"sid": "S-1-5-21-1-2001", "username": "svc_backup"},
                    timestamp=ts, source="log")
    g.upsert_entity("Host", "HR-WS-01",
                    attrs={"hostname": "HR-WS-01"},
                    timestamp=ts, source="log")
    g.upsert_entity("Host", "FIN-SRV-01",
                    attrs={"hostname": "FIN-SRV-01"},
                    timestamp=ts, source="log")
    g.upsert_relation("logged_into",
                      "Account", "S-1-5-21-1-2001",
                      "Host", "HR-WS-01",
                      timestamp=ts, source="log", attrs={"logon_type": "3"})
    g.upsert_relation("logged_into",
                      "Account", "S-1-5-21-1-2001",
                      "Host", "FIN-SRV-01",
                      timestamp=ts, source="log", attrs={"logon_type": "3"})
    return g


# =========================================================
# Judgment dataclass + engine 骨架
# =========================================================

def test_judgment_dataclass_has_required_fields() -> None:
    from reasoning.judgment_engine import Judgment
    j = Judgment(
        judgment_id="j-1", alert_id="al-1",
        verdict="suspicious", confidence=0.75,
        reasoning_steps=["s1"], evidence_refs=[{"type": "matched_field", "ref": "x"}],
        attack_chain=["T1078"], next_steps=["n1"],
        ontology_version="1.0",
    )
    assert j.semantic_gap is None
    assert j.needs_review is False


def test_judge_returns_judgment_with_verdict() -> None:
    from reasoning.judgment_engine import JudgmentEngine

    alert = _make_alert()
    g = _make_graph_with_attack()
    hub = FakeSignalHub()
    llm = FakeLLMClient()

    engine = JudgmentEngine(llm=llm, graph=g, signal_hub=hub)
    j = engine.judge(alert)

    assert j.alert_id == "al-1"
    assert j.verdict == "suspicious"
    assert j.confidence == 0.75
    assert j.attack_chain == ["T1078"]
    assert j.ontology_version == "1.0"


def test_judge_prompt_includes_alert_and_subgraph() -> None:
    """prompt 必须把 alert matched_fields 和 graph 子图一起塞进去给 LLM。"""
    from reasoning.judgment_engine import JudgmentEngine

    alert = _make_alert()
    g = _make_graph_with_attack()
    llm = FakeLLMClient()

    engine = JudgmentEngine(llm=llm, graph=g, signal_hub=FakeSignalHub())
    engine.judge(alert)

    assert len(llm.calls) == 1
    user_prompt = llm.calls[0]["user"]
    # alert 关键字段
    assert "r2-anomalous-service-account-logon" in user_prompt
    assert "T1078" in user_prompt
    # 子图关键节点（center = alert.computer=HR-WS-01，2 跳拉出 svc_backup）
    assert "svc_backup" in user_prompt or "S-1-5-21-1-2001" in user_prompt
    assert "HR-WS-01" in user_prompt


def test_judge_prompt_injects_ontology_vocabulary() -> None:
    """system prompt 要把当前本体的节点/边类型注入作为概念词汇表。"""
    from reasoning.judgment_engine import JudgmentEngine

    class FakeOnto:
        version = "1.0"
        nodes = {"User": {}, "Account": {}, "Host": {}, "Process": {}, "NetworkEndpoint": {}}
        edges = {"owns": {}, "authenticated_as": {}, "logged_into": {},
                 "spawned": {}, "executed_on": {}, "connected_to": {}}

    alert = _make_alert()
    g = _make_graph_with_attack()
    llm = FakeLLMClient()

    engine = JudgmentEngine(llm=llm, graph=g, signal_hub=FakeSignalHub(), ontology=FakeOnto())
    engine.judge(alert)

    sys_prompt = llm.calls[0]["system"]
    assert "Account" in sys_prompt
    assert "logged_into" in sys_prompt


def test_judge_subgraph_empty_when_host_not_in_graph() -> None:
    """alert.computer 对应的 Host 不在图里 → 子图为空，judgment 仍能产出。"""
    from graph.store import GraphStore
    from reasoning.judgment_engine import JudgmentEngine

    alert = _make_alert(computer="UNKNOWN-HOST")
    g = GraphStore(ontology_version="1.0")
    llm = FakeLLMClient()

    engine = JudgmentEngine(llm=llm, graph=g, signal_hub=FakeSignalHub())
    j = engine.judge(alert)
    assert j is not None
    # prompt 里应显式标注 "subgraph empty"
    assert "empty" in llm.calls[0]["user"].lower() or "no subgraph" in llm.calls[0]["user"].lower()


# =========================================================
# 低 confidence / semantic_gap 支路
# =========================================================

def test_low_confidence_marks_needs_review() -> None:
    from reasoning.judgment_engine import JudgmentEngine

    alert = _make_alert()
    g = _make_graph_with_attack()
    llm = FakeLLMClient(response={
        "verdict": "unknown",
        "confidence": 0.3,                    # < 0.5
        "reasoning_steps": ["不确定"],
        "evidence_refs": [{"type": "matched_field", "ref": "EventData.LogonType"}],
        "attack_chain": [],
        "next_steps": ["人工核查"],
    })
    engine = JudgmentEngine(llm=llm, graph=g, signal_hub=FakeSignalHub())
    j = engine.judge(alert)
    assert j.needs_review is True


def test_high_confidence_no_review() -> None:
    from reasoning.judgment_engine import JudgmentEngine

    alert = _make_alert()
    g = _make_graph_with_attack()
    engine = JudgmentEngine(llm=FakeLLMClient(), graph=g, signal_hub=FakeSignalHub())
    j = engine.judge(alert)
    assert j.needs_review is False  # 默认 confidence=0.75


def test_semantic_gap_emits_signal() -> None:
    from reasoning.judgment_engine import JudgmentEngine

    # 4698 Scheduled Task 规则（若存在）会匹配 TaskName；此处模拟那种 matched_fields
    alert = _make_alert(
        event_id=4698,
        matched_fields={"EventData.TaskName": "\\Microsoft\\Windows\\MS_Telemetry_Update"},
    )
    g = _make_graph_with_attack()
    hub = FakeSignalHub()
    llm = FakeLLMClient(response={
        "verdict": "suspicious",
        "confidence": 0.6,
        "reasoning_steps": ["看到 4698 计划任务创建，但本体没有 ScheduledTask 节点"],
        "evidence_refs": [{"type": "matched_field", "ref": "EventData.TaskName"}],
        "attack_chain": ["T1053"],
        "next_steps": ["扩展本体"],
        "semantic_gap": {
            "description": "本体缺少 ScheduledTask 概念，无法建模 T1053 持久化",
            "missing_concept": "ScheduledTask",
        },
    })
    engine = JudgmentEngine(llm=llm, graph=g, signal_hub=hub)
    j = engine.judge(alert)

    assert j.semantic_gap is not None
    assert len(hub.calls) == 1
    sig = hub.calls[0]
    assert sig["source_layer"] == "reasoning"
    assert sig["signal_type"] == "semantic_gap"
    assert "ScheduledTask" in str(sig["payload"])


def test_no_semantic_gap_no_signal() -> None:
    from reasoning.judgment_engine import JudgmentEngine

    alert = _make_alert()
    g = _make_graph_with_attack()
    hub = FakeSignalHub()
    engine = JudgmentEngine(llm=FakeLLMClient(), graph=g, signal_hub=hub)
    engine.judge(alert)
    assert hub.calls == []


# =========================================================
# 严格 evidence_refs 校验（反幻觉闸门二）
# =========================================================

def test_evidence_ref_matched_field_must_exist_on_alert() -> None:
    """LLM 编造一个 matched_field ref，研判应失败（LLM validator 应抛错，judge 应传播）。"""
    from reasoning.judgment_engine import JudgmentEngine

    alert = _make_alert(matched_fields={"EventData.LogonType": "3"})
    g = _make_graph_with_attack()

    # LLM 返回一个不存在的字段
    bogus_llm = FakeLLMClient(response={
        "verdict": "malicious",
        "confidence": 0.9,
        "reasoning_steps": ["hallucinated"],
        "evidence_refs": [{"type": "matched_field", "ref": "EventData.DoesNotExist"}],
        "attack_chain": ["T1078"],
        "next_steps": [],
    })
    engine = JudgmentEngine(llm=bogus_llm, graph=g, signal_hub=FakeSignalHub())
    with pytest.raises(RuntimeError, match="validator"):
        engine.judge(alert)


def test_evidence_ref_graph_node_must_exist() -> None:
    from reasoning.judgment_engine import JudgmentEngine

    alert = _make_alert()
    g = _make_graph_with_attack()

    bogus_llm = FakeLLMClient(response={
        "verdict": "malicious",
        "confidence": 0.9,
        "reasoning_steps": ["..."],
        "evidence_refs": [{"type": "graph_node",
                           "ref": "Account:S-1-FAKE-DOES-NOT-EXIST"}],
        "attack_chain": ["T1078"],
        "next_steps": [],
    })
    engine = JudgmentEngine(llm=bogus_llm, graph=g, signal_hub=FakeSignalHub())
    with pytest.raises(RuntimeError, match="validator"):
        engine.judge(alert)


def test_judge_subgraph_caps_process_count_at_default_limit() -> None:
    """默认保留 Process，但限量（避免 token 爆炸）：100 个 Process 只保留最近 8 个。"""
    from graph.store import GraphStore
    from reasoning.judgment_engine import JudgmentEngine

    g = GraphStore(ontology_version="1.0")
    g.upsert_entity("Host", "HR-WS-01", attrs={"hostname": "HR-WS-01"},
                    timestamp="2026-04-17T10:00:00Z", source="log")
    g.upsert_entity("Account", "S-1-5-21-1-1001",
                    attrs={"sid": "S-1-5-21-1-1001"},
                    timestamp="2026-04-17T10:00:00Z", source="log")
    # 100 个 Process 按时间递增（越后越新）
    for i in range(100):
        ts = f"2026-04-17T10:{i:02d}:00Z" if i < 60 else f"2026-04-17T11:{i-60:02d}:00Z"
        pkey = f"HR-WS-01::proc{i:03d}::{ts}"
        g.upsert_entity("Process", pkey,
                        attrs={"pid": str(i), "image_name": f"proc{i:03d}.exe"},
                        timestamp=ts, source="log")
        g.upsert_relation("executed_on", "Process", pkey, "Host", "HR-WS-01",
                          timestamp=ts, source="log")
    g.upsert_relation("logged_into", "Account", "S-1-5-21-1-1001",
                      "Host", "HR-WS-01",
                      timestamp="2026-04-17T10:00:00Z", source="log")

    llm = FakeLLMClient()
    engine = JudgmentEngine(llm=llm, graph=g, signal_hub=FakeSignalHub())
    engine.judge(_make_alert(computer="HR-WS-01"))

    user_prompt = llm.calls[0]["user"]
    # 最新 8 个（proc092..proc099）应出现
    assert "proc099.exe" in user_prompt
    assert "proc092.exe" in user_prompt
    # 早期的应被裁掉
    assert "proc000.exe" not in user_prompt
    assert "proc050.exe" not in user_prompt
    # Account / Host 仍应出现
    assert "S-1-5-21-1-1001" in user_prompt
    assert "HR-WS-01" in user_prompt


def test_judge_subgraph_limits_process_count_top_n_by_recency() -> None:
    """Process 默认按 last_seen desc 取 top-N（避免 token 爆炸）。"""
    from graph.store import GraphStore
    from reasoning.judgment_engine import JudgmentEngine

    g = GraphStore(ontology_version="1.0")
    g.upsert_entity("Host", "HR-WS-01", attrs={"hostname": "HR-WS-01"},
                    timestamp="2026-04-17T10:12:00Z", source="log")
    # 20 个 Process，时间戳递增（编号越大越新）
    for i in range(20):
        ts = f"2026-04-17T10:{10 + i:02d}:00Z"
        pkey = f"HR-WS-01::proc{i}::{ts}"
        g.upsert_entity("Process", pkey,
                        attrs={"pid": str(i), "image_name": f"proc{i}.exe"},
                        timestamp=ts, source="log")
        g.upsert_relation("executed_on", "Process", pkey, "Host", "HR-WS-01",
                          timestamp=ts, source="log")

    llm = FakeLLMClient()
    engine = JudgmentEngine(
        llm=llm, graph=g, signal_hub=FakeSignalHub(),
        max_nodes_per_type={"Process": 5},
    )
    engine.judge(_make_alert(computer="HR-WS-01"))

    prompt = llm.calls[0]["user"]
    # 最新 5 个（proc15..proc19）应出现
    assert "proc19.exe" in prompt
    assert "proc15.exe" in prompt
    # 早期的不应出现
    assert "proc0.exe" not in prompt
    assert "proc5.exe" not in prompt


def test_judge_subgraph_include_types_configurable() -> None:
    """subgraph_node_types 参数可定制保留的类型。"""
    from graph.store import GraphStore
    from reasoning.judgment_engine import JudgmentEngine

    ts = "2026-04-17T10:12:00Z"
    g = GraphStore(ontology_version="1.0")
    g.upsert_entity("Host", "HR-WS-01", attrs={"hostname": "HR-WS-01"},
                    timestamp=ts, source="log")
    g.upsert_entity("Process", "HR-WS-01::ps::1::" + ts,
                    attrs={"pid": "1", "image_name": "powershell.exe"},
                    timestamp=ts, source="log")
    g.upsert_relation("executed_on",
                      "Process", "HR-WS-01::ps::1::" + ts,
                      "Host", "HR-WS-01",
                      timestamp=ts, source="log")

    llm = FakeLLMClient()
    engine = JudgmentEngine(
        llm=llm, graph=g, signal_hub=FakeSignalHub(),
        subgraph_node_types={"Host", "Process"},  # 显式包含 Process
    )
    engine.judge(_make_alert(computer="HR-WS-01"))

    user_prompt = llm.calls[0]["user"]
    assert "powershell.exe" in user_prompt


def test_evidence_ref_valid_graph_node_accepted() -> None:
    """指向真实存在的子图节点应被接受。"""
    from reasoning.judgment_engine import JudgmentEngine

    alert = _make_alert()
    g = _make_graph_with_attack()

    llm = FakeLLMClient(response={
        "verdict": "malicious",
        "confidence": 0.9,
        "reasoning_steps": ["..."],
        "evidence_refs": [
            {"type": "matched_field", "ref": "EventData.LogonType"},
            {"type": "graph_node", "ref": "Account:S-1-5-21-1-2001"},
            {"type": "graph_node", "ref": "Host:HR-WS-01"},
        ],
        "attack_chain": ["T1078"],
        "next_steps": [],
    })
    engine = JudgmentEngine(llm=llm, graph=g, signal_hub=FakeSignalHub())
    j = engine.judge(alert)
    assert j.verdict == "malicious"
    assert len(j.evidence_refs) == 3
