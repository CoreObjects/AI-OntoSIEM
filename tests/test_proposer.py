"""组件 8 本体演化提议引擎单测（TDD · FakeLLMClient）。"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import pytest


# =========================================================
# Fakes
# =========================================================

class FakeLLMClient:
    def __init__(self, response: Optional[Dict[str, Any]] = None):
        self._response = response
        self.calls: List[Dict[str, Any]] = []

    def set_response(self, response: Dict[str, Any]) -> None:
        self._response = response

    def structured_json(
        self, system: str, user: str, *,
        required_keys=(), validator=None,
        max_tokens=4096, temperature=0.2, max_retries=2,
    ) -> Dict[str, Any]:
        self.calls.append({"system": system, "user": user,
                           "required_keys": set(required_keys)})
        if self._response is None:
            raise RuntimeError("fake llm has no response set")
        missing = set(required_keys) - set(self._response.keys())
        if missing:
            raise RuntimeError(f"fake response missing keys {missing}")
        if validator is not None:
            err = validator(self._response)
            if err is not None:
                raise RuntimeError(f"fake validator failed: {err}")
        return dict(self._response)


class FakeSignalHub:
    def __init__(self, pending=None):
        self._pending = pending or []
        self.marked: List[str] = []

    def list_pending(self, window_hours=24, threshold=20):
        return list(self._pending)

    def list_aggregations(self, window_hours=24, min_count=1):
        return list(self._pending)

    def mark_processed(self, agg_key):
        self.marked.append(agg_key)
        return 1


class FakeOntology:
    def __init__(self, nodes=None, edges=None, version="1.0"):
        self.version = version
        self.nodes = dict.fromkeys(nodes or ["User", "Account", "Host", "Process",
                                             "NetworkEndpoint"], {})
        self.edges = dict.fromkeys(edges or ["owns", "authenticated_as", "logged_into",
                                             "spawned", "executed_on", "connected_to"], {})


# =========================================================
# Proposal dataclass
# =========================================================

def test_proposal_dataclass_fields() -> None:
    from evolution.proposer import Proposal
    p = Proposal(
        proposal_id="p-1",
        proposal_type="node",
        name="ScheduledTask",
        semantic_definition="Windows Task Scheduler 条目",
        supporting_evidence=[{"record_id": 1, "excerpt": "4698 TaskName=..."}] * 3,
        overlap_analysis={"Process": 0.3, "Account": 0.05},
        attack_mapping=["T1053.005"],
        source_signals=["data:unparseable_event:4698"],
        ontology_base_version="1.0",
    )
    assert p.status == "pending"


# =========================================================
# ProposalEngine 基础流程
# =========================================================

def _sig(key: str, count: int, source="data", type_="unparseable_event"):
    return {
        "aggregation_key": key, "count": count,
        "source_layer": source, "signal_type": type_,
        "priority": "hot", "first_seen": "2026-04-22T10:00:00Z",
        "last_seen": "2026-04-23T04:00:00Z", "processed": False,
    }


def _good_llm_response(n=1):
    props = []
    for i in range(n):
        props.append({
            "proposal_type": "node",
            "name": f"NewConcept{i}",
            "semantic_definition": f"新概念 {i} 的定义",
            "supporting_evidence": [
                {"record_id": 100 + j, "excerpt": f"sample {j}"}
                for j in range(3)
            ],
            "overlap_analysis": {"Process": 0.2, "Account": 0.1},
            "attack_mapping": [f"T105{i}"],
            "source_signals": [f"data:unparseable_event:{4698+i}"],
        })
    return {"proposals": props}


def test_generate_returns_proposals() -> None:
    from evolution.proposer import ProposalEngine
    hub = FakeSignalHub(pending=[_sig("data:unparseable_event:4698", 22)])
    llm = FakeLLMClient(_good_llm_response(1))
    eng = ProposalEngine(llm=llm, signal_hub=hub, ontology=FakeOntology())
    props = eng.generate()
    assert len(props) == 1
    assert props[0].name == "NewConcept0"
    assert props[0].proposal_type == "node"
    assert props[0].status == "pending"
    assert props[0].ontology_base_version == "1.0"


def test_generate_skips_when_no_pending_signals() -> None:
    from evolution.proposer import ProposalEngine
    hub = FakeSignalHub(pending=[])
    llm = FakeLLMClient()
    eng = ProposalEngine(llm=llm, signal_hub=hub, ontology=FakeOntology())
    props = eng.generate()
    assert props == []
    assert llm.calls == []  # 没有信号就不调 LLM


# =========================================================
# Prompt 注入：硬边界 + 信号 + 本体 + 反面样本
# =========================================================

def test_prompt_contains_hard_constraints() -> None:
    from evolution.proposer import ProposalEngine
    hub = FakeSignalHub(pending=[_sig("data:unparseable_event:4698", 22)])
    llm = FakeLLMClient(_good_llm_response(1))
    ProposalEngine(llm=llm, signal_hub=hub, ontology=FakeOntology()).generate()

    sys_prompt = llm.calls[0]["system"]
    # 5 条硬约束（需求 §4.8）
    assert "只能新增" in sys_prompt or "only add" in sys_prompt.lower()
    assert "≥3" in sys_prompt or ">= 3" in sys_prompt or "至少 3" in sys_prompt
    assert "overlap" in sys_prompt.lower() or "重叠" in sys_prompt
    assert "5" in sys_prompt  # 单次最多 5 个


def test_prompt_contains_pending_signals_summary() -> None:
    from evolution.proposer import ProposalEngine
    hub = FakeSignalHub(pending=[
        _sig("data:unparseable_event:4698", 22),
        _sig("data:unparseable_event:4702", 8),
    ])
    llm = FakeLLMClient(_good_llm_response(1))
    ProposalEngine(llm=llm, signal_hub=hub, ontology=FakeOntology()).generate()
    user = llm.calls[0]["user"]
    assert "4698" in user
    assert "22" in user


def test_prompt_lists_current_ontology_concepts() -> None:
    from evolution.proposer import ProposalEngine
    hub = FakeSignalHub(pending=[_sig("k", 22)])
    llm = FakeLLMClient(_good_llm_response(1))
    ProposalEngine(llm=llm, signal_hub=hub, ontology=FakeOntology()).generate()
    user = llm.calls[0]["user"]
    # 当前本体的核心概念都应在 prompt（让 LLM 知道已有啥）
    assert "Account" in user and "Host" in user and "logged_into" in user


def test_prompt_injects_rejection_history() -> None:
    """反面样本库：历史被拒绝的提议应注入 prompt 让 LLM 避免重复。"""
    from evolution.proposer import ProposalEngine
    hub = FakeSignalHub(pending=[_sig("k", 22)])
    llm = FakeLLMClient(_good_llm_response(1))

    rejected_names = ["FakeConceptX", "AnotherBadOne"]
    eng = ProposalEngine(llm=llm, signal_hub=hub, ontology=FakeOntology(),
                         rejection_names=rejected_names)
    eng.generate()

    user = llm.calls[0]["user"]
    assert "FakeConceptX" in user
    assert "AnotherBadOne" in user


# =========================================================
# 硬边界校验（代码侧二次把关 LLM 输出）
# =========================================================

def test_hardgate_rejects_proposal_with_less_than_3_evidence() -> None:
    from evolution.proposer import ProposalEngine
    hub = FakeSignalHub(pending=[_sig("k", 22)])
    bad = _good_llm_response(1)
    bad["proposals"][0]["supporting_evidence"] = [{"record_id": 1, "excerpt": "x"}]  # 只 1 条
    llm = FakeLLMClient(bad)
    eng = ProposalEngine(llm=llm, signal_hub=hub, ontology=FakeOntology())
    props = eng.generate()
    assert props == []  # 被硬边界过滤掉


def test_hardgate_rejects_modify_or_delete_type() -> None:
    from evolution.proposer import ProposalEngine
    hub = FakeSignalHub(pending=[_sig("k", 22)])
    bad = _good_llm_response(1)
    bad["proposals"][0]["proposal_type"] = "delete"
    llm = FakeLLMClient(bad)
    eng = ProposalEngine(llm=llm, signal_hub=hub, ontology=FakeOntology())
    props = eng.generate()
    assert props == []


def test_hardgate_truncates_to_5_proposals() -> None:
    """LLM 即使给了 7 个，也只保留前 5 个。"""
    from evolution.proposer import ProposalEngine
    hub = FakeSignalHub(pending=[_sig("k", 22)])
    llm = FakeLLMClient(_good_llm_response(7))
    eng = ProposalEngine(llm=llm, signal_hub=hub, ontology=FakeOntology())
    props = eng.generate()
    assert len(props) == 5


def test_hardgate_rejects_collision_with_existing_node() -> None:
    """name 与当前本体节点/边同名 → 拒（只能新增，不能重复）。"""
    from evolution.proposer import ProposalEngine
    hub = FakeSignalHub(pending=[_sig("k", 22)])
    bad = _good_llm_response(1)
    bad["proposals"][0]["name"] = "Account"  # 本体已有
    llm = FakeLLMClient(bad)
    eng = ProposalEngine(llm=llm, signal_hub=hub, ontology=FakeOntology())
    props = eng.generate()
    assert props == []


# =========================================================
# 闸一：重叠度 > 0.7 自动丢弃
# =========================================================

def test_overlap_gate_drops_high_similarity_proposal() -> None:
    from evolution.proposer import ProposalEngine
    hub = FakeSignalHub(pending=[_sig("k", 22)])
    bad = _good_llm_response(1)
    bad["proposals"][0]["overlap_analysis"] = {"Process": 0.85}  # > 0.7
    llm = FakeLLMClient(bad)
    eng = ProposalEngine(llm=llm, signal_hub=hub, ontology=FakeOntology())
    props = eng.generate()
    assert props == []


def test_overlap_gate_keeps_low_similarity_proposal() -> None:
    from evolution.proposer import ProposalEngine
    hub = FakeSignalHub(pending=[_sig("k", 22)])
    ok = _good_llm_response(1)
    ok["proposals"][0]["overlap_analysis"] = {"Process": 0.4, "Account": 0.2}
    llm = FakeLLMClient(ok)
    eng = ProposalEngine(llm=llm, signal_hub=hub, ontology=FakeOntology())
    props = eng.generate()
    assert len(props) == 1


# =========================================================
# 闸二：字符串名称冗余检测（与本体/拒绝样本对比）
# =========================================================

def test_string_similarity_gate_drops_near_duplicate_name() -> None:
    """'Accounts' 与 'Account' 过于相似 → 丢。"""
    from evolution.proposer import ProposalEngine
    hub = FakeSignalHub(pending=[_sig("k", 22)])
    bad = _good_llm_response(1)
    bad["proposals"][0]["name"] = "Accounts"  # 与 Account 相似度 ~0.94
    llm = FakeLLMClient(bad)
    eng = ProposalEngine(llm=llm, signal_hub=hub, ontology=FakeOntology())
    props = eng.generate()
    assert props == []


def test_string_similarity_gate_against_rejection_names() -> None:
    """与历史拒绝名称高度相似的新提议也丢。"""
    from evolution.proposer import ProposalEngine
    hub = FakeSignalHub(pending=[_sig("k", 22)])
    bad = _good_llm_response(1)
    bad["proposals"][0]["name"] = "BadConceptx"
    llm = FakeLLMClient(bad)
    eng = ProposalEngine(llm=llm, signal_hub=hub, ontology=FakeOntology(),
                         rejection_names=["BadConcept"])
    props = eng.generate()
    assert props == []


# =========================================================
# source_signals 关联：mark_processed 在演化消费后由审核侧调，不在 generate 里
# =========================================================

def test_generate_does_not_mark_signals_processed() -> None:
    """提议 generate 只是"产生候选"；mark_processed 应在审核通过后做。"""
    from evolution.proposer import ProposalEngine
    hub = FakeSignalHub(pending=[_sig("data:unparseable_event:4698", 22)])
    llm = FakeLLMClient(_good_llm_response(1))
    ProposalEngine(llm=llm, signal_hub=hub, ontology=FakeOntology()).generate()
    assert hub.marked == []
