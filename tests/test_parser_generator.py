"""组件 10 Day 1：Parser 自动生成器单测（TDD · FakeLLMClient）。

输入  approved Proposal + anomaly_pool 样本 + 现 parser 配置 + 当前本体
输出  CandidateParser（含 rules YAML 结构、target_node_type、confidence、sample_count）

闸门：
  G1 字段引用真实 — event_data.X 必须出现在至少一条 anomaly 样本里
  G2 target_node 必须存在于（升级后）本体
  G3 rules 必须能被 ParserConfig.from_dict 合法解析（DSL 兼容）
  G4 至少一条 entity 引用了 target_node
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional


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
        max_tokens=4096, temperature=0.1, max_retries=2,
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


class FakeOntology:
    # 端点字典与 ontology v1.0 对齐
    _DEFAULT_ENDPOINTS = {
        "owns": ("User", "Account"),
        "authenticated_as": ("Host", "Account"),
        "logged_into": ("Account", "Host"),
        "spawned": ("Process", "Process"),
        "executed_on": ("Process", "Host"),
        "connected_to": ("Process", "NetworkEndpoint"),
    }

    def __init__(self, nodes=None, edges=None, version="1.1", endpoints=None):
        self.version = version
        # 默认含 v1.0 节点 + ScheduledTask（代表升级后的本体）
        default_nodes = ["User", "Account", "Host", "Process",
                         "NetworkEndpoint", "ScheduledTask"]
        default_edges = ["owns", "authenticated_as", "logged_into",
                         "spawned", "executed_on", "connected_to"]
        self.nodes = dict.fromkeys(nodes or default_nodes, {})
        self.edges = dict.fromkeys(edges or default_edges, {})
        self._endpoints = dict(endpoints) if endpoints is not None else dict(self._DEFAULT_ENDPOINTS)

    def edge_endpoints(self, edge_type: str):
        return self._endpoints.get(edge_type)


def _scheduled_task_proposal():
    """组件 8 真调 Qwen 产出的实际 ScheduledTask 提议结构。"""
    from evolution.proposer import Proposal
    return Proposal(
        proposal_id="bae04eee-784d-4dbb-93be-8c4e16324bfd",
        proposal_type="node",
        name="ScheduledTask",
        semantic_definition="Windows 计划任务条目（Task Scheduler）；EventID 4698 创建/4702 修改",
        supporting_evidence=[
            {"record_id": 10, "excerpt": "TaskName=\\Microsoft\\Windows\\TaskScheduler\\Idle Maintenance"},
            {"record_id": 218, "excerpt": "TaskName=\\Microsoft\\Windows\\Chkdsk\\ProactiveScan"},
            {"record_id": 357, "excerpt": "TaskName=..."},
        ],
        overlap_analysis={"Process": 0.35, "Account": 0.05},
        attack_mapping=["T1053.005"],
        source_signals=["data:unparseable_event:4698", "data:unparseable_event:4702"],
        ontology_base_version="1.0",
        status="approved",
    )


def _4698_samples(n: int = 3) -> List[Dict[str, Any]]:
    """模拟 anomaly_pool.list_open() 返回结构（已 _row_to_dict）。"""
    samples = []
    for i in range(n):
        samples.append({
            "record_id": 10 + i,
            "event_id": 4698,
            "computer": "HR-WS-01",
            "timestamp": f"2026-04-14 17:31:0{i}",
            "failure_reason": "no rule for (event_id=4698, channel=Security)",
            "raw_event": {
                "event_id": 4698,
                "channel": "Security",
                "provider": "Microsoft-Windows-Security-Auditing",
                "record_number": 10 + i,
                "timestamp": f"2026-04-14 17:31:0{i}",
                "computer": "HR-WS-01",
                "event_data": json.dumps({
                    "SubjectUserSid": "S-1-5-21-1000000000-1000000000-1000000000-1002",
                    "SubjectUserName": "bob",
                    "SubjectDomainName": "CORP",
                    "SubjectLogonId": "0x3D4092A",
                    "TaskName": f"\\Microsoft\\Windows\\Task{i}",
                    "TaskContent": f"<Task><Actions><Exec><Command>cmd{i}.exe</Command></Exec></Actions></Task>",
                }),
            },
        })
    return samples


def _good_llm_response() -> Dict[str, Any]:
    """LLM 输出：parser 配置（rules 列表 + confidence + explanation）。"""
    return {
        "target_node_type": "ScheduledTask",
        "source_events": [
            {"event_id": 4698, "channel": "Security"},
        ],
        "rules": [
            {
                "name": "4698_scheduled_task_create",
                "event_id": 4698,
                "channel": "Security",
                "description": "Scheduled Task 创建（演化生成 v1.1）",
                "entities": [
                    {
                        "node": "ScheduledTask",
                        "id_expr": "compose:@computer|event_data.TaskName",
                        "attrs": {
                            "task_name": "event_data.TaskName",
                            "task_content": "event_data.TaskContent",
                        },
                        "meta": {"source": "log", "confidence": 0.9},
                    },
                    {
                        "node": "Account",
                        "id_expr": "event_data.SubjectUserSid",
                        "attrs": {
                            "sid": "event_data.SubjectUserSid",
                            "username": "event_data.SubjectUserName",
                            "domain": "event_data.SubjectDomainName",
                        },
                        "meta": {"source": "log", "confidence": 1.0},
                    },
                    {
                        "node": "Host",
                        "id_expr": "@computer",
                        "attrs": {"hostname": "@computer"},
                        "meta": {"source": "log", "confidence": 1.0},
                    },
                ],
                "relations": [],
            },
        ],
        "confidence": 0.85,
        "explanation": "4698 Scheduled Task 创建事件，主要字段 TaskName / TaskContent / SubjectUserSid 对应到 ScheduledTask 主键 + Account 触发者。",
    }


def _make_engine(llm=None, ontology=None, response=None):
    from evolution.parser_generator import ParserGenerator
    if llm is None:
        llm = FakeLLMClient(response or _good_llm_response())
    if ontology is None:
        ontology = FakeOntology()
    return ParserGenerator(llm=llm, ontology=ontology), llm


def _gen(engine, samples=None, proposal=None, parser_cfg=None):
    return engine.generate(
        approved_proposal=proposal or _scheduled_task_proposal(),
        anomaly_samples=samples if samples is not None else _4698_samples(3),
        current_parser_config=parser_cfg,
    )


# =========================================================
# CandidateParser dataclass
# =========================================================

def test_candidate_parser_dataclass_fields() -> None:
    from evolution.parser_generator import CandidateParser
    c = CandidateParser(
        candidate_id="c-1",
        triggered_by_ontology_version="1.1",
        triggered_by_proposal_id="p-1",
        target_node_type="ScheduledTask",
        source_events=[{"event_id": 4698, "channel": "Security"}],
        rules=[{"name": "4698_x", "event_id": 4698, "channel": "Security",
                "entities": [], "relations": []}],
        sample_count=3,
        confidence=0.85,
        explanation="ok",
    )
    assert c.status == "pending"
    assert c.created_at  # 自动生成


def test_candidate_parser_yaml_text_property() -> None:
    """CandidateParser 应能产出可写入 parsers/generated/ 的 YAML 文本。"""
    import yaml
    from evolution.parser_generator import CandidateParser
    c = CandidateParser(
        candidate_id="c-1",
        triggered_by_ontology_version="1.1",
        triggered_by_proposal_id="p-1",
        target_node_type="ScheduledTask",
        source_events=[{"event_id": 4698, "channel": "Security"}],
        rules=[{"name": "4698_x", "event_id": 4698, "channel": "Security",
                "description": "...", "entities": [], "relations": []}],
        sample_count=3,
        confidence=0.85,
        explanation="ok",
    )
    text = c.yaml_text
    assert isinstance(text, str)
    doc = yaml.safe_load(text)
    assert doc["target_ontology_version"] == "1.1"
    assert doc["rules"][0]["event_id"] == 4698
    assert "Auto-generated" in doc.get("description", "") or "auto" in doc.get("description", "").lower()


# =========================================================
# 基础生成流程
# =========================================================

def test_generate_returns_candidate_parser() -> None:
    eng, _ = _make_engine()
    c = _gen(eng)
    assert c is not None
    assert c.target_node_type == "ScheduledTask"
    assert c.sample_count == 3
    assert c.confidence == 0.85
    assert c.status == "pending"


def test_generate_carries_proposal_and_ontology_versions() -> None:
    eng, _ = _make_engine()
    c = _gen(eng)
    assert c.triggered_by_proposal_id == "bae04eee-784d-4dbb-93be-8c4e16324bfd"
    assert c.triggered_by_ontology_version == "1.1"


def test_generate_returns_none_when_no_samples() -> None:
    """没有 anomaly 样本就别调 LLM。"""
    eng, llm = _make_engine()
    c = _gen(eng, samples=[])
    assert c is None
    assert llm.calls == []  # 不调 LLM


# =========================================================
# Prompt 注入
# =========================================================

def test_system_prompt_contains_dsl_syntax() -> None:
    eng, llm = _make_engine()
    _gen(eng)
    sys_prompt = llm.calls[0]["system"]
    # 表达式 DSL 必须教给 LLM
    assert "@computer" in sys_prompt
    assert "@timestamp" in sys_prompt
    assert "event_data." in sys_prompt
    assert "compose:" in sys_prompt
    assert "const:" in sys_prompt


def test_user_prompt_includes_proposal_definition() -> None:
    eng, llm = _make_engine()
    _gen(eng)
    user = llm.calls[0]["user"]
    assert "ScheduledTask" in user
    # 语义定义应注入
    assert "Task Scheduler" in user or "计划任务" in user


def test_user_prompt_includes_anomaly_samples() -> None:
    eng, llm = _make_engine()
    _gen(eng)
    user = llm.calls[0]["user"]
    assert "4698" in user
    # raw_event 关键字段
    assert "TaskName" in user
    assert "SubjectUserSid" in user


def test_user_prompt_includes_existing_parser_format_example() -> None:
    """让 LLM 看到已有 parser 配置一两条作为格式参照。"""
    from parsers.windows_parser import ParserConfig
    from pathlib import Path
    cfg = ParserConfig.load_all([Path("parsers/mappings")])
    eng, llm = _make_engine()
    _gen(eng, parser_cfg=cfg)
    user = llm.calls[0]["user"]
    # 至少一条现有规则名应在 user prompt 里作为模板
    assert any(r.name in user for r in cfg.rules)


# =========================================================
# 闸门 G1：字段引用必须在样本中真实存在（反幻觉）
# =========================================================

def test_g1_drops_candidate_with_hallucinated_event_data_field() -> None:
    bad = _good_llm_response()
    # 注入一个样本里不存在的字段
    bad["rules"][0]["entities"][0]["attrs"]["fake_field"] = "event_data.NonExistentField"
    eng, _ = _make_engine(response=bad)
    c = _gen(eng)
    assert c is None


def test_g1_accepts_compose_referring_real_fields() -> None:
    """compose: 里的子字段也必须真实存在。"""
    ok = _good_llm_response()
    ok["rules"][0]["entities"][0]["id_expr"] = (
        "compose:@computer|event_data.TaskName|event_data.SubjectLogonId"
    )
    eng, _ = _make_engine(response=ok)
    c = _gen(eng)
    assert c is not None


def test_g1_drops_compose_with_hallucinated_subfield() -> None:
    bad = _good_llm_response()
    bad["rules"][0]["entities"][0]["id_expr"] = (
        "compose:@computer|event_data.TaskName|event_data.SoldOnTV"
    )
    eng, _ = _make_engine(response=bad)
    c = _gen(eng)
    assert c is None


# =========================================================
# 闸门 G2：target_node_type 必须在（升级后的）本体
# =========================================================

def test_g2_drops_candidate_with_unknown_target_node_type() -> None:
    bad = _good_llm_response()
    bad["target_node_type"] = "TotallyBogusType"
    eng, _ = _make_engine(response=bad)
    c = _gen(eng)
    assert c is None


def test_g2_drops_entity_referencing_unknown_node_type() -> None:
    bad = _good_llm_response()
    bad["rules"][0]["entities"].append({
        "node": "AlienConcept", "id_expr": "@computer",
        "attrs": {}, "meta": {},
    })
    eng, _ = _make_engine(response=bad)
    c = _gen(eng)
    assert c is None


# =========================================================
# 闸门 G3：rules round-trip 必须能被 ParserConfig.from_dict 接受
# =========================================================

def test_g3_rules_compatible_with_parser_config_loader() -> None:
    """生成的 rules 拿去喂 ParserConfig 应不爆。"""
    from parsers.windows_parser import EventRule
    eng, _ = _make_engine()
    c = _gen(eng)
    assert c is not None
    for rd in c.rules:
        # 不抛异常即通过
        rule = EventRule.from_dict(rd)
        assert rule.event_id > 0
        assert rule.entities  # 至少一条 entity


# =========================================================
# 闸门 G4：target_node 必须真的被某条 entity 引用
# =========================================================

def test_g4_drops_candidate_not_referencing_target_node() -> None:
    """LLM 声称 target=ScheduledTask 但 entities 全是别的节点 → 丢。"""
    bad = _good_llm_response()
    bad["rules"][0]["entities"] = [
        {
            "node": "Account",
            "id_expr": "event_data.SubjectUserSid",
            "attrs": {}, "meta": {},
        },
    ]
    eng, _ = _make_engine(response=bad)
    c = _gen(eng)
    assert c is None


# =========================================================
# 闸门 G5：硬边界 — User 节点禁止从日志生成（CMDB-only）
# =========================================================

def test_g5_rejects_candidate_with_user_node_in_entities() -> None:
    """parser 不允许产 User 节点 — User 只能来自 CMDB/IAM。"""
    bad = _good_llm_response()
    # 把 Account 改 User（LLM 现实输出过这个错误）
    bad["rules"][0]["entities"][1]["node"] = "User"
    eng, _ = _make_engine(response=bad)
    c = _gen(eng)
    assert c is None


# =========================================================
# 闸门 G6：硬边界 — owns 边禁止从日志生成（declared-only），违反 → strip
# =========================================================

def test_g6_strips_owns_edge_from_relations() -> None:
    bad = _good_llm_response()
    bad["rules"][0]["relations"] = [
        {"edge": "owns", "from_ref": "Account", "to_ref": "ScheduledTask",
         "extra_attrs": {}}
    ]
    eng, _ = _make_engine(response=bad)
    c = _gen(eng)
    assert c is not None
    # 关系被剔除
    for rule in c.rules:
        assert all(r["edge"] != "owns" for r in rule.get("relations") or [])
    # 剔除原因被记录
    assert any(s.get("edge") == "owns" for s in c.stripped_relations)


# =========================================================
# 闸门 G7：边端点类型必须与本体声明匹配（否则 strip）
# =========================================================

def test_g7_strips_relation_with_endpoint_type_mismatch() -> None:
    """executed_on 在本体里是 Process→Host，不允许 ScheduledTask→Host。"""
    bad = _good_llm_response()
    bad["rules"][0]["entities"].append({
        "node": "Host", "ref_name": "Host2", "id_expr": "@computer",
        "attrs": {}, "meta": {},
    })
    bad["rules"][0]["relations"] = [
        {"edge": "executed_on", "from_ref": "ScheduledTask", "to_ref": "Host",
         "extra_attrs": {}}
    ]
    eng, _ = _make_engine(response=bad)
    c = _gen(eng)
    assert c is not None
    for rule in c.rules:
        assert all(r["edge"] != "executed_on" for r in rule.get("relations") or [])
    assert any(s.get("edge") == "executed_on" and "endpoint" in s.get("reason", "").lower()
               for s in c.stripped_relations)


def test_g7_keeps_relation_with_correct_endpoints() -> None:
    """spawned: Process→Process — 端点对，应保留。"""
    ok = _good_llm_response()
    # 加两个 Process 实体让 spawned 有合法端点
    ok["rules"][0]["entities"].extend([
        {"node": "Process", "ref_name": "p_parent",
         "id_expr": "compose:@computer|event_data.SubjectLogonId",
         "attrs": {}, "meta": {}},
        {"node": "Process", "ref_name": "p_child",
         "id_expr": "compose:@computer|event_data.SubjectUserSid",
         "attrs": {}, "meta": {}},
    ])
    ok["rules"][0]["relations"] = [
        {"edge": "spawned", "from_ref": "p_parent", "to_ref": "p_child",
         "extra_attrs": {}}
    ]
    eng, _ = _make_engine(response=ok)
    c = _gen(eng)
    assert c is not None
    rels = [r for rule in c.rules for r in (rule.get("relations") or [])]
    assert any(r["edge"] == "spawned" for r in rels)
    assert c.stripped_relations == []


# =========================================================
# stripped_relations 字段
# =========================================================

def test_stripped_relations_default_empty_list() -> None:
    from evolution.parser_generator import CandidateParser
    c = CandidateParser(
        candidate_id="c-1",
        triggered_by_ontology_version="1.1",
        triggered_by_proposal_id="p-1",
        target_node_type="ScheduledTask",
        source_events=[],
        rules=[{"name": "x", "event_id": 4698, "channel": "Security",
                "entities": [], "relations": []}],
        sample_count=0,
        confidence=0.5,
        explanation="",
    )
    assert c.stripped_relations == []
