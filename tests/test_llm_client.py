"""reasoning/llm_client.py 单测（不打真实 API，只测本地逻辑）。"""
from __future__ import annotations

import json
import os
from typing import Any, Dict

import pytest

os.environ.setdefault("DASHSCOPE_API_KEY", "test-key")

from reasoning.llm_client import (  # noqa: E402
    LLMBudgetExceeded,
    LLMClient,
    LLMOutputInvalid,
    validate_evidence_refs,
)


# -------- validate_evidence_refs --------

def test_validate_evidence_refs_missing() -> None:
    assert validate_evidence_refs({}) == "evidence_refs is required"


def test_validate_evidence_refs_wrong_type() -> None:
    assert "must be list" in (validate_evidence_refs({"evidence_refs": "abc"}) or "")


def test_validate_evidence_refs_empty() -> None:
    assert "non-empty" in (validate_evidence_refs({"evidence_refs": []}) or "")


def test_validate_evidence_refs_ok() -> None:
    assert validate_evidence_refs({"evidence_refs": ["event_1", "event_2"]}) is None


# -------- LLMClient 行为（mock OpenAI 客户端）--------

class _FakeUsage:
    def __init__(self, p: int, c: int) -> None:
        self.prompt_tokens = p
        self.completion_tokens = c
        self.total_tokens = p + c


class _FakeMessage:
    def __init__(self, content: str) -> None:
        self.content = content


class _FakeChoice:
    def __init__(self, content: str) -> None:
        self.message = _FakeMessage(content)


class _FakeResponse:
    def __init__(self, content: str, prompt_tokens: int = 10, completion_tokens: int = 20) -> None:
        self.choices = [_FakeChoice(content)]
        self.usage = _FakeUsage(prompt_tokens, completion_tokens)


class _FakeChatCompletions:
    def __init__(self, responses: list[str]) -> None:
        self._responses = list(responses)
        self.call_count = 0

    def create(self, **kwargs: Any) -> _FakeResponse:
        self.call_count += 1
        if not self._responses:
            raise RuntimeError("no more canned responses")
        return _FakeResponse(self._responses.pop(0))


class _FakeClient:
    def __init__(self, responses: list[str]) -> None:
        self.chat = type("_", (), {"completions": _FakeChatCompletions(responses)})()


def _mk_client(responses: list[str]) -> LLMClient:
    c = LLMClient(api_key="test", base_url="http://fake", model="qwen-test",
                  budget_warn=1000, budget_hard=100_000)
    c._client = _FakeClient(responses)  # type: ignore[assignment]
    return c


def test_happy_path_returns_parsed_json() -> None:
    client = _mk_client(['{"verdict": "benign", "evidence_refs": ["e1"]}'])
    data = client.structured_json(
        system="sys", user="usr",
        required_keys={"verdict", "evidence_refs"},
    )
    assert data["verdict"] == "benign"
    assert client.usage.total_tokens == 30


def test_retries_on_invalid_json() -> None:
    client = _mk_client([
        'not valid json',
        '{"verdict": "benign", "evidence_refs": ["e1"]}',
    ])
    data = client.structured_json(
        system="sys", user="usr",
        required_keys={"verdict", "evidence_refs"},
    )
    assert data["verdict"] == "benign"


def test_gives_up_after_max_retries() -> None:
    client = _mk_client(['bad', 'still bad', 'no way'])
    with pytest.raises(LLMOutputInvalid):
        client.structured_json(system="s", user="u",
                               required_keys={"x"}, max_retries=2)


def test_missing_required_keys_retries() -> None:
    client = _mk_client([
        '{"verdict": "benign"}',  # missing evidence_refs
        '{"verdict": "benign", "evidence_refs": ["e1"]}',
    ])
    data = client.structured_json(
        system="s", user="u",
        required_keys={"verdict", "evidence_refs"},
    )
    assert "evidence_refs" in data


def test_validator_runs() -> None:
    client = _mk_client([
        '{"verdict": "benign", "evidence_refs": []}',           # empty array
        '{"verdict": "benign", "evidence_refs": ["e1", "e2"]}',
    ])
    data = client.structured_json(
        system="s", user="u",
        required_keys={"verdict", "evidence_refs"},
        validator=validate_evidence_refs,
    )
    assert len(data["evidence_refs"]) == 2


def test_budget_hard_limit_raises() -> None:
    client = LLMClient(api_key="test", base_url="http://fake", model="qwen-test",
                       budget_warn=50, budget_hard=100)
    client._client = _FakeClient(['{"x": 1}'])  # type: ignore[assignment]
    # 注入已累计 tokens 超限
    client._usage.total_tokens = 200
    with pytest.raises(LLMBudgetExceeded):
        client.structured_json(system="s", user="u", required_keys=set())


def test_empty_response_retried() -> None:
    client = _mk_client(['', '{"ok": 1}'])
    data = client.structured_json(system="s", user="u", required_keys={"ok"})
    assert data["ok"] == 1


def test_non_dict_response_retried() -> None:
    client = _mk_client(['[1, 2, 3]', '{"ok": 1}'])
    data = client.structured_json(system="s", user="u", required_keys={"ok"})
    assert data["ok"] == 1
