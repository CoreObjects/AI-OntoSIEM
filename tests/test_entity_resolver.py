"""实体消歧分层（需求 §4.5）：
  - 强匹配（SID / hostname / pid+image+start_time）confidence=1.0
  - 中匹配（domain\\username）confidence=0.8
  - 弱匹配（仅 username 等）confidence<0.8，进观察区
"""
from __future__ import annotations

import pytest


# =========================================================
# Account 消歧
# =========================================================

def test_resolve_account_strong_when_sid_present() -> None:
    from graph.entity_resolver import resolve_account
    r = resolve_account(sid="S-1-5-21-1-1001", domain="CORP", username="alice")
    assert r.canonical_id == "S-1-5-21-1-1001"
    assert r.confidence == 1.0
    assert r.match_level == "strong"


def test_resolve_account_medium_without_sid() -> None:
    from graph.entity_resolver import resolve_account
    r = resolve_account(sid=None, domain="corp", username="Alice")
    # 规范化：domain 大写，username 小写
    assert r.canonical_id == "CORP\\alice"
    assert r.confidence == 0.8
    assert r.match_level == "medium"


def test_resolve_account_weak_only_username() -> None:
    from graph.entity_resolver import resolve_account
    r = resolve_account(sid=None, domain=None, username="alice")
    assert r.canonical_id == "?\\alice"
    assert r.confidence < 0.8
    assert r.match_level == "weak"


def test_resolve_account_ignores_anonymous_sid() -> None:
    """S-1-0-0 (Anonymous) 等空 SID 不应走强匹配。"""
    from graph.entity_resolver import resolve_account
    r = resolve_account(sid="S-1-0-0", domain="CORP", username="alice")
    # Anonymous SID 回退到中匹配
    assert r.match_level == "medium"
    assert r.canonical_id == "CORP\\alice"


def test_resolve_account_ignores_empty_string_sid() -> None:
    from graph.entity_resolver import resolve_account
    r = resolve_account(sid="", domain="CORP", username="alice")
    assert r.match_level == "medium"


def test_resolve_account_raises_when_nothing() -> None:
    from graph.entity_resolver import resolve_account
    with pytest.raises(ValueError):
        resolve_account(sid=None, domain=None, username=None)


# =========================================================
# Host 消歧
# =========================================================

def test_resolve_host_strong_by_hostname() -> None:
    from graph.entity_resolver import resolve_host
    r = resolve_host(hostname="HR-WS-01")
    assert r.canonical_id == "HR-WS-01"
    assert r.match_level == "strong"


def test_resolve_host_normalizes_fqdn_to_short() -> None:
    """HR-WS-01.corp.local → HR-WS-01（规范化）。"""
    from graph.entity_resolver import resolve_host
    r = resolve_host(hostname="HR-WS-01.corp.local")
    assert r.canonical_id == "HR-WS-01"
    # FQDN → short 做了推断，降级为 medium
    assert r.match_level == "medium"


def test_resolve_host_case_insensitive() -> None:
    from graph.entity_resolver import resolve_host
    a = resolve_host(hostname="hr-ws-01")
    b = resolve_host(hostname="HR-WS-01")
    assert a.canonical_id == b.canonical_id == "HR-WS-01"


# =========================================================
# Process 消歧
# =========================================================

def test_resolve_process_strong_composite_key() -> None:
    """pid + image + start_time 组合主键。"""
    from graph.entity_resolver import resolve_process
    r = resolve_process(
        pid="1234",
        image_name="C:\\Windows\\System32\\cmd.exe",
        start_time="2026-04-15T14:23:01Z",
        host="HR-WS-01",
    )
    assert r.canonical_id == "HR-WS-01::cmd.exe::1234::2026-04-15T14:23:01Z"
    assert r.match_level == "strong"


def test_resolve_process_medium_no_start_time() -> None:
    """pid 会复用，没有 start_time 只能中匹配。"""
    from graph.entity_resolver import resolve_process
    r = resolve_process(pid="1234", image_name="cmd.exe", start_time=None, host="HR-WS-01")
    assert r.match_level == "medium"
    assert r.confidence == 0.8
