"""实体消歧分层（需求 §4.5）。

三级策略：
  strong  (confidence=1.0)  —— SID / hostname / pid+image+start_time+host
  medium  (confidence=0.8)  —— domain\\username / FQDN 推短名 / pid+image+host
  weak    (confidence<0.8)  —— 仅 username 等，进观察区

规范化：
  - domain 强制大写、username 强制小写
  - hostname 大写、FQDN 只保留第一段
  - image_name 只保留 basename（"C:\\...\\cmd.exe" → "cmd.exe"）
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ResolveResult:
    canonical_id: str
    confidence: float
    match_level: str  # "strong" / "medium" / "weak"


# =========================================================
# Account
# =========================================================

_EMPTY_SIDS = {"", "S-1-0-0", "S-1-5-7"}  # Anonymous / Anonymous Logon


def resolve_account(
    sid: Optional[str],
    domain: Optional[str],
    username: Optional[str],
) -> ResolveResult:
    if sid and sid not in _EMPTY_SIDS and sid.startswith("S-"):
        return ResolveResult(sid, 1.0, "strong")
    if domain and username:
        return ResolveResult(
            f"{domain.upper()}\\{username.lower()}",
            0.8,
            "medium",
        )
    if username:
        return ResolveResult(f"?\\{username.lower()}", 0.5, "weak")
    raise ValueError("resolve_account: need at least one of (sid, domain+username, username)")


# =========================================================
# Host
# =========================================================

def resolve_host(hostname: str) -> ResolveResult:
    if not hostname:
        raise ValueError("resolve_host: empty hostname")
    short = hostname.split(".", 1)[0].upper()
    is_fqdn = "." in hostname
    return ResolveResult(
        canonical_id=short,
        confidence=0.8 if is_fqdn else 1.0,
        match_level="medium" if is_fqdn else "strong",
    )


# =========================================================
# Process
# =========================================================

def _basename(image: str) -> str:
    # Windows 路径与 posix 都覆盖
    for sep in ("\\", "/"):
        if sep in image:
            image = image.rsplit(sep, 1)[1]
    return image


def resolve_process(
    pid: str,
    image_name: str,
    start_time: Optional[str],
    host: str,
) -> ResolveResult:
    if not pid or not image_name or not host:
        raise ValueError("resolve_process: pid/image_name/host required")
    base = _basename(image_name)
    host_norm = host.split(".", 1)[0].upper()
    if start_time:
        return ResolveResult(
            canonical_id=f"{host_norm}::{base}::{pid}::{start_time}",
            confidence=1.0,
            match_level="strong",
        )
    return ResolveResult(
        canonical_id=f"{host_norm}::{base}::{pid}",
        confidence=0.8,
        match_level="medium",
    )
