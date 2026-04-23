"""LLM 客户端封装（Qwen-Plus via DashScope OpenAI 兼容接口）。

核心职责：
  - 统一接口：structured_json() 返回 dict（而非原始字符串）
  - Token 预算守护：累计消耗达阈值告警/拒绝
  - Retry：JSON 解析失败 / 响应不合规时重试 ≤ max_retries
  - evidence_refs 强制校验（反幻觉第一道闸门）

使用：
    from reasoning.llm_client import get_client
    client = get_client()
    result = client.structured_json(
        system="你是资深 Windows 安全分析师...",
        user="研判这条告警...",
        required_keys={"verdict", "confidence", "reasoning_steps", "evidence_refs"},
    )
"""
from __future__ import annotations

import json
import logging
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

from dotenv import load_dotenv
from openai import OpenAI
from openai.types.chat import ChatCompletion

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")


class LLMBudgetExceeded(RuntimeError):
    """累计 token 消耗超过硬上限时抛出。"""


class LLMOutputInvalid(RuntimeError):
    """LLM 输出不符合 schema 或 JSON 解析失败（重试已耗尽）。"""


@dataclass
class UsageStats:
    calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0

    def add(self, resp: ChatCompletion) -> None:
        self.calls += 1
        u = resp.usage
        if u is not None:
            self.prompt_tokens += u.prompt_tokens or 0
            self.completion_tokens += u.completion_tokens or 0
            self.total_tokens += u.total_tokens or 0


class LLMClient:
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        budget_warn: Optional[int] = None,
        budget_hard: Optional[int] = None,
    ) -> None:
        self.api_key = api_key or os.environ.get("DASHSCOPE_API_KEY", "")
        if not self.api_key:
            raise RuntimeError("DASHSCOPE_API_KEY not set")
        self.base_url = base_url or os.environ.get(
            "DASHSCOPE_BASE_URL",
            "https://dashscope.aliyuncs.com/compatible-mode/v1",
        )
        self.model = model or os.environ.get("LLM_MODEL", "qwen-plus-2025-07-28")
        self.budget_warn = int(budget_warn or os.environ.get("LLM_TOKEN_BUDGET_WARN", 700_000))
        self.budget_hard = int(budget_hard or os.environ.get("LLM_TOKEN_BUDGET_HARD", 900_000))

        self._client = OpenAI(api_key=self.api_key, base_url=self.base_url)
        self._usage = UsageStats()
        self._lock = threading.RLock()

    # -------- Public API --------

    @property
    def usage(self) -> UsageStats:
        with self._lock:
            return UsageStats(
                calls=self._usage.calls,
                prompt_tokens=self._usage.prompt_tokens,
                completion_tokens=self._usage.completion_tokens,
                total_tokens=self._usage.total_tokens,
            )

    def structured_json(
        self,
        system: str,
        user: str,
        *,
        required_keys: Iterable[str] = (),
        validator: Optional[Callable[[Dict[str, Any]], Optional[str]]] = None,
        max_tokens: int = 2048,
        temperature: float = 0.1,
        max_retries: int = 2,
    ) -> Dict[str, Any]:
        """调用 LLM 返回 JSON dict。

        Args:
          required_keys: 响应必须包含的 top-level key 集合
          validator:     额外的校验函数，返回 None 表示通过，否则返回错误字符串

        失败情况：
          - JSON 无法解析 → 重试（至多 max_retries）
          - required_keys 缺失 → 重试
          - validator 返回错误 → 重试
          - 重试耗尽 → 抛 LLMOutputInvalid
          - 预算超限 → 抛 LLMBudgetExceeded（调用前检查）
        """
        self._check_budget()

        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]

        last_error = ""
        for attempt in range(max_retries + 1):
            try:
                resp = self._client.chat.completions.create(
                    model=self.model,
                    messages=messages,  # type: ignore[arg-type]
                    response_format={"type": "json_object"},
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
            except Exception as exc:
                last_error = f"api error: {exc}"
                logger.warning("LLM API call failed (attempt %d): %s", attempt + 1, exc)
                if attempt >= max_retries:
                    raise LLMOutputInvalid(last_error) from exc
                continue

            with self._lock:
                self._usage.add(resp)
            self._warn_budget()

            content = (resp.choices[0].message.content or "").strip()
            if not content:
                last_error = "empty response"
                logger.warning("LLM returned empty content (attempt %d)", attempt + 1)
                continue

            try:
                data = json.loads(content)
            except json.JSONDecodeError as exc:
                last_error = f"JSON parse failed: {exc}"
                logger.warning("LLM JSON parse failed (attempt %d): %s\n--\n%s",
                               attempt + 1, exc, content[:500])
                continue

            if not isinstance(data, dict):
                last_error = f"expected JSON object, got {type(data).__name__}"
                continue

            missing = set(required_keys) - data.keys()
            if missing:
                last_error = f"missing keys: {sorted(missing)}"
                logger.warning("LLM output missing keys (attempt %d): %s", attempt + 1, missing)
                # 追加一轮强化指令
                messages.append({"role": "assistant", "content": content})
                messages.append({"role": "user", "content": f"上次输出缺少必填字段 {sorted(missing)}。请重新输出完整 JSON。"})
                continue

            if validator is not None:
                err = validator(data)
                if err is not None:
                    last_error = f"validator failed: {err}"
                    messages.append({"role": "assistant", "content": content})
                    messages.append({"role": "user", "content": f"上次输出不合规：{err}。请修正后重新输出完整 JSON。"})
                    continue

            return data

        raise LLMOutputInvalid(f"LLM failed after {max_retries + 1} attempts: {last_error}")

    # -------- Budget guard --------

    def _check_budget(self) -> None:
        with self._lock:
            if self._usage.total_tokens >= self.budget_hard:
                raise LLMBudgetExceeded(
                    f"Total tokens {self._usage.total_tokens} >= hard limit {self.budget_hard}"
                )

    def _warn_budget(self) -> None:
        with self._lock:
            total = self._usage.total_tokens
        if total >= self.budget_warn:
            logger.warning("LLM token usage %d >= warn threshold %d", total, self.budget_warn)


# -------- evidence_refs 校验器 --------

def validate_evidence_refs(data: Dict[str, Any]) -> Optional[str]:
    """反幻觉闸门：evidence_refs 必须存在且非空数组。"""
    refs = data.get("evidence_refs")
    if refs is None:
        return "evidence_refs is required"
    if not isinstance(refs, list):
        return f"evidence_refs must be list, got {type(refs).__name__}"
    if len(refs) == 0:
        return "evidence_refs must be non-empty"
    return None


# -------- 单例 --------

_default_client: Optional[LLMClient] = None


def get_client() -> LLMClient:
    global _default_client
    if _default_client is None:
        _default_client = LLMClient()
    return _default_client
