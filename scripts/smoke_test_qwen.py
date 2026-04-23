"""Qwen-Plus 冒烟测试：验证 API 可用 + structured output 能跑 + token 计数正常。

运行：
    python scripts/smoke_test_qwen.py
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")

from openai import OpenAI  # noqa: E402

API_KEY = os.environ.get("DASHSCOPE_API_KEY")
BASE_URL = os.environ.get("DASHSCOPE_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1")
MODEL = os.environ.get("LLM_MODEL", "qwen-plus-2025-07-28")


def main() -> int:
    if not API_KEY:
        print("ERROR: DASHSCOPE_API_KEY not set in .env")
        return 1

    client = OpenAI(api_key=API_KEY, base_url=BASE_URL)

    schema_hint = (
        "你必须只回复一个符合下述 JSON schema 的 JSON 对象，不要有任何其他文字：\n"
        '{"verdict":"benign|suspicious|malicious",'
        '"confidence":float(0..1),'
        '"reasoning_steps":[string],'
        '"evidence_refs":[string]}'
    )

    alert_sample = (
        "Windows 安全事件: EventID=4624, LogonType=3, "
        "Account=svc_backup, Host=FIN-SRV-01, "
        "SourceIP=10.3.5.44, Time=2026-04-22T02:13:07Z"
    )

    print(f"[1/3] Model: {MODEL}")
    print(f"[2/3] Endpoint: {BASE_URL}")
    print(f"[3/3] Calling Qwen-Plus...")

    resp = client.chat.completions.create(
        model=MODEL,
        messages=[
            {"role": "system", "content": schema_hint},
            {"role": "user", "content": f"请对下列告警做快速研判：\n{alert_sample}"},
        ],
        response_format={"type": "json_object"},
        temperature=0.1,
        max_tokens=512,
    )

    content = resp.choices[0].message.content or ""
    usage = resp.usage
    print("\n===== Response =====")
    print(content)
    print("\n===== Usage =====")
    print(f"prompt_tokens:     {usage.prompt_tokens}")
    print(f"completion_tokens: {usage.completion_tokens}")
    print(f"total_tokens:      {usage.total_tokens}")

    try:
        parsed = json.loads(content)
        required = {"verdict", "confidence", "reasoning_steps", "evidence_refs"}
        missing = required - parsed.keys()
        if missing:
            print(f"\nWARN: JSON missing keys: {missing}")
            return 2
        print("\nOK: structured output schema valid")
        return 0
    except json.JSONDecodeError as e:
        print(f"\nFAIL: cannot parse JSON: {e}")
        return 3


if __name__ == "__main__":
    sys.exit(main())
