"""组件 10 Day 1 端到端：基于 approved 提议 + 异常池样本，调 Qwen 生成 parser candidate。

前置：
  - 至少一个 approved Proposal 在 data/proposals.duckdb（必含 source_signals）
  - 异常池 data/anomaly_pool.duckdb 含对应 event_id 的样本
  - 升级后的本体 ontology/v1.X.yaml 已存在

输出：
  parsers/generated/<candidate_id_short>.yaml
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from core.ontology_service import get_service              # noqa: E402
from evolution.parser_generator import ParserGenerator     # noqa: E402
from parsers.windows_parser import ParserConfig, MAPPINGS_DIR  # noqa: E402
from reasoning.llm_client import get_client                # noqa: E402
from storage.anomaly_pool import AnomalyPool               # noqa: E402
from storage.candidate_parser_store import CandidateParserStore  # noqa: E402
from storage.proposal_store import ProposalStore           # noqa: E402


_EVENT_ID_RE = re.compile(r":(\d+)$")


def _event_ids_from_signals(signals: list[str]) -> list[int]:
    """从 source_signals (e.g. 'data:unparseable_event:4698') 抽出 event_id 列表。"""
    out: list[int] = []
    for s in signals or []:
        m = _EVENT_ID_RE.search(s)
        if m:
            out.append(int(m.group(1)))
    return out


def main() -> int:
    from evolution.pipeline_ops import generate_candidates
    from reasoning.llm_client import get_client

    llm = get_client()
    res = generate_candidates(llm=llm)  # 服务层：CLI 与 UI 共用

    for d in res.details:
        print(f"  - {d}")
    u = llm.usage
    print(f"\n[LLM] calls={u.calls}  total={u.total_tokens}")
    print(f"[summary] inserted={res.inserted}  dropped={res.dropped}  "
          f"skipped={res.skipped}")
    if res.inserted == 0 and res.skipped == 0 and res.dropped == 0:
        print("[STOP] 没有可生成候选的 approved 提议；先在 UI 演化页 approve。")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
