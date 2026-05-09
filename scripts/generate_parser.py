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
    svc = get_service()
    onto = svc.get_current()
    print(f"[onto] v{onto.version}  nodes={len(onto.nodes)}  edges={len(onto.edges)}")

    store = ProposalStore()
    approved = store.list_by_status("approved")
    if not approved:
        print("[STOP] 没有 approved 提议；先跑 Streamlit UI 审批，或手动 approve。")
        return 1

    pool = AnomalyPool()
    candidate_store = CandidateParserStore()
    cfg = ParserConfig.load_all([MAPPINGS_DIR])
    llm = get_client()
    gen = ParserGenerator(llm=llm, ontology=onto)

    n_ok = n_drop = n_skip = 0
    for row in approved:
        proposal = store.as_proposal(row["proposal_id"])
        if proposal is None:
            continue

        # 已有同 proposal 的 pending 或 approved 候选 → 跳过（避免重复花 token）
        existing = candidate_store.list_by_proposal(proposal.proposal_id)
        active = [r for r in existing if r["status"] in ("pending", "approved")]
        if active:
            print(f"  - skip {proposal.name}: 已存在 {len(active)} 条 active 候选")
            n_skip += 1
            continue

        # 收集 event_id → anomaly 样本
        event_ids = _event_ids_from_signals(proposal.source_signals)
        if not event_ids:
            print(f"  - skip {proposal.name}: source_signals 没 event_id 后缀")
            continue
        samples: list[dict] = []
        for eid in event_ids:
            samples.extend(pool.list_by_event_id(eid, limit=10))
        if not samples:
            print(f"  - skip {proposal.name}: 异常池没有 event_id={event_ids} 的样本")
            continue

        print(f"\n[generate] {proposal.name}  ({proposal.proposal_type})  "
              f"events={event_ids}  samples={len(samples)}")
        candidate = gen.generate(
            approved_proposal=proposal,
            anomaly_samples=samples,
            current_parser_config=cfg,
        )
        if candidate is None:
            print(f"  ❌ 闸门 reject")
            n_drop += 1
            continue

        candidate_store.insert(candidate)
        n_ok += 1
        print(f"  [OK] candidate {candidate.candidate_id[:8]}  status=pending  "
              f"conf={candidate.confidence}  rules={len(candidate.rules)}  "
              f"stripped_rels={len(candidate.stripped_relations)}")
        for r in candidate.rules:
            ents = [e.get("ref_name") or e["node"] for e in r.get("entities") or []]
            rels = [f"{rel['edge']}:{rel['from_ref']}->{rel['to_ref']}"
                    for rel in r.get("relations") or []]
            print(f"     - {r['name']}  entities={ents}  rels={rels}")
        for s in candidate.stripped_relations:
            print(f"     - [STRIP] {s['edge']}: {s.get('from_ref')}->{s.get('to_ref')}")
            print(f"              {s['reason']}")

    u = llm.usage
    print(f"\n[LLM] calls={u.calls}  prompt={u.prompt_tokens}  "
          f"completion={u.completion_tokens}  total={u.total_tokens}")
    print(f"[summary] {n_ok} new candidates inserted, {n_drop} dropped, {n_skip} skipped")
    print(f"          total in store: {candidate_store.count()}  "
          f"by status: {candidate_store.count_by_status()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
