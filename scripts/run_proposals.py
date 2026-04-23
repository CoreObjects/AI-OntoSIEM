"""运行本体演化提议：读 signals + ontology + rejection_names → LLM 提议 → proposals.duckdb。

运行前需要：
    python scripts/run_parser.py     # 产 unparseable_event 信号
    python scripts/run_judgments.py  # 产 semantic_gap 信号（可选，但推荐）

用法：
    python scripts/run_proposals.py              # 24h 窗口 + 阈值 10
    python scripts/run_proposals.py --threshold 5
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
except Exception:
    pass

from core.ontology_service import get_service  # noqa: E402
from evolution.proposer import ProposalEngine  # noqa: E402
from evolution.signal_hub import get_hub  # noqa: E402
from reasoning.llm_client import get_client  # noqa: E402
from storage.proposal_store import ProposalStore  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--window", type=int, default=24)
    ap.add_argument("--threshold", type=int, default=10)
    args = ap.parse_args()

    hub = get_hub()
    onto = get_service().get_current()
    store = ProposalStore()

    rejection_names = store.rejection_names()
    print(f"[proposer] ontology v{onto.version} · "
          f"rejection history: {len(rejection_names)} names")

    engine = ProposalEngine(
        llm=get_client(),
        signal_hub=hub,
        ontology=onto,
        rejection_names=rejection_names,
    )

    pending = hub.list_pending(window_hours=args.window, threshold=args.threshold)
    print(f"[proposer] pending signal groups (window={args.window}h, threshold={args.threshold}): "
          f"{len(pending)}")
    for g in pending:
        print(f"  - {g['aggregation_key']:55s} count={g['count']}  priority={g['priority']}")

    if not pending:
        print("\n[proposer] nothing to propose.")
        return 0

    props = engine.generate(window_hours=args.window, threshold=args.threshold)
    print(f"\n[proposer] LLM produced {len(props)} proposal(s) after 4 gates:")
    for p in props:
        print(f"\n--- {p.proposal_id[:8]}  [{p.proposal_type}] {p.name}")
        print(f"    定义: {p.semantic_definition}")
        print(f"    证据: {len(p.supporting_evidence)} 条")
        print(f"    重叠: " + ", ".join(
            f"{k}={v:.2f}" for k, v in sorted(
                p.overlap_analysis.items(), key=lambda kv: -kv[1]
            )[:3]
        ))
        print(f"    ATT&CK: {p.attack_mapping}")
        print(f"    来源信号: {p.source_signals}")
        store.insert(p)

    print(f"\n[proposer] persisted {len(props)} proposals to {store._db_path.name}")  # type: ignore[attr-defined]
    print(f"[proposer] store state: {store.count_by_status()}")
    print(f"[llm] usage: {get_client().usage}")
    store.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
