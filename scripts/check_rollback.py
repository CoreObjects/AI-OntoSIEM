"""组件 10 Day 5：回滚检查脚本。

读最新 ValidatorReport JSON → 跑 assess_for_rollback → 打印 + 落盘提议。

用法：
    python scripts/check_rollback.py
    python scripts/check_rollback.py --report data/replay_reports/validator_xxx.json

不自动 apply 回滚 —— 仅产候选给审核员看。
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from evolution.pipeline_ops import REPORTS_DIR, latest_rollback_assessment  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--min-rejudged", type=int, default=5)
    args = ap.parse_args()

    proposal = latest_rollback_assessment(reports_dir=REPORTS_DIR,
                                          require_min_rejudged=args.min_rejudged)
    if not REPORTS_DIR.exists() or not list(REPORTS_DIR.glob("validator_*.json")):
        print("ERROR: 没找到 validator 报告。先跑 scripts/run_replay_validator.py。")
        return 1

    if proposal is None:
        print("\n[OK] 不触发回滚（指标无显著恶化）。")
        return 0

    print(f"\n=== ⚠️  RollbackProposal · {proposal.severity.upper()} ===")
    print(f"  proposal_id    : {proposal.proposal_id[:8]}")
    print(f"  target_version : v{proposal.target_version}")
    print(f"  current_version: v{proposal.current_version}")
    print(f"  rationale:")
    for line in proposal.rationale.splitlines():
        print(f"    {line}")

    out_dir = REPORTS_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = out_dir / f"rollback_{ts}.json"
    out_path.write_text(
        json.dumps(proposal.to_dict(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"\n[written] {out_path}")
    print("\n[next] 人工审核此提议；如确认要回滚：")
    print(f"  - 删除 ontology/v{proposal.current_version}.yaml")
    print(f"  - 重启 streamlit（OntologyService 会重读 v{proposal.target_version} 为 latest）")
    print(f"  - parsers/generated/ 下 triggered_by_ontology_version="
          f"v{proposal.current_version} 的 YAML 也建议删")
    return 0


if __name__ == "__main__":
    sys.exit(main())
