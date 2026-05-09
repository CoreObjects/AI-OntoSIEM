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

from evolution.replay_validator import ValidatorReport      # noqa: E402
from evolution.rollback_proposer import assess_for_rollback  # noqa: E402

REPORTS_DIR = ROOT / "data" / "replay_reports"


def _load_report(path: Path) -> ValidatorReport:
    data = json.loads(path.read_text(encoding="utf-8"))
    return ValidatorReport(
        started_at=data.get("started_at", ""),
        finished_at=data.get("finished_at", ""),
        ontology_version_before=data.get("ontology_version_before", ""),
        ontology_version_after=data.get("ontology_version_after", ""),
        pool_open_before=int(data.get("pool_open_before", 0)),
        pool_open_after=int(data.get("pool_open_after", 0)),
        rejudged_count=int(data.get("rejudged_count", 0)),
        verdict_changes=[],   # 摘要不需要逐条
        verdict_unchanged=int(data.get("verdict_unchanged", 0)),
        verdict_upgraded=int(data.get("verdict_upgraded", 0)),
        verdict_downgraded=int(data.get("verdict_downgraded", 0)),
        semantic_gap_cleared=int(data.get("semantic_gap_cleared", 0)),
        semantic_gap_persisted=int(data.get("semantic_gap_persisted", 0)),
        avg_evidence_refs_before=float(data.get("avg_evidence_refs_before", 0.0)),
        avg_evidence_refs_after=float(data.get("avg_evidence_refs_after", 0.0)),
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", type=Path, default=None,
                    help="ValidatorReport JSON 路径（默认取最新）")
    ap.add_argument("--min-rejudged", type=int, default=5)
    args = ap.parse_args()

    if args.report:
        path = args.report
    else:
        files = sorted(REPORTS_DIR.glob("validator_*.json"))
        if not files:
            print("ERROR: 没找到 validator 报告。先跑 scripts/run_replay_validator.py。")
            return 1
        path = files[-1]

    print(f"[input] {path}")
    report = _load_report(path)
    print(f"[metrics] v{report.ontology_version_before} → v{report.ontology_version_after}")
    print(f"  rejudged: {report.rejudged_count}")
    print(f"  verdict:  upgraded={report.verdict_upgraded}  "
          f"downgraded={report.verdict_downgraded}  "
          f"unchanged={report.verdict_unchanged}")
    print(f"  semantic_gap: cleared={report.semantic_gap_cleared}  "
          f"persisted={report.semantic_gap_persisted}")
    print(f"  avg_refs: {report.avg_evidence_refs_before:.2f} → "
          f"{report.avg_evidence_refs_after:.2f}")

    proposal = assess_for_rollback(report, require_min_rejudged=args.min_rejudged)
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
