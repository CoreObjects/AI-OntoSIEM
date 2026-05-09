"""组件 10 Day 5：全管线 orchestrator —— 一条命令从零跑到回放对比。

阶段：
  P1 数据生成   generate_demo_data.py
  P2 解析       run_parser.py
  P3 检测       run_detection.py
  P4 研判 v1.0  run_judgments.py            （真调 LLM ~65K tokens）
  P5 提议       run_proposals.py            （真调 LLM ~3K tokens）
  P6 自动审批 ScheduledTask 提议 → ontology/v1.1.yaml
  P7 候选 parser    generate_parser.py     （真调 LLM ~3K tokens）
  P8 自动审批 candidate parser → parsers/generated/<id>.yaml
  P9 回放       replay_anomaly_pool.py
  P10 重判+diff run_replay_validator.py     （真调 LLM ~70K tokens）
  P11 回滚检查  check_rollback.py

总 LLM 成本：~140K tokens（< 1M 额度 14%）

用法：
    python scripts/run_full_pipeline.py                 # 跳过已存在的产物
    python scripts/run_full_pipeline.py --from-scratch  # 清空所有 db 后从头跑
    python scripts/run_full_pipeline.py --skip P4 P10   # 跳过指定步骤
    python scripts/run_full_pipeline.py --dry-run       # 只打印计划不执行
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PYTHON = sys.executable


# =========================================================
# 步骤定义
# =========================================================

@dataclass
class Step:
    code: str            # P1 / P2 / ...
    name: str
    skip_if: Optional[Callable[[], bool]]   # True 表示已经跑过可跳过
    runner: Callable[[], int]               # 返回 exit code
    estimated_tokens: int = 0


def _exists(*paths: Path) -> bool:
    return all(p.exists() for p in paths)


def _run_script(name: str) -> int:
    cmd = [PYTHON, str(ROOT / "scripts" / name)]
    print(f"  → {' '.join(cmd)}")
    return subprocess.call(cmd)


def _approve_scheduledtask_proposal() -> int:
    """P6：自动审批 ScheduledTask node 提议 → ontology/v1.1.yaml。"""
    from core.ontology_service import get_service
    from evolution.ontology_upgrader import OntologyUpgrader
    from evolution.review_actions import approve_and_upgrade
    from storage.proposal_store import ProposalStore

    svc = get_service()
    store = ProposalStore()
    upgrader = OntologyUpgrader(ontology_dir=ROOT / "ontology", service=svc)

    pending = [r for r in store.list_by_status("pending")
               if r["name"] == "ScheduledTask" and r["proposal_type"] == "node"]
    if not pending:
        # 已审批 → 跳过
        approved = [r for r in store.list_by_status("approved")
                    if r["name"] == "ScheduledTask"]
        if approved:
            print("  [skip] ScheduledTask 提议已审批")
            return 0
        print("  [ERR] 没有 pending 的 ScheduledTask 提议")
        return 1

    pid = pending[0]["proposal_id"]
    new_path = approve_and_upgrade(store, pid, upgrader)
    print(f"  [OK] 自动审批 {pid[:8]} → {new_path.name}")
    return 0


def _approve_first_pending_candidate() -> int:
    """P8：自动审批第一条 pending 候选 parser → parsers/generated/<id>.yaml。"""
    from evolution.parser_review_actions import approve_and_apply
    from storage.candidate_parser_store import CandidateParserStore

    store = CandidateParserStore()
    pending = store.list_by_status("pending")
    if not pending:
        approved = store.list_by_status("approved")
        if approved:
            print("  [skip] 候选 parser 已审批")
            return 0
        print("  [ERR] 没有 pending 候选 parser")
        return 1

    cid = pending[0]["candidate_id"]
    yaml_path = approve_and_apply(store, cid)
    print(f"  [OK] 自动审批 {cid[:8]} → {yaml_path.name}")
    return 0


# =========================================================
# Pipeline definition
# =========================================================

def build_pipeline() -> List[Step]:
    return [
        Step(
            "P1", "数据生成 (generate_demo_data)",
            skip_if=lambda: _exists(ROOT / "data" / "events.duckdb"),
            runner=lambda: _run_script("generate_demo_data.py"),
        ),
        Step(
            "P2", "解析 (run_parser)",
            skip_if=lambda: _exists(ROOT / "data" / "parsed_events.duckdb"),
            runner=lambda: _run_script("run_parser.py"),
        ),
        Step(
            "P3", "Sigma 检测 (run_detection)",
            skip_if=lambda: _exists(ROOT / "data" / "alerts.duckdb"),
            runner=lambda: _run_script("run_detection.py"),
        ),
        Step(
            "P4", "认知研判 v1.0 (run_judgments) — 真调 LLM",
            skip_if=lambda: _exists(ROOT / "data" / "judgments.duckdb"),
            runner=lambda: _run_script("run_judgments.py"),
            estimated_tokens=65000,
        ),
        Step(
            "P5", "演化提议 (run_proposals) — 真调 LLM",
            skip_if=lambda: _exists(ROOT / "data" / "proposals.duckdb"),
            runner=lambda: _run_script("run_proposals.py"),
            estimated_tokens=3000,
        ),
        Step(
            "P6", "自动审批 ScheduledTask → v1.1",
            skip_if=lambda: _exists(ROOT / "ontology" / "v1.1.yaml"),
            runner=_approve_scheduledtask_proposal,
        ),
        Step(
            "P7", "候选 parser (generate_parser) — 真调 LLM",
            skip_if=lambda: _exists(ROOT / "data" / "candidate_parsers.duckdb"),
            runner=lambda: _run_script("generate_parser.py"),
            estimated_tokens=3000,
        ),
        Step(
            "P8", "自动审批候选 parser → parsers/generated/",
            skip_if=lambda: bool(list((ROOT / "parsers" / "generated").glob("*.yaml"))),
            runner=_approve_first_pending_candidate,
        ),
        Step(
            "P9", "异常池回放 (replay_anomaly_pool)",
            # 回放总是要跑：检查图谱可视化产物存在则跳
            skip_if=lambda: _exists(ROOT / "graph" / "visualization_replay.html"),
            runner=lambda: _run_script("replay_anomaly_pool.py"),
        ),
        Step(
            "P10", "回放验证 (run_replay_validator) — 真调 LLM",
            skip_if=lambda: _exists(ROOT / "data" / "judgments_after_replay.duckdb"),
            runner=lambda: _run_script("run_replay_validator.py"),
            estimated_tokens=71000,
        ),
        Step(
            "P11", "回滚检查 (check_rollback)",
            skip_if=None,  # 总是跑（无副作用，只读）
            runner=lambda: _run_script("check_rollback.py"),
        ),
    ]


def _reset_for_scratch() -> None:
    """清空所有运行产物，回到 git clone 后的干净态。保留 events.duckdb 之外的 db 都删。"""
    print("\n=== 清空产物（--from-scratch）===")
    targets = [
        ROOT / "data" / "events.duckdb",
        ROOT / "data" / "parsed_events.duckdb",
        ROOT / "data" / "alerts.duckdb",
        ROOT / "data" / "anomaly_pool.duckdb",
        ROOT / "data" / "anomaly_pool.duckdb.wal",
        ROOT / "data" / "signals.duckdb",
        ROOT / "data" / "judgments.duckdb",
        ROOT / "data" / "judgments_after_replay.duckdb",
        ROOT / "data" / "proposals.duckdb",
        ROOT / "data" / "candidate_parsers.duckdb",
    ]
    for t in targets:
        if t.exists():
            t.unlink()
            print(f"  rm {t.relative_to(ROOT)}")

    for d in (
        ROOT / "data" / "replay_reports",
        ROOT / "parsers" / "generated",
    ):
        if d.exists():
            for f in d.iterdir():
                if f.is_file():
                    f.unlink()
                    print(f"  rm {f.relative_to(ROOT)}")

    # 删 v1.1+ ontology yaml（保留 v1.0）
    for y in (ROOT / "ontology").glob("v*.yaml"):
        if y.name != "v1.0.yaml":
            y.unlink()
            print(f"  rm {y.relative_to(ROOT)}")

    # 删 graph HTML
    for h in (ROOT / "graph").glob("*.html"):
        h.unlink()
        print(f"  rm {h.relative_to(ROOT)}")

    print("[OK] 清空完成")


# =========================================================
# 主入口
# =========================================================

def main() -> int:
    ap = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                 description=__doc__)
    ap.add_argument("--from-scratch", action="store_true",
                    help="清空所有运行产物后从头跑")
    ap.add_argument("--skip", nargs="+", default=[],
                    metavar="STEP", help="跳过指定步骤代码（如 P4 P10）")
    ap.add_argument("--dry-run", action="store_true",
                    help="只打印计划不执行")
    args = ap.parse_args()

    if args.from_scratch:
        if not args.dry_run:
            _reset_for_scratch()

    pipeline = build_pipeline()
    skip_set = {s.upper() for s in args.skip}

    print("\n=== 全管线 orchestrator · 计划 ===")
    total_tokens = 0
    plan: List[tuple] = []
    for step in pipeline:
        if step.code in skip_set:
            verdict = "SKIP (--skip)"
        elif step.skip_if is not None and step.skip_if():
            verdict = "SKIP (产物已存在)"
        else:
            verdict = "RUN"
            total_tokens += step.estimated_tokens
        plan.append((step, verdict))
        token_str = (f" ~{step.estimated_tokens // 1000}K"
                     if step.estimated_tokens else "")
        print(f"  [{step.code:4s}] {step.name:50s}  {verdict}{token_str}")
    print(f"\n  预计 LLM 消耗：~{total_tokens // 1000}K tokens")

    if args.dry_run:
        print("\n[dry-run] 不执行")
        return 0

    print("\n=== 开始执行 ===\n")
    t0 = time.monotonic()
    failed: List[str] = []
    for step, verdict in plan:
        if verdict.startswith("SKIP"):
            continue
        print(f"\n--- [{step.code}] {step.name} ---")
        sub_t0 = time.monotonic()
        rc = step.runner()
        elapsed = time.monotonic() - sub_t0
        if rc == 0:
            print(f"  [OK] {step.code} 完成 ({elapsed:.1f}s)")
        else:
            print(f"  [FAIL] {step.code} 退出码 {rc} ({elapsed:.1f}s)")
            failed.append(step.code)
            print("\n[ABORT] 失败步骤会让后面依赖产物缺失，停止管线。")
            break

    total = time.monotonic() - t0
    print(f"\n=== 全管线结束 · {total:.1f}s ===")
    if failed:
        print(f"  失败步骤：{', '.join(failed)}")
        return 1
    print("  全部步骤成功 ✅")
    return 0


if __name__ == "__main__":
    sys.exit(main())
