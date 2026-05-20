"""把项目状态一键重置回"演化前 v1.0 起跑线"，给现场演化直播 Demo 用。

当前磁盘常是 v1.1 终态（提议已审批 / Parser 已生成 / 异常池已回填 / 重判已跑）。
本脚本精确撤销这些演化产物，让你直接 `streamlit run ui/main.py` 就能从 0:00
开始按 docs/demo_script.md 的剧本现场演化。

会重置（撤销演化）：
  - ontology/        删 v1.1+ .yaml（保留 v1.0.yaml / cmdb.yaml）
  - proposals.duckdb 全部提议状态改回 pending（撤销 approve_and_upgrade）
  - parsers/generated/ 删全部 .yaml（撤销 candidate parser apply）
  - candidate_parsers.duckdb / judgments_after_replay.duckdb 删除
  - anomaly_pool.duckdb  reset_backfilled() → 异常池回到全 open（如 32）
  - signals.duckdb   删 manual_annotation 信号（反馈采纳率回 0%）
  - replay_reports/  删 validator_*.json / rollback_*.json
  - graph/visualization_replay.html 删（演化中由 replay 脚本重生）

会保留（演化前就该在的上游产物，缺了会警告）：
  - events.duckdb / parsed_events.duckdb / alerts.duckdb / judgments.duckdb(v1.0)
  - proposals.duckdb 本身（只改状态，不删——保留确定性，不重调 LLM）

用法：
    python scripts/reset_for_demo.py            # 执行重置
    python scripts/reset_for_demo.py --dry-run  # 只打印将做什么，不动文件
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import duckdb  # noqa: E402

DATA = ROOT / "data"
ONTOLOGY = ROOT / "ontology"
GENERATED_PARSERS = ROOT / "parsers" / "generated"
GRAPH = ROOT / "graph"
REPORTS = DATA / "replay_reports"

PROPOSALS_DB = DATA / "proposals.duckdb"
SIGNALS_DB = DATA / "signals.duckdb"
ANOMALY_DB = DATA / "anomaly_pool.duckdb"

# 演化前必须在的上游产物（缺了 Demo 跑不起来）
REQUIRED_UPSTREAM = {
    "events.duckdb": "python scripts/generate_demo_data.py",
    "parsed_events.duckdb": "python scripts/run_parser.py",
    "alerts.duckdb": "python scripts/run_detection.py",
    "judgments.duckdb": "python scripts/run_judgments.py",
    "proposals.duckdb": "python scripts/run_proposals.py",
}


class _Ctx:
    def __init__(self, dry_run: bool) -> None:
        self.dry = dry_run

    def rm_file(self, p: Path) -> bool:
        if not p.exists():
            return False
        if self.dry:
            print(f"  [dry] rm {p.relative_to(ROOT)}")
            return True
        p.unlink()
        print(f"  [DONE] rm {p.relative_to(ROOT)}")
        return True


# =========================================================
# 各重置步骤
# =========================================================

def reset_ontology(ctx: _Ctx) -> None:
    print("\n[1/8] ontology/ —— 删 v1.1+ ，保留 v1.0")
    removed = 0
    for y in sorted(ONTOLOGY.glob("v*.yaml")):
        if y.name == "v1.0.yaml":
            continue
        ctx.rm_file(y)
        removed += 1
    if removed == 0:
        print("  [skip] 已只剩 v1.0（无 v1.1+）")


def reset_proposals(ctx: _Ctx) -> None:
    print("\n[2/8] proposals.duckdb —— 全部状态改回 pending")
    if not PROPOSALS_DB.exists():
        print("  [WARN] proposals.duckdb 不存在，先跑 run_proposals.py")
        return
    con = duckdb.connect(str(PROPOSALS_DB))
    try:
        before = dict(con.execute(
            "SELECT status, COUNT(*) FROM proposals GROUP BY status"
        ).fetchall())
        print(f"  当前状态分布：{before or '(空)'}")
        if not ctx.dry:
            con.execute(
                "UPDATE proposals SET status = 'pending', rejection_reason = NULL "
                "WHERE status != 'pending'"
            )
            after = dict(con.execute(
                "SELECT status, COUNT(*) FROM proposals GROUP BY status"
            ).fetchall())
            print(f"  [DONE] 重置后：{after or '(空)'}")
        else:
            print("  [dry] 将把所有非 pending 提议改回 pending")
    except duckdb.CatalogException:
        print("  [WARN] proposals 表不存在")
    finally:
        con.close()


def reset_generated_parsers(ctx: _Ctx) -> None:
    print("\n[3/8] parsers/generated/ —— 删全部 .yaml")
    n = 0
    if GENERATED_PARSERS.exists():
        for y in sorted(GENERATED_PARSERS.glob("*.yaml")):
            ctx.rm_file(y)
            n += 1
    if n == 0:
        print("  [skip] 已空")


def reset_candidate_and_after_dbs(ctx: _Ctx) -> None:
    print("\n[4/8] 删 candidate_parsers / judgments_after_replay（含 .wal）")
    any_hit = False
    for stem in ("candidate_parsers.duckdb", "judgments_after_replay.duckdb"):
        any_hit |= ctx.rm_file(DATA / stem)
        any_hit |= ctx.rm_file(DATA / (stem + ".wal"))
    if not any_hit:
        print("  [skip] 无可删")


def reset_anomaly_pool(ctx: _Ctx) -> None:
    print("\n[5/8] anomaly_pool —— reset_backfilled（回到全 open）")
    if not ANOMALY_DB.exists():
        print("  [WARN] anomaly_pool.duckdb 不存在，先跑 run_parser.py")
        return
    from storage.anomaly_pool import AnomalyPool
    pool = AnomalyPool()
    try:
        open_before, total = pool.size_open(), pool.size_total()
        if ctx.dry:
            print(f"  [dry] 当前 open={open_before} / total={total} → 将翻回全 open")
        else:
            pool.reset_backfilled()
            print(f"  [DONE] open {open_before} → {pool.size_open()} / total={total}")
    finally:
        pool.close()


def reset_feedback_signals(ctx: _Ctx) -> None:
    print("\n[6/8] signals.duckdb —— 删 manual_annotation（反馈采纳率回 0%）")
    if not SIGNALS_DB.exists():
        print("  [skip] signals.duckdb 不存在")
        return
    con = duckdb.connect(str(SIGNALS_DB))
    try:
        n = con.execute(
            "SELECT COUNT(*) FROM signals WHERE signal_type = 'manual_annotation'"
        ).fetchone()[0]
        if n == 0:
            print("  [skip] 无 manual_annotation 信号")
        elif ctx.dry:
            print(f"  [dry] 将删 {n} 条 manual_annotation 信号")
        else:
            con.execute("DELETE FROM signals WHERE signal_type = 'manual_annotation'")
            print(f"  [DONE] 删 {n} 条 manual_annotation 信号")
    except duckdb.CatalogException:
        print("  [skip] signals 表不存在")
    finally:
        con.close()


def reset_reports_and_html(ctx: _Ctx) -> None:
    print("\n[7/8] replay_reports/ + graph 回放 HTML")
    n = 0
    if REPORTS.exists():
        for pat in ("validator_*.json", "rollback_*.json"):
            for f in sorted(REPORTS.glob(pat)):
                ctx.rm_file(f)
                n += 1
    if ctx.rm_file(GRAPH / "visualization_replay.html"):
        n += 1
    if n == 0:
        print("  [skip] 无可删")


def verify(ctx: _Ctx) -> None:
    print("\n[8/8] 校验起跑线状态")
    # 上游产物齐全？
    missing = []
    for fname, cmd in REQUIRED_UPSTREAM.items():
        if not (DATA / fname).exists():
            missing.append((fname, cmd))
    if missing:
        print("  [WARN] 缺少上游产物（Demo 前请先补齐）：")
        for fname, cmd in missing:
            print(f"    - {fname}  ←  {cmd}")
    else:
        print("  [OK] 上游产物齐全（events/parsed/alerts/judgments/proposals）")

    # 本体只剩 v1.0？
    versions = sorted(y.name for y in ONTOLOGY.glob("v*.yaml"))
    print(f"  本体版本：{versions}")

    # 提议状态分布
    if PROPOSALS_DB.exists():
        con = duckdb.connect(str(PROPOSALS_DB), read_only=True)
        try:
            dist = dict(con.execute(
                "SELECT status, COUNT(*) FROM proposals GROUP BY status"
            ).fetchall())
            print(f"  提议状态：{dist}")
        except duckdb.CatalogException:
            pass
        finally:
            con.close()

    # 异常池
    if ANOMALY_DB.exists():
        con = duckdb.connect(str(ANOMALY_DB), read_only=True)
        try:
            o = con.execute("SELECT COUNT(*) FROM anomaly_pool WHERE backfilled = FALSE").fetchone()[0]
            t = con.execute("SELECT COUNT(*) FROM anomaly_pool").fetchone()[0]
            print(f"  异常池：open={o} / total={t}")
        finally:
            con.close()


# =========================================================
# 主入口
# =========================================================

def _runbook() -> None:
    print("\n" + "=" * 60)
    print("起跑线就绪。现场演化直播动线（全程点按钮、零终端；详见 docs/demo_script.md）：")
    print("=" * 60)
    print("""
  只开一个终端：streamlit run ui/main.py  （浏览器 localhost:8501）
  演化每一步都是 UI 按钮，演示时不用再切终端。

  0:00  📊 评测看板：异常池 32 / 反馈 0%
  0:30  📐 本体演化 → 🆕 提议审核 → 点【✅ 通过】ScheduledTask → banner 跳 v1.1
  1:00  📐 → 🔧 候选 Parser → 点【🤖 生成候选 Parser】→ 抽样回放 → 【Approve & Apply】
  2:30  📐 → 🔁 回放与验证 → 点【▶ 回放异常池】→ 异常池 32 → 10
  3:00  🛡️ 告警研判 → 点【🔄 重建图谱】→ HR-WS-01 出现孤岛 ScheduledTask 节点
  3:30  📐 → 🔁 回放与验证 → 点【🔬 回放重判 + 对比】→ 实时进度条「重判 N/10」→ diff
  3:50  📐 → 🔁 回放与验证 → 点【🛡 回滚检查】→ RollbackProposal WARNING
  4:00  🛡️ 告警研判：选一条告警写 notes → 点 👎
  4:30  📊 评测看板：反馈采纳率 0% → 飞起

  ※ 重判按钮真调 LLM ~4 分钟，进度条实时跳，边讲架构边等。
  ※ verdict 每次跑不同（LLM 非确定性）：降级了讲 R5 代价，没降讲安全增量。
  ※ 异常池 32→10、回滚提议 WARNING 是确定性兜底叙事。
""")


def main() -> int:
    ap = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__,
    )
    ap.add_argument("--dry-run", action="store_true",
                    help="只打印将做什么，不实际改动")
    args = ap.parse_args()

    ctx = _Ctx(dry_run=args.dry_run)
    mode = "DRY-RUN（不改动）" if args.dry_run else "执行重置"
    print(f"=== reset_for_demo · {mode} ===")

    reset_ontology(ctx)
    reset_proposals(ctx)
    reset_generated_parsers(ctx)
    reset_candidate_and_after_dbs(ctx)
    reset_anomaly_pool(ctx)
    reset_feedback_signals(ctx)
    reset_reports_and_html(ctx)
    verify(ctx)

    if not args.dry_run:
        _runbook()
    else:
        print("\n[dry-run] 未改动任何文件。去掉 --dry-run 即执行。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
