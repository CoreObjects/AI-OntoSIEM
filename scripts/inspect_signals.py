"""信号中枢热力图（终端文字版看板入口）。

用法：
    python scripts/inspect_signals.py               # 默认 24h 窗口 + 阈值 10
    python scripts/inspect_signals.py --threshold 5

信号数据源：data/signals.duckdb
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Windows 终端（cp936）下中文会乱码；强制 stdout 走 UTF-8
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
except Exception:
    pass

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from evolution.signal_hub import SignalHub  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--window", type=int, default=24, help="时间窗口（小时）")
    ap.add_argument("--threshold", type=int, default=10, help="待处理阈值")
    args = ap.parse_args()

    hub = SignalHub()

    total = hub.count_all()
    print(f"=== 信号中枢 · 数据库 {hub._db_path.relative_to(ROOT)} ===")  # type: ignore[attr-defined]
    print(f"总信号数：{total}")
    if total == 0:
        print("(无信号。请先跑 scripts/run_parser.py 和 scripts/run_judgments.py)")
        return 0

    print()
    print("按 priority（冷热分级）：")
    for pri, cnt in sorted(hub.count_by_priority().items(),
                           key=lambda kv: ["hot", "warm", "cold"].index(kv[0])):
        bar = "█" * min(cnt, 40)
        print(f"  {pri:6s} {cnt:4d}  {bar}")

    print()
    print("按 signal_type：")
    for t, cnt in sorted(hub.count_by_type().items(), key=lambda kv: -kv[1]):
        print(f"  {t:28s} {cnt}")

    print()
    print(f"聚合热力图（窗口 {args.window}h · 按 count desc）：")
    groups = hub.list_aggregations(window_hours=args.window, min_count=1)
    if not groups:
        print("  (窗口内无信号)")
    else:
        for g in groups[:30]:
            flag = "[DONE]" if g["processed"] else "[TODO]"
            bar = "█" * min(g["count"], 40)
            print(f"  {g['aggregation_key']:55s} {g['count']:4d}  {g['priority']:5s}  {flag}  {bar}")

    print()
    print(f">>> 待处理聚合组（窗口 {args.window}h · 阈值 {args.threshold}）：")
    pending = hub.list_pending(window_hours=args.window, threshold=args.threshold)
    if not pending:
        print("  (无)")
    else:
        for p in pending:
            print(f"  {p['aggregation_key']:55s} count={p['count']}  "
                  f"first={p['first_seen']}  last={p['last_seen']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
