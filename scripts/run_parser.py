"""运行 Windows 解析器：events.duckdb → parsed_events.duckdb + anomaly_pool.duckdb + signals.duckdb。

运行前确保 scripts/generate_demo_data.py 已经跑过。

    python scripts/run_parser.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# 先清理上次的 anomaly_pool 和 signals（避免累加，demo 从零开始）
for p in [ROOT / "data" / "anomaly_pool.duckdb", ROOT / "data" / "signals.duckdb"]:
    if p.exists():
        p.unlink()

from parsers.windows_parser import parse_database, DEFAULT_PARSED_DB  # noqa: E402
from storage.anomaly_pool import AnomalyPool  # noqa: E402
from evolution.signal_hub import SignalHub  # noqa: E402

EVENTS_DB = ROOT / "data" / "events.duckdb"


def main() -> int:
    if not EVENTS_DB.exists():
        print(f"ERROR: {EVENTS_DB} not found. Run scripts/generate_demo_data.py first.")
        return 1

    print(f"[parser] reading from {EVENTS_DB}")
    stats = parse_database(EVENTS_DB, DEFAULT_PARSED_DB)
    print(f"[parser] stats: {stats}")

    pool = AnomalyPool()
    print(f"[anomaly_pool] open records: {pool.size_open()}")
    print(f"[anomaly_pool] by event_id:  {pool.count_by_event_id()}")

    hub = SignalHub()
    print(f"[signals] total: {hub.count_all()}")
    print(f"[signals] by type: {hub.count_by_type()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
