"""运行检测引擎：events.duckdb → alerts.duckdb（+ 向 signal_hub 上报 rule_schema_mismatch）。

运行前需要：
    python scripts/generate_demo_data.py   # 生成 events.duckdb
    python scripts/run_parser.py           # 解析入库（可选，告警直接跑原始事件即可）

用法：
    python scripts/run_detection.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import duckdb  # noqa: E402

from core.ontology_service import get_service  # noqa: E402
from detection.engine import DetectionEngine  # noqa: E402
from evolution.signal_hub import get_hub  # noqa: E402
from storage.alert_store import AlertStore  # noqa: E402

EVENTS_DB = ROOT / "data" / "events.duckdb"
ALERTS_DB = ROOT / "data" / "alerts.duckdb"
RULES_DIR = ROOT / "detection" / "rules"


def _row_to_event(r: tuple) -> dict:
    ed = r[6]
    if isinstance(ed, str):
        try:
            ed = json.loads(ed)
        except json.JSONDecodeError:
            ed = {}
    return {
        "event_id": r[0],
        "channel": r[1],
        "provider": r[2],
        "record_number": r[3],
        "timestamp": r[4],
        "computer": r[5],
        "event_data": ed,
    }


def main() -> int:
    if not EVENTS_DB.exists():
        print(f"ERROR: {EVENTS_DB} not found. Run scripts/generate_demo_data.py first.")
        return 1
    if ALERTS_DB.exists():
        ALERTS_DB.unlink()

    onto = get_service().get_current()
    hub = get_hub()
    engine = DetectionEngine(rules_dir=RULES_DIR, ontology=onto, signal_hub=hub)
    print(f"[detection] loaded {len(engine.rules)} rules (ontology v{onto.version})")
    for r in engine.rules:
        print(f"  - {r.id:40s}  {r.level:8s}  {','.join(r.attack_techniques)}")

    con = duckdb.connect(str(EVENTS_DB), read_only=True)
    rows = con.execute(
        "SELECT event_id, channel, provider, record_number, timestamp, computer, event_data "
        "FROM events ORDER BY record_number"
    ).fetchall()
    con.close()

    store = AlertStore(db_path=ALERTS_DB)
    total_alerts = 0
    for r in rows:
        event = _row_to_event(r)
        alerts = engine.evaluate_event(event)
        if alerts:
            store.insert_many(alerts)
            total_alerts += len(alerts)

    print(f"[detection] total events scanned: {len(rows)}")
    print(f"[detection] alerts produced:      {total_alerts}")
    print(f"[detection] by technique:         {store.count_by_technique()}")
    store.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
