"""组件 10 服务层：演化管线四步编排，CLI 脚本与 Streamlit 按钮共用。

把 generate_parser / replay_anomaly_pool / run_replay_validator / check_rollback
四个脚本的编排逻辑收成可复用函数，避免脚本与 UI 重复实现。

- 关键依赖（store / pool / graph / engine / llm / db 路径）均可注入，默认走真实对象，
  便于 TDD 用 tmp + 假对象隔离测试。
- 函数自己打开的 store 在 finally 关闭（短连接，不长期持锁）。
- rejudge_and_compare 支持 progress_cb，喂 UI 实时进度条。
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]

DATA = ROOT / "data"
ALERTS_DB = DATA / "alerts.duckdb"
PARSED_DB = DATA / "parsed_events.duckdb"
OLD_JUDGMENTS_DB = DATA / "judgments.duckdb"
NEW_JUDGMENTS_DB = DATA / "judgments_after_replay.duckdb"
SIGNALS_DB = DATA / "signals.duckdb"
REPORTS_DIR = DATA / "replay_reports"
CMDB_FILE = ROOT / "ontology" / "cmdb.yaml"
HTML_OUT = ROOT / "graph" / "visualization_replay.html"

_EVENT_ID_RE = re.compile(r":(\d+)$")


def _event_ids_from_signals(signals: List[str]) -> List[int]:
    out: List[int] = []
    for s in signals or []:
        m = _EVENT_ID_RE.search(s)
        if m:
            out.append(int(m.group(1)))
    return out


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


# =========================================================
# 结果 dataclass
# =========================================================

@dataclass
class GenerateResult:
    inserted: int
    dropped: int
    skipped: int
    candidates: List[Any] = field(default_factory=list)
    details: List[str] = field(default_factory=list)


@dataclass
class ReplayResult:
    report: Any                 # ReplayReport
    pool_before: int
    pool_after: int
    scheduledtask_count: int
    graph: Any                  # GraphStore
    html_path: Optional[Path] = None


# =========================================================
# 1) 生成候选 parser
# =========================================================

def generate_candidates(
    *,
    ontology=None,
    proposal_store=None,
    anomaly_pool=None,
    candidate_store=None,
    parser_config=None,
    generator=None,
    llm=None,
) -> GenerateResult:
    """对所有 approved 提议生成候选 parser 并插入 store。

    generator 可注入（测试免 LLM）；否则用 ParserGenerator(llm, ontology)。
    """
    from core.ontology_service import get_service
    from evolution.parser_generator import ParserGenerator
    from parsers.windows_parser import MAPPINGS_DIR, ParserConfig
    from storage.anomaly_pool import AnomalyPool
    from storage.candidate_parser_store import CandidateParserStore
    from storage.proposal_store import ProposalStore

    if ontology is None:
        ontology = get_service().get_current()
    own_ps = proposal_store is None
    own_pool = anomaly_pool is None
    own_cs = candidate_store is None
    proposal_store = proposal_store or ProposalStore()
    anomaly_pool = anomaly_pool or AnomalyPool()
    candidate_store = candidate_store or CandidateParserStore()

    try:
        approved = proposal_store.list_by_status("approved")
        inserted = dropped = skipped = 0
        candidates: List[Any] = []
        details: List[str] = []

        if approved and generator is None:
            if parser_config is None:
                parser_config = ParserConfig.load_all([MAPPINGS_DIR])
            from reasoning.llm_client import get_client
            generator = ParserGenerator(llm=llm or get_client(), ontology=ontology)

        for row in approved:
            proposal = proposal_store.as_proposal(row["proposal_id"])
            if proposal is None:
                continue
            existing = candidate_store.list_by_proposal(proposal.proposal_id)
            if [r for r in existing if r["status"] in ("pending", "approved")]:
                skipped += 1
                details.append(f"skip {proposal.name}: 已有 active 候选")
                continue
            event_ids = _event_ids_from_signals(proposal.source_signals)
            if not event_ids:
                details.append(f"skip {proposal.name}: source_signals 无 event_id")
                continue
            samples: List[dict] = []
            for eid in event_ids:
                samples.extend(anomaly_pool.list_by_event_id(eid, limit=10))
            if not samples:
                details.append(f"skip {proposal.name}: 异常池无 event_id={event_ids} 样本")
                continue
            candidate = generator.generate(
                approved_proposal=proposal,
                anomaly_samples=samples,
                current_parser_config=parser_config,
            )
            if candidate is None:
                dropped += 1
                details.append(f"drop {proposal.name}: 闸门 reject")
                continue
            candidate_store.insert(candidate)
            candidates.append(candidate)
            inserted += 1
            details.append(
                f"insert {candidate.candidate_id[:8]} target={candidate.target_node_type} "
                f"stripped={len(candidate.stripped_relations)}"
            )

        return GenerateResult(inserted=inserted, dropped=dropped, skipped=skipped,
                              candidates=candidates, details=details)
    finally:
        if own_cs:
            candidate_store.close()
        if own_pool:
            anomaly_pool.close()
        if own_ps:
            proposal_store.close()


# =========================================================
# 2) 回放异常池
# =========================================================

def replay_pool(
    *,
    ontology=None,
    parser_config=None,
    graph=None,
    anomaly_pool=None,
    parsed_db: Path = PARSED_DB,
    cmdb_file: Path = CMDB_FILE,
    write_html: bool = True,
    html_path: Path = HTML_OUT,
    reports_dir: Path = REPORTS_DIR,
) -> ReplayResult:
    """重建图（注入则用） + 回放异常池 + 落报告/HTML。返回 ReplayResult。"""
    from core.ontology_service import get_service
    from evolution.replay_engine import ReplayEngine
    from graph.cmdb_loader import load_cmdb
    from graph.importer import import_parsed_db
    from graph.store import GraphStore
    from graph.visualizer import render_html
    from parsers.windows_parser import (
        GENERATED_MAPPINGS_DIR, MAPPINGS_DIR, ParserConfig,
    )
    from storage.anomaly_pool import AnomalyPool

    if ontology is None:
        ontology = get_service().get_current()
    if parser_config is None:
        parser_config = ParserConfig.load_all([MAPPINGS_DIR, GENERATED_MAPPINGS_DIR])
    if graph is None:
        graph = GraphStore(ontology_version=ontology.version)
        import_parsed_db(parsed_db, graph)
        if Path(cmdb_file).exists():
            load_cmdb(cmdb_file, graph)

    own_pool = anomaly_pool is None
    anomaly_pool = anomaly_pool or AnomalyPool()
    try:
        # demo 重跑保护：已 backfilled 则翻回 open，保证图能拿到 ScheduledTask
        if anomaly_pool.size_open() < anomaly_pool.size_total():
            anomaly_pool.reset_backfilled()
        pool_before = anomaly_pool.size_open()

        engine = ReplayEngine(anomaly_pool=anomaly_pool, parser_config=parser_config,
                              ontology=ontology, graph=graph)
        report = engine.replay()
        pool_after = report.total_open_after
        sched = graph.list_nodes_by_type("ScheduledTask")

        reports_dir = Path(reports_dir)
        reports_dir.mkdir(parents=True, exist_ok=True)
        (reports_dir / f"replay_{_ts()}.json").write_text(
            json.dumps(report.to_dict(), ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )

        out_html = None
        if write_html:
            render_html(graph, html_path,
                        title=f"AI-OntoSIEM · 回放后图谱 v{ontology.version}")
            out_html = html_path

        return ReplayResult(report=report, pool_before=pool_before,
                            pool_after=pool_after, scheduledtask_count=len(sched),
                            graph=graph, html_path=out_html)
    finally:
        if own_pool:
            anomaly_pool.close()


# =========================================================
# 3) 回放重判 + 演化前后对比
# =========================================================

def _load_alerts(alerts_db: Path):
    import duckdb

    from detection.engine import Alert

    con = duckdb.connect(str(alerts_db), read_only=True)
    cols = ("alert_id, rule_id, rule_title, severity, event_record_id, event_id, "
            "channel, computer, timestamp, attack_techniques, matched_fields, "
            "ontology_version, raw_event")
    rows = con.execute(f"SELECT {cols} FROM alerts ORDER BY timestamp").fetchall()
    con.close()

    def _l(v):
        if isinstance(v, str):
            try:
                return json.loads(v)
            except json.JSONDecodeError:
                return v
        return v

    return [
        Alert(
            alert_id=r[0], rule_id=r[1], rule_title=r[2], severity=r[3],
            event_record_id=int(r[4] or 0), event_id=int(r[5] or 0),
            channel=r[6] or "", computer=r[7] or "", timestamp=str(r[8]),
            attack_techniques=_l(r[9]) or [], matched_fields=_l(r[10]) or {},
            ontology_version=r[11] or "1.0", raw_event=_l(r[12]) or {},
        )
        for r in rows
    ]


def rejudge_and_compare(
    *,
    ontology=None,
    parser_config=None,
    graph=None,
    anomaly_pool=None,
    alerts=None,
    old_judgments=None,
    judge_engine=None,
    llm=None,
    progress_cb: Optional[Callable] = None,
    pool_open_before: int = 0,
    pool_open_after: int = 0,
    ontology_version_before: str = "",
    ontology_version_after: str = "",
    subgraph_depth: int = 2,
    alerts_db: Path = ALERTS_DB,
    old_judgments_db: Path = OLD_JUDGMENTS_DB,
    new_judgments_db: Path = NEW_JUDGMENTS_DB,
    reports_dir: Path = REPORTS_DIR,
    parsed_db: Path = PARSED_DB,
    cmdb_file: Path = CMDB_FILE,
):
    """回放 + 重判（progress_cb 喂进度条）+ diff，返回 ValidatorReport。

    注入 graph / alerts / old_judgments / judge_engine 可跳过真实重建与 LLM（测试用）。
    """
    from core.ontology_service import get_service
    from evolution.replay_validator import compare_judgments, rejudge_alerts
    from evolution.signal_hub import SignalHub
    from reasoning.judgment_engine import JudgmentEngine
    from storage.judgment_store import JudgmentStore

    if ontology is None:
        ontology = get_service().get_current()
    if not ontology_version_after:
        ontology_version_after = ontology.version

    signal_hub = None
    try:
        # 1) graph：注入则用，否则重建 + 回放
        if graph is None:
            rp = replay_pool(ontology=ontology, parser_config=parser_config,
                             anomaly_pool=anomaly_pool, write_html=False,
                             reports_dir=reports_dir, parsed_db=parsed_db,
                             cmdb_file=cmdb_file)
            graph = rp.graph
            pool_open_before = rp.pool_before
            pool_open_after = rp.pool_after

        # 2) 老 judgments
        if old_judgments is None:
            os_ = JudgmentStore(db_path=old_judgments_db)
            old_judgments = os_.list_recent(limit=1000)
            os_.close()
        if not ontology_version_before:
            ontology_version_before = (old_judgments[0]["ontology_version"]
                                       if old_judgments else "1.0")

        # 3) alerts
        if alerts is None:
            alerts = _load_alerts(alerts_db)

        # 4) engine
        if judge_engine is None:
            signal_hub = SignalHub(SIGNALS_DB)
            judge_engine = JudgmentEngine(
                llm=llm or _get_client(), graph=graph, signal_hub=signal_hub,
                ontology=ontology, subgraph_depth=subgraph_depth,
            )

        # 5) 重判（带进度）
        new_judgments = rejudge_alerts(judge_engine, alerts, progress_cb=progress_cb)

        # 6) 持久化 after-judgments
        new_judgments_db = Path(new_judgments_db)
        if new_judgments_db.exists():
            new_judgments_db.unlink()
        ns = JudgmentStore(db_path=new_judgments_db)
        ns.insert_many(new_judgments)
        ns.close()

        # 7) diff
        report = compare_judgments(
            before=old_judgments, after=new_judgments,
            pool_open_before=pool_open_before, pool_open_after=pool_open_after,
            ontology_version_before=ontology_version_before,
            ontology_version_after=ontology_version_after,
        )

        # 8) 落 json
        reports_dir = Path(reports_dir)
        reports_dir.mkdir(parents=True, exist_ok=True)
        (reports_dir / f"validator_{_ts()}.json").write_text(
            json.dumps(report.to_dict(), ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )
        return report
    finally:
        if signal_hub is not None:
            signal_hub.close()


def _get_client():
    from reasoning.llm_client import get_client
    return get_client()


# =========================================================
# 4) 回滚检查
# =========================================================

def latest_rollback_assessment(*, reports_dir: Path = REPORTS_DIR,
                               require_min_rejudged: int = 5):
    """读最新 validator 报告 → assess_for_rollback。无报告返回 None。"""
    from evolution.replay_validator import ValidatorReport
    from evolution.rollback_proposer import assess_for_rollback

    reports_dir = Path(reports_dir)
    files = sorted(reports_dir.glob("validator_*.json")) if reports_dir.exists() else []
    if not files:
        return None
    data = json.loads(files[-1].read_text(encoding="utf-8"))
    report = ValidatorReport(
        started_at=data.get("started_at", ""),
        finished_at=data.get("finished_at", ""),
        ontology_version_before=data.get("ontology_version_before", ""),
        ontology_version_after=data.get("ontology_version_after", ""),
        pool_open_before=int(data.get("pool_open_before", 0)),
        pool_open_after=int(data.get("pool_open_after", 0)),
        rejudged_count=int(data.get("rejudged_count", 0)),
        verdict_changes=[],
        verdict_unchanged=int(data.get("verdict_unchanged", 0)),
        verdict_upgraded=int(data.get("verdict_upgraded", 0)),
        verdict_downgraded=int(data.get("verdict_downgraded", 0)),
        semantic_gap_cleared=int(data.get("semantic_gap_cleared", 0)),
        semantic_gap_persisted=int(data.get("semantic_gap_persisted", 0)),
        avg_evidence_refs_before=float(data.get("avg_evidence_refs_before", 0.0)),
        avg_evidence_refs_after=float(data.get("avg_evidence_refs_after", 0.0)),
    )
    return assess_for_rollback(report, require_min_rejudged=require_min_rejudged)
