"""服务层 evolution/pipeline_ops.py TDD。

四个演化管线编排函数：CLI 脚本与 UI 按钮共用，避免逻辑重复。
注入假对象 / tmp db 隔离测试，不调真 LLM。
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from reasoning.judgment_engine import Judgment


# =========================================================
# rejudge_and_compare
# =========================================================

def test_rejudge_and_compare_progress_and_report(tmp_path) -> None:
    from evolution import pipeline_ops
    from graph.store import GraphStore

    class _A:
        def __init__(self, aid):
            self.alert_id = aid
            self.rule_id = "r-" + aid

    alerts = [_A("a1"), _A("a2")]
    old = [
        {"alert_id": "a1", "verdict": "malicious", "confidence": 0.9,
         "evidence_refs": [{"type": "x", "ref": "1"}], "semantic_gap": None,
         "ontology_version": "1.0"},
        {"alert_id": "a2", "verdict": "suspicious", "confidence": 0.6,
         "evidence_refs": [], "semantic_gap": None, "ontology_version": "1.0"},
    ]

    class _Engine:
        def judge(self, a):
            return Judgment(
                judgment_id="n-" + a.alert_id, alert_id=a.alert_id,
                verdict="suspicious", confidence=0.65, reasoning_steps=[],
                evidence_refs=[{"type": "x", "ref": "1"}], attack_chain=[],
                next_steps=[], ontology_version="1.1", semantic_gap=None,
                needs_review=False,
            )

    seen = []
    report = pipeline_ops.rejudge_and_compare(
        alerts=alerts, old_judgments=old, judge_engine=_Engine(),
        graph=GraphStore(ontology_version="1.1"),
        pool_open_before=32, pool_open_after=10,
        ontology_version_before="1.0", ontology_version_after="1.1",
        new_judgments_db=tmp_path / "after.duckdb",
        reports_dir=tmp_path / "reports",
        progress_cb=lambda i, n, a, j: seen.append(i),
    )
    assert seen == [1, 2]
    assert report.rejudged_count == 2
    assert report.pool_open_before == 32 and report.pool_open_after == 10
    # 报告落盘
    assert list((tmp_path / "reports").glob("validator_*.json"))
    # after-judgments 持久化
    from storage.judgment_store import JudgmentStore
    js = JudgmentStore(db_path=tmp_path / "after.duckdb")
    assert len(js.list_recent(limit=10)) == 2
    js.close()


# =========================================================
# latest_rollback_assessment
# =========================================================

def test_latest_rollback_assessment_triggers_on_persisted_gap(tmp_path) -> None:
    from evolution import pipeline_ops
    rd = tmp_path / "reports"
    rd.mkdir()
    (rd / "validator_20260101T000000Z.json").write_text(json.dumps({
        "ontology_version_before": "1.0", "ontology_version_after": "1.1",
        "pool_open_before": 32, "pool_open_after": 10, "rejudged_count": 10,
        "verdict_unchanged": 10, "verdict_upgraded": 0, "verdict_downgraded": 0,
        "semantic_gap_cleared": 0, "semantic_gap_persisted": 6,
        "avg_evidence_refs_before": 8.6, "avg_evidence_refs_after": 7.6,
    }), encoding="utf-8")

    p = pipeline_ops.latest_rollback_assessment(reports_dir=rd)
    assert p is not None
    assert p.severity in {"warning", "critical"}
    assert "gap" in p.rationale.lower()


def test_latest_rollback_assessment_none_when_no_report(tmp_path) -> None:
    from evolution import pipeline_ops
    rd = tmp_path / "reports"
    rd.mkdir()
    assert pipeline_ops.latest_rollback_assessment(reports_dir=rd) is None


# =========================================================
# generate_candidates
# =========================================================

def test_generate_candidates_inserts_with_fake_generator(tmp_path) -> None:
    from evolution import pipeline_ops
    from evolution.parser_generator import CandidateParser
    from evolution.proposer import Proposal
    from storage.anomaly_pool import AnomalyPool
    from storage.candidate_parser_store import CandidateParserStore
    from storage.proposal_store import ProposalStore

    pdb = tmp_path / "p.duckdb"
    cdb = tmp_path / "c.duckdb"
    adb = tmp_path / "a.duckdb"

    ps = ProposalStore(pdb)
    ps.insert(Proposal(
        proposal_id="p1", proposal_type="node", name="ScheduledTask",
        semantic_definition="d", supporting_evidence=[], overlap_analysis={},
        attack_mapping=[], source_signals=["data:unparseable_event:4698"],
        ontology_base_version="1.0", status="approved",
    ))
    ps.close()

    pool = AnomalyPool(adb)
    pool.add(record_id=1, event_id=4698, computer="H",
             timestamp=datetime.now(timezone.utc), failure_reason="x",
             raw_event={"event_id": 4698}, ontology_version="1.1")
    pool.close()

    class _Gen:
        def generate(self, *, approved_proposal, anomaly_samples,
                     current_parser_config):
            return CandidateParser(
                candidate_id="c1", triggered_by_ontology_version="1.1",
                triggered_by_proposal_id=approved_proposal.proposal_id,
                target_node_type="ScheduledTask",
                source_events=[{"event_id": 4698, "channel": "Security"}],
                rules=[{"name": "r", "event_id": 4698, "channel": "Security",
                        "entities": []}],
                sample_count=len(anomaly_samples), confidence=0.85,
            )

    res = pipeline_ops.generate_candidates(
        proposal_store=ProposalStore(pdb),
        anomaly_pool=AnomalyPool(adb),
        candidate_store=CandidateParserStore(cdb),
        generator=_Gen(),
    )
    assert res.inserted == 1

    cs = CandidateParserStore(cdb)
    assert cs.count_by_status().get("pending") == 1
    cs.close()


def test_generate_candidates_skips_when_no_approved(tmp_path) -> None:
    from evolution import pipeline_ops
    from storage.anomaly_pool import AnomalyPool
    from storage.candidate_parser_store import CandidateParserStore
    from storage.proposal_store import ProposalStore

    res = pipeline_ops.generate_candidates(
        proposal_store=ProposalStore(tmp_path / "p.duckdb"),
        anomaly_pool=AnomalyPool(tmp_path / "a.duckdb"),
        candidate_store=CandidateParserStore(tmp_path / "c.duckdb"),
        generator=object(),  # 不应被调用
    )
    assert res.inserted == 0


# =========================================================
# replay_pool
# =========================================================

def test_replay_pool_empty_pool_shape(tmp_path) -> None:
    from core.ontology_service import get_service
    from evolution import pipeline_ops
    from graph.store import GraphStore
    from parsers.windows_parser import MAPPINGS_DIR, ParserConfig
    from storage.anomaly_pool import AnomalyPool

    onto = get_service().get_current()
    g = GraphStore(ontology_version=onto.version)
    pool = AnomalyPool(tmp_path / "a.duckdb")  # 空池
    cfg = ParserConfig.load_all([MAPPINGS_DIR])

    res = pipeline_ops.replay_pool(
        ontology=onto, parser_config=cfg, graph=g, anomaly_pool=pool,
        write_html=False, reports_dir=tmp_path / "reports",
    )
    assert res.pool_before == 0
    assert res.pool_after == 0
    assert res.report.attempted == 0
    pool.close()
