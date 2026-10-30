"""Prioritization layer tests.

What they pin down: priority score = CVSS x asset criticality weight x
reachability factor (deterministic formula, no model involved). Sorting is by
score descending with ties broken by dedup key (unique, recomputable). This
layer also hosts the independent auditor: it recomputes the order from its own
data and flags any disagreement.
"""
from evidencechain.aggregate import aggregate
from evidencechain.models import Finding, RiskItem, Evidence
from evidencechain.prioritize import (
    ASSET_WEIGHTS,
    REACH_FACTORS,
    audit_ranking,
    expected_order,
    prioritize,
    priority_score,
    severity_of,
)


def mk(fid, title, asset="a1", cvss=5.0, crit="medium", reach="local", cve=None,
       stage="s1", file="s1.jsonl", line=1):
    return Finding(
        finding_id=fid, stage=stage, title=title, asset=asset,
        asset_criticality=crit, cvss=cvss, reachability=reach, cve=cve,
        remediation="fix", note="",
        evidence=Evidence(file=file, line=line, finding_id=fid),
    )


def risk(key="ta:a|a1", cvss=5.0, crit="medium", reach="local", evidence=True):
    return RiskItem(
        key=key, title="t", asset="a1", asset_criticality=crit, cvss=cvss,
        reachability=reach, cve=None, stages=("s1",),
        evidence=(Evidence(file="s1.jsonl", line=1),) if evidence else (),
        remediation="fix", merged_from=("F-1",),
    )


def test_weights_are_declared():
    assert ASSET_WEIGHTS == {"low": 0.2, "medium": 0.5, "high": 0.8, "critical": 1.0}
    assert REACH_FACTORS == {"local": 0.3, "adjacent": 0.6, "network": 1.0}


def test_priority_score_formula():
    r = risk(cvss=9.1, crit="critical", reach="network")
    assert priority_score(r) == 9.1


def test_priority_score_applies_asset_weight():
    r = risk(cvss=8.0, crit="high", reach="network")
    assert priority_score(r) == 6.4


def test_priority_score_applies_reachability_factor():
    r = risk(cvss=5.3, crit="critical", reach="adjacent")
    assert priority_score(r) == 3.18


def test_severity_bands():
    assert severity_of(9.1) == "critical"
    assert severity_of(9.0) == "critical"
    assert severity_of(7.5) == "high"
    assert severity_of(4.0) == "medium"
    assert severity_of(3.9) == "low"
    assert severity_of(0.0) == "low"


def test_prioritize_orders_by_score_desc():
    risks = aggregate([
        mk("F-1", "low", cvss=1.0),
        mk("F-2", "high", cvss=9.0, crit="critical", reach="network"),
        mk("F-3", "mid", cvss=5.0, crit="high"),
    ])
    ranked = prioritize(risks)
    assert [r.merged_from[0] for r in ranked] == ["F-2", "F-3", "F-1"]


def test_prioritize_tie_break_is_deterministic_by_key():
    risks = aggregate([
        mk("F-1", "zeta", cvss=5.0),
        mk("F-2", "alpha", cvss=5.0),
    ])
    ranked = prioritize(risks)
    assert [r.key for r in ranked] == sorted(r.key for r in ranked)
    assert prioritize(risks) == ranked  # idempotent


def test_expected_order_recomputes_from_scratch():
    risks = aggregate([
        mk("F-1", "a", cvss=1.0),
        mk("F-2", "b", cvss=9.0, crit="critical", reach="network"),
    ])
    ranked = prioritize(risks)
    assert expected_order(risks) == [r.key for r in ranked]


def test_audit_passes_for_correct_order():
    risks = aggregate([mk("F-1", "a", cvss=1.0), mk("F-2", "b", cvss=9.0, crit="critical")])
    verdict = audit_ranking(prioritize(risks))
    assert verdict["status"] == "PASS"
    assert all(c["status"] == "PASS" for c in verdict["checks"])


def test_audit_detects_tampered_order():
    risks = aggregate([mk("F-1", "a", cvss=1.0), mk("F-2", "b", cvss=9.0, crit="critical")])
    ranked = prioritize(risks)
    ranked.reverse()  # as if a low-score risk had been promoted by hand
    verdict = audit_ranking(ranked)
    assert verdict["status"] == "FAIL"
    failed = [c["name"] for c in verdict["checks"] if c["status"] == "FAIL"]
    assert "ordering_matches_recomputed" in failed


def test_audit_flags_missing_evidence():
    ranked = [risk(evidence=False)]
    verdict = audit_ranking(ranked)
    assert verdict["status"] == "FAIL"
    failed = [c["name"] for c in verdict["checks"] if c["status"] == "FAIL"]
    assert "evidence_present" in failed


def test_audit_flags_duplicate_keys():
    r = risk()
    verdict = audit_ranking([r, r])
    failed = [c["name"] for c in verdict["checks"] if c["status"] == "FAIL"]
    assert "no_duplicate_keys" in failed


def test_audit_flags_cvss_out_of_range():
    r = risk(cvss=42.0)
    verdict = audit_ranking([r])
    failed = [c["name"] for c in verdict["checks"] if c["status"] == "FAIL"]
    assert "cvss_within_range" in failed
