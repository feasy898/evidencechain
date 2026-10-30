"""Aggregate layer tests.

What they pin down: findings describing the same risk are merged into one
RiskItem across stages -- the dedup key prefers the CVE and falls back to
"normalized title + asset"; merging keeps the highest CVSS, the most exposed
reachability, the highest asset criticality, and all evidence lines (resolvable).
"""
from evidencechain.aggregate import aggregate, dedup_key, normalize_title
from evidencechain.models import Evidence, Finding


def mk(fid, title, asset="a1", cvss=5.0, crit="medium", reach="local",
       cve=None, stage="s1", file="s1.jsonl", line=1):
    return Finding(
        finding_id=fid, stage=stage, title=title, asset=asset,
        asset_criticality=crit, cvss=cvss, reachability=reach, cve=cve,
        remediation="fix it", note="",
        evidence=Evidence(file=file, line=line, finding_id=fid),
    )


def test_normalize_title():
    assert normalize_title("  Missing   HSTS header ") == "missing hsts header"
    assert normalize_title("Missing-HSTS_Header") == "missing hsts header"
    assert normalize_title("Missing HSTS header.") == "missing hsts header"


def test_dedup_key_prefers_cve():
    a = mk("F-1", "some title", cve="cve-2024-1")
    b = mk("F-2", "totally different title", cve="CVE-2024-1")
    assert dedup_key(a) == dedup_key(b)
    assert dedup_key(a).startswith("cve:")


def test_dedup_key_falls_back_to_title_and_asset():
    a = mk("F-1", "Missing HSTS header", asset="gw")
    b = mk("F-2", "missing hsts header", asset="GW")
    c = mk("F-3", "missing hsts header", asset="other-asset")
    assert dedup_key(a) == dedup_key(b)
    assert dedup_key(a) != dedup_key(c)


def test_aggregate_merges_same_cve():
    risks = aggregate([
        mk("F-201", "Out-of-bounds write", asset="svc", cvss=9.1, cve="CVE-2024-21538",
           stage="scan", file="stage2_scan.jsonl", line=2),
        mk("F-202", "OOB write in parser", asset="svc", cvss=8.8, cve="CVE-2024-21538",
           stage="scan2", file="stage3_manual.jsonl", line=5),
    ])
    assert len(risks) == 1
    r = risks[0]
    assert r.cvss == 9.1
    assert r.merged_from == ("F-201", "F-202")
    assert [e.ref() for e in r.evidence] == ["stage2_scan.jsonl:2", "stage3_manual.jsonl:5"]


def test_aggregate_merges_same_title_asset_without_cve():
    risks = aggregate([
        mk("F-101", "Backup snapshots stored on public bucket", asset="bucket", stage="recon"),
        mk("F-302", "backup snapshots stored on public bucket.", asset="bucket", stage="manual"),
    ])
    assert len(risks) == 1
    assert risks[0].merged_from == ("F-101", "F-302")


def test_aggregate_keeps_distinct_risks_separate():
    risks = aggregate([
        mk("F-1", "A", asset="x"),
        mk("F-2", "B", asset="x"),
    ])
    assert len(risks) == 2


def test_aggregate_takes_highest_asset_criticality():
    risks = aggregate([
        mk("F-1", "A", asset="x", crit="low"),
        mk("F-2", "A", asset="x", crit="critical"),
    ])
    assert risks[0].asset_criticality == "critical"


def test_aggregate_takes_most_exposed_reachability():
    risks = aggregate([
        mk("F-1", "A", asset="x", reach="local"),
        mk("F-2", "A", asset="x", reach="network"),
    ])
    assert risks[0].reachability == "network"


def test_aggregate_unions_stages():
    risks = aggregate([
        mk("F-1", "A", asset="x", stage="recon"),
        mk("F-2", "A", asset="x", stage="manual"),
    ])
    assert risks[0].stages == ("manual", "recon")


def test_aggregate_evidence_is_sorted_and_deduped():
    risks = aggregate([
        mk("F-2", "A", asset="x", file="b.jsonl", line=3),
        mk("F-1", "A", asset="x", file="a.jsonl", line=9),
        mk("F-3", "A", asset="x", file="a.jsonl", line=9),
    ])
    assert [e.ref() for e in risks[0].evidence] == ["a.jsonl:9", "b.jsonl:3"]


def test_aggregate_takes_title_and_remediation_from_max_cvss_finding():
    risks = aggregate([
        mk("F-1", "low cvss title", cvss=1.0, cve="CVE-1"),
        mk("F-2", "high cvss title", cvss=8.0, cve="CVE-1"),
    ])
    assert risks[0].title == "high cvss title"


def test_aggregate_empty_input():
    assert aggregate([]) == []
