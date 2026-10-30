"""Priority-ranking layer: deterministic priority score + independent auditor.

Priority score formula (no model involved, can be recomputed by hand):
    priority_score = CVSS × asset-criticality weight × reachability factor

Independent auditor `audit_ranking`: recomputes the ranking from its own data.
Order mismatch, missing evidence, duplicate keys, out-of-range CVSS — anything
fails gets flagged (a conclusion is never allowed to vouch for itself).
"""
from __future__ import annotations

from typing import Dict, List, Sequence

from .models import RiskItem

ASSET_WEIGHTS: Dict[str, float] = {
    "low": 0.2,
    "medium": 0.5,
    "high": 0.8,
    "critical": 1.0,
}

REACH_FACTORS: Dict[str, float] = {
    "local": 0.3,
    "adjacent": 0.6,
    "network": 1.0,
}

SEVERITY_BANDS = (
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.0, "low"),
)


def severity_of(cvss: float) -> str:
    """CVSS → severity band (pure numeric banding, no external vocabulary)."""
    for threshold, name in SEVERITY_BANDS:
        if cvss >= threshold:
            return name
    return "low"


def priority_score(risk: RiskItem) -> float:
    """Priority score = CVSS × asset-criticality weight × reachability factor."""
    weight = ASSET_WEIGHTS[risk.asset_criticality]
    factor = REACH_FACTORS[risk.reachability]
    return round(risk.cvss * weight * factor, 4)


def _sort_key(risk: RiskItem):
    return (-priority_score(risk), risk.key)


def prioritize(risks: Sequence[RiskItem]) -> List[RiskItem]:
    """Sort: priority score descending, ties broken by dedup key ascending (unique result)."""
    return sorted(risks, key=_sort_key)


def expected_order(risks: Sequence[RiskItem]) -> List[str]:
    """Expected order recomputed from the data (sequence of dedup keys)."""
    return [r.key for r in prioritize(risks)]


def audit_ranking(ranked: Sequence[RiskItem]) -> dict:
    """Independent audit: four machine checks over the already-ranked result; returns a verdict."""
    actual = [r.key for r in ranked]
    expected = expected_order(ranked)

    ordering_ok = actual == expected
    ordering_detail = "order matches recomputation"
    if not ordering_ok:
        first_bad = next(
            (i for i, (a, e) in enumerate(zip(actual, expected)) if a != e),
            min(len(actual), len(expected)),
        )
        ordering_detail = (
            f"order diverges from recomputation starting at position {first_bad + 1}: "
            f"actual={actual[first_bad:first_bad + 3]} "
            f"expected={expected[first_bad:first_bad + 3]}")

    dup = sorted({k for k in actual if actual.count(k) > 1})
    missing = [r.key for r in ranked if not r.evidence]
    out_of_range = [r.key for r in ranked if not (0.0 <= r.cvss <= 10.0)]

    checks = [
        {"name": "ordering_matches_recomputed",
         "status": "PASS" if ordering_ok else "FAIL",
         "detail": ordering_detail},
        {"name": "no_duplicate_keys",
         "status": "PASS" if not dup else "FAIL",
         "detail": "no duplicate dedup keys" if not dup else f"duplicate keys: {', '.join(dup)}"},
        {"name": "evidence_present",
         "status": "PASS" if not missing else "FAIL",
         "detail": "every conclusion carries an evidence row" if not missing
                   else f"missing evidence: {', '.join(missing)}"},
        {"name": "cvss_within_range",
         "status": "PASS" if not out_of_range else "FAIL",
         "detail": "all CVSS scores within 0..10" if not out_of_range
                   else f"out of range: {', '.join(out_of_range)}"},
    ]
    status = "PASS" if all(c["status"] == "PASS" for c in checks) else "FAIL"
    return {
        "status": status,
        "checks": checks,
        "checked_risks": len(ranked),
        "expected_order": expected,
        "actual_order": actual,
    }
