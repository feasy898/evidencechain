"""Aggregate layer: merge the same risk across stages into unique RiskItems.

Merge rules (deterministic, no model involved):
- Dedup key: `cve:<UPPERCASE CVE>` when a CVE exists, otherwise
  `ta:<normalized title>|<lowercase asset>`.
- Numeric fields take the worst value: max CVSS, highest asset criticality,
  most exposed reachability.
- Evidence lines are unioned (sorted and deduplicated by file:line), so every
  conclusion can be traced back to raw artifacts.
- Title and remediation come from the finding with the highest CVSS
  (ties broken by ascending finding_id).
"""
from __future__ import annotations

import re
from typing import Dict, List, Sequence

from .models import Evidence, Finding, RiskItem

ASSET_CRITICALITY_ORDER = ("low", "medium", "high", "critical")
REACHABILITY_ORDER = ("local", "adjacent", "network")


def normalize_title(title: str) -> str:
    """Normalize a title: trim -> unify whitespace/hyphens/underscores ->
    lowercase -> strip trailing periods."""
    text = re.sub(r"[\s_\-]+", " ", (title or "").strip().lower())
    return text.strip(" .")


def dedup_key(finding: Finding) -> str:
    """Dedup key: CVE when present, otherwise `normalized title + asset`."""
    if finding.cve:
        return "cve:" + finding.cve.strip().upper()
    return "ta:" + normalize_title(finding.title) + "|" + (finding.asset or "").strip().lower()


def _max_criticality(a: str, b: str) -> str:
    return a if ASSET_CRITICALITY_ORDER.index(a) >= ASSET_CRITICALITY_ORDER.index(b) else b


def _most_exposed(a: str, b: str) -> str:
    return a if REACHABILITY_ORDER.index(a) >= REACHABILITY_ORDER.index(b) else b


def aggregate(findings: Sequence[Finding]) -> List[RiskItem]:
    """Merge raw findings into unique risks (ordered by dedup key: deterministic)."""
    buckets: Dict[str, List[Finding]] = {}
    for f in findings:
        buckets.setdefault(dedup_key(f), []).append(f)

    risks: List[RiskItem] = []
    for key in sorted(buckets):
        group = sorted(buckets[key], key=lambda f: (-f.cvss, f.finding_id))
        head = group[0]
        criticality = "low"
        reachability = "local"
        for f in group:
            criticality = _max_criticality(criticality, f.asset_criticality)
            reachability = _most_exposed(reachability, f.reachability)

        evidence: List[Evidence] = []
        seen = set()
        for f in sorted(group, key=lambda f: (f.evidence.file, f.evidence.line, f.finding_id)):
            ref = f.evidence.ref()
            if ref in seen:
                continue
            seen.add(ref)
            evidence.append(f.evidence)

        # Injection flags are unioned across the merged findings so the report
        # shows every payload pattern that the gate caught for this risk.
        flags = sorted({flag for f in group for flag in f.injection_flags})

        risks.append(RiskItem(
            key=key,
            title=head.title,
            asset=head.asset,
            asset_criticality=criticality,
            cvss=head.cvss,
            reachability=reachability,
            cve=head.cve,
            stages=tuple(sorted({f.stage for f in group})),
            evidence=tuple(evidence),
            remediation=head.remediation,
            merged_from=tuple(sorted(f.finding_id for f in group)),
            note=head.note,
            injection_flags=tuple(flags),
        ))
    return risks
