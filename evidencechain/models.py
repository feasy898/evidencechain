"""Data contracts: Evidence / Finding / RiskItem.

Conventions (the verifiable semantics this module relies on):
- Evidence.ref() is always `file:line`, where line is the real line number recorded
  by the parser when reading from disk.
- None of the dataclasses perform I/O, which keeps them easy to serialize and recompute.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Tuple


class ParseError(Exception):
    """Invalid input artifact (bad JSON / missing field / out-of-range value). The message must include `file:line`."""


@dataclass(frozen=True)
class Evidence:
    """One evidence reference: points at a single line of an input artifact."""

    file: str
    line: int
    finding_id: str = ""

    def ref(self) -> str:
        return f"{self.file}:{self.line}"

    def to_dict(self) -> dict:
        return {"file": self.file, "line": self.line, "finding_id": self.finding_id}


@dataclass
class Finding:
    """A single raw finding from the parsing layer (not deduplicated, not ranked)."""

    finding_id: str
    stage: str
    title: str
    asset: str
    asset_criticality: str
    cvss: float
    reachability: str
    cve: Optional[str]
    remediation: str
    note: str
    evidence: Evidence
    injection_flags: Tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "stage": self.stage,
            "title": self.title,
            "asset": self.asset,
            "asset_criticality": self.asset_criticality,
            "cvss": self.cvss,
            "reachability": self.reachability,
            "cve": self.cve,
            "remediation": self.remediation,
            "note": self.note,
            "evidence": self.evidence.ref(),
            "injection_flags": list(self.injection_flags),
        }


@dataclass
class RiskItem:
    """Aggregation-layer product: one unique risk merged across stages."""

    key: str
    title: str
    asset: str
    asset_criticality: str
    cvss: float
    reachability: str
    cve: Optional[str]
    stages: Tuple[str, ...]
    evidence: Tuple[Evidence, ...]
    remediation: str
    merged_from: Tuple[str, ...]
    note: str = ""
    injection_flags: Tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "title": self.title,
            "asset": self.asset,
            "asset_criticality": self.asset_criticality,
            "cvss": self.cvss,
            "reachability": self.reachability,
            "cve": self.cve,
            "stages": list(self.stages),
            "evidence": [e.to_dict() for e in self.evidence],
            "remediation": self.remediation,
            "merged_from": list(self.merged_from),
            "note": self.note,
        }
