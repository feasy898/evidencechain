"""Data contracts: Evidence / Finding / RiskItem.

Conventions:
- Evidence.ref() is always `filename:line`, where the line number is the real
  line recorded by the parser while reading the artifact from disk.
- None of the dataclasses perform I/O, which keeps them trivially serializable
  and recomputable.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Tuple


class ParseError(Exception):
    """An input artifact is invalid (bad JSON / missing field / out-of-range value).

    The message always carries `file:line`.
    """


@dataclass(frozen=True)
class Evidence:
    """A single evidence reference pointing at one line of an input artifact."""

    file: str
    line: int
    finding_id: str = ""

    def ref(self) -> str:
        return f"{self.file}:{self.line}"

    def to_dict(self) -> dict:
        return {"file": self.file, "line": self.line, "finding_id": self.finding_id}


@dataclass
class Finding:
    """One raw finding as produced by the parse layer (not deduplicated, not ranked)."""

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
    """Aggregate-layer output: one unique risk after cross-stage merging."""

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
            "injection_flags": list(self.injection_flags),
        }
