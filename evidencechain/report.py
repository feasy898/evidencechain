"""Report layer: structured risk report (JSON) + human-readable risk register (Markdown).

Two ground rules:
1. Single source of truth: the Markdown register is rendered from the summary,
   so the prose report and the structured data cannot disagree.
2. The injection gate runs once more before rendering (defense in depth):
   artifact text is always just text.
"""
from __future__ import annotations

from typing import Dict, List, Sequence

from . import __version__
from .models import RiskItem
from .parse import sanitize_text
from .prioritize import priority_score, severity_of

SEVERITY_ORDER = ("critical", "high", "medium", "low")


def _cell(text: str) -> str:
    """Escape a Markdown table cell."""
    safe, _ = sanitize_text(str(text or ""))
    return safe.replace("|", "\\|").replace("\n", " ").strip()


def build_summary(ranked: Sequence[RiskItem], raw_count: int, digest: str,
                  verdict: dict) -> dict:
    """Assemble ranked risks into the structured report data."""
    risks: List[dict] = []
    by_severity = {name: 0 for name in SEVERITY_ORDER}
    by_stage: Dict[str, int] = {}

    for index, risk in enumerate(ranked, start=1):
        severity = severity_of(risk.cvss)
        by_severity[severity] += 1
        for stage in risk.stages:
            by_stage[stage] = by_stage.get(stage, 0) + 1
        title, _ = sanitize_text(risk.title)
        remediation, _ = sanitize_text(risk.remediation)
        note, _ = sanitize_text(risk.note)
        risks.append({
            "rank": index,
            "id": f"R-{index:03d}",
            "key": risk.key,
            "title": title,
            "asset": risk.asset,
            "asset_criticality": risk.asset_criticality,
            "severity": severity,
            "cvss": risk.cvss,
            "priority_score": priority_score(risk),
            "reachability": risk.reachability,
            "cve": risk.cve,
            "stages": list(risk.stages),
            "evidence": [e.to_dict() for e in risk.evidence],
            "evidence_refs": [e.ref() for e in risk.evidence],
            "remediation": remediation,
            "merged_from": list(risk.merged_from),
            "note": note,
            "injection_flags": list(risk.injection_flags),
        })

    unique = len(ranked)
    return {
        "generator": f"evidencechain {__version__}",
        "input_digest": digest,
        "totals": {
            "raw_findings": raw_count,
            "unique_risks": unique,
            "merged_duplicates": raw_count - unique,
            "by_severity": by_severity,
            "by_stage": dict(sorted(by_stage.items())),
        },
        "risks": risks,
        "verdict": verdict,
    }


def render_report(summary: dict) -> str:
    """Render the human-readable risk register (deterministic: no timestamps,
    identical output on repeated runs)."""
    totals = summary["totals"]
    risks = summary["risks"]
    verdict = summary["verdict"]
    lines: List[str] = []

    lines.append(f"# Risk Register - EvidenceChain v{__version__}")
    lines.append("")
    lines.append(f"- Input digest: `{summary['input_digest']}`")
    lines.append(f"- **{totals['raw_findings']}** raw findings deduplicated into "
                 f"**{totals['unique_risks']}** unique risks "
                 f"({totals['merged_duplicates']} duplicates merged)")
    lines.append(f"- Independent verdict: **{verdict['status']}** "
                 f"({len(verdict['checks'])} checks)")
    lines.append("")

    lines.append("## 1. Executive summary")
    lines.append("")
    if risks:
        top = risks[0]
        lines.append(f"- Top priority: **{top['id']} {top['title']}** "
                     f"({top['severity']}, CVSS {top['cvss']}, "
                     f"priority score {top['priority_score']}, asset {top['asset']})")
        lines.append(f"- Severity distribution: critical {totals['by_severity']['critical']} / "
                     f"high {totals['by_severity']['high']} / "
                     f"medium {totals['by_severity']['medium']} / "
                     f"low {totals['by_severity']['low']}")
    lines.append(f"- In short: {totals['raw_findings']} findings scattered across assessment "
                 f"stages are consolidated into {totals['unique_risks']} ranked, actionable "
                 f"conclusions. Every conclusion is traceable to the exact input artifact line "
                 f"(`file:line`). No network calls at any point.")
    lines.append("")

    lines.append("## 2. Risk register (sorted by priority score)")
    lines.append("")
    lines.append("| Rank | ID | Title | Asset | Severity | CVSS | Priority | Reachability | Stages | Evidence | Remediation |")
    lines.append("|---|---|---|---|---|---|---|---|---|---|---|")
    for risk in risks:
        refs = ", ".join(risk["evidence_refs"]) or "-"
        stages = ", ".join(risk["stages"]) or "-"
        lines.append(
            f"| {risk['rank']} | {risk['id']} | {_cell(risk['title'])} | {_cell(risk['asset'])} | "
            f"{risk['severity']} | {risk['cvss']} | {risk['priority_score']} | {risk['reachability']} | "
            f"{stages} | {refs} | {_cell(risk['remediation']) or '-'} |")
    lines.append("")

    lines.append("## 3. Independent verdict")
    lines.append("")
    lines.append("| Check | Result | Detail |")
    lines.append("|---|---|---|")
    for check in verdict["checks"]:
        lines.append(f"| {check['name']} | {check['status']} | {_cell(check['detail'])} |")
    lines.append("")
    return "\n".join(lines)
