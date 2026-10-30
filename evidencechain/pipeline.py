"""End-to-end pipeline: parse -> aggregate -> prioritize -> audit -> write reports.

Command line:
    python3 -m evidencechain.pipeline --input demo/inputs --output outputs

Outputs (fully deterministic, no timestamps; repeated runs are byte-identical):
    outputs/summary.json      structured, prioritized risk report
    outputs/risk_register.md  human-readable risk register
    outputs/verdict.json      independent audit result
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .aggregate import aggregate
from .parse import digest_inputs, load_artifacts
from .prioritize import audit_ranking, prioritize
from .report import build_summary, render_report


def run_pipeline(input_dir, output_dir) -> dict:
    """Run the full pipeline once and return the structured summary."""
    findings = load_artifacts(input_dir)
    risks = aggregate(findings)
    ranked = prioritize(risks)
    verdict = audit_ranking(ranked)
    digest = digest_inputs(input_dir)
    summary = build_summary(ranked, raw_count=len(findings), digest=digest, verdict=verdict)

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=False) + "\n",
        encoding="utf-8")
    (out / "risk_register.md").write_text(render_report(summary), encoding="utf-8")
    (out / "verdict.json").write_text(
        json.dumps(verdict, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return summary


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="EvidenceChain security-assessment finding pipeline")
    parser.add_argument("--input", required=True, help="input artifact directory (*.jsonl)")
    parser.add_argument("--output", required=True, help="output directory for reports")
    args = parser.parse_args(argv)

    summary = run_pipeline(args.input, args.output)
    totals = summary["totals"]
    print(f"Input digest {summary['input_digest']}")
    print(f"{totals['raw_findings']} raw findings -> {totals['unique_risks']} unique risks "
          f"({totals['merged_duplicates']} duplicates merged)")
    for risk in summary["risks"]:
        refs = ", ".join(risk["evidence_refs"])
        print(f"  {risk['rank']:>2}. {risk['id']} [{risk['severity']:<8}] {risk['title']} "
              f"(priority {risk['priority_score']} | evidence {refs})")
    print(f"Independent verdict: {summary['verdict']['status']}")
    return 0 if summary["verdict"]["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
