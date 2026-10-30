#!/usr/bin/env python3
"""Independent validator: machine-checks pipeline outputs; any failed check
exits non-zero.

Usage:
    python3 tools/validate_outputs.py --inputs demo/inputs --outputs outputs

Five checks:
    1. digest_matches              the input digest anchored in the report
                                   matches the current inputs
    2. evidence_resolves           every `file:line` evidence reference exists
                                   in the input artifacts, the id matches, AND
                                   each risk's facts (cvss, title, asset,
                                   severity, priority, ...) match what those
                                   input lines actually say
    3. ranking_matches_recomputed  the reported order matches an order
                                   recomputed by this validator's OWN copy of
                                   the scoring tables -- the pipeline's
                                   prioritize module is never called
    4. register_matches_summary    every cell of the Markdown register matches
                                   summary.json
    5. no_known_payload_in_outputs the free-text fields of the outputs are
                                   re-scanned with the known injection patterns
                                   (the injection_flags audit records are
                                   exempt; see the README Limitations section
                                   for what this does and does not guarantee)

Independence note: the scoring tables below deliberately duplicate
evidencechain/prioritize.py instead of importing it, so a changed pipeline
formula breaks check 3. They live in the same repository, though -- this
validator audits outputs, it is not an out-of-band trust anchor.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evidencechain.parse import detect_injection, digest_inputs, sanitize_text  # noqa: E402

# --- Validator-local copies of the pipeline's scoring tables ---------------
# Keep in sync with evidencechain/prioritize.py BY HAND. That is the point:
# if the pipeline's formula or weights change, check 3 fails until this copy
# is updated deliberately.
CRITICALITY_ORDER = ("low", "medium", "high", "critical")
REACHABILITY_ORDER = ("local", "adjacent", "network")
ASSET_WEIGHTS = {"low": 0.2, "medium": 0.5, "high": 0.8, "critical": 1.0}
REACH_FACTORS = {"local": 0.3, "adjacent": 0.6, "network": 1.0}
SEVERITY_BANDS = ((9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.0, "low"))


def _local_severity(cvss: float) -> str:
    for threshold, name in SEVERITY_BANDS:
        if cvss >= threshold:
            return name
    return "low"


def _local_score(entry: dict) -> float:
    cvss = float(entry["cvss"])
    weight = ASSET_WEIGHTS[entry["asset_criticality"]]
    factor = REACH_FACTORS[entry["reachability"]]
    return round(cvss * weight * factor, 4)


REGISTER_HEADER = ("| Rank | ID | Title | Asset | Severity | CVSS | Priority | "
                   "Reachability | Stages | Evidence | Remediation |")
REGISTER_COLUMNS = ("rank", "id", "title", "asset", "severity", "cvss", "priority",
                    "reachability", "stages", "evidence", "remediation")


def _split_row(line: str) -> list[str]:
    """Split a Markdown table row into cells, honoring `\\|` escapes."""
    inner = line.strip().removeprefix("|").removesuffix("|")
    return [c.replace("\\|", "|").strip() for c in re.split(r"(?<!\\)\|", inner)]


def _check_digest(inputs: Path, summary: dict) -> tuple[bool, str]:
    actual = digest_inputs(inputs)
    if actual != summary.get("input_digest"):
        return False, (f"input digest mismatch: report={summary.get('input_digest')} "
                       f"actual={actual}")
    return True, f"input digest matches {actual}"


def _fact_problems(risk_id: str, entry: dict, records: list[dict]) -> list[str]:
    """Compare one risk's reported facts against its cited input records.

    Re-derives the merge rules (worst value wins, head = highest CVSS with
    finding_id tiebreak) independently of the aggregate module.
    """
    problems: list[str] = []
    if not records:
        return []  # nothing resolved; the missing-evidence problem is already recorded

    def fact(name: str, from_inputs, from_report) -> None:
        if from_inputs != from_report:
            problems.append(f"{risk_id} {name}: report={from_report!r} inputs={from_inputs!r}")

    input_ids = sorted(str(r.get("id", "")).strip() for r in records)
    if sorted(entry.get("merged_from", [])) != input_ids:
        problems.append(f"{risk_id} merged ids: report={entry.get('merged_from')} "
                        f"inputs={input_ids}")

    head = sorted(records, key=lambda r: (-float(r.get("cvss", 0.0)),
                                          str(r.get("id", "")).strip()))[0]
    cvss = float(head["cvss"])
    fact("cvss (worst of merged)", cvss, float(entry["cvss"]))
    fact("title (head finding)", sanitize_text(str(head.get("title", "")))[0].strip(),
         entry["title"])
    fact("asset (head finding)", str(head.get("asset", "")).strip(), entry["asset"])
    fact("remediation (head finding)",
         sanitize_text(str(head.get("remediation", "")))[0].strip(), entry["remediation"])
    cve = head.get("cve")
    cve = cve.strip().upper() if isinstance(cve, str) and cve.strip() else None
    fact("cve", cve, entry.get("cve"))

    criticality, reachability = "low", "local"
    for record in records:
        candidate = record.get("asset_criticality", "medium")
        if candidate in CRITICALITY_ORDER and \
                CRITICALITY_ORDER.index(candidate) > CRITICALITY_ORDER.index(criticality):
            criticality = candidate
        candidate = record.get("reachability")
        if candidate in REACHABILITY_ORDER and \
                REACHABILITY_ORDER.index(candidate) > REACHABILITY_ORDER.index(reachability):
            reachability = candidate
    fact("asset_criticality (worst of merged)", criticality, entry["asset_criticality"])
    fact("reachability (most exposed of merged)", reachability, entry["reachability"])

    stages = sorted({Path(ev["file"]).stem for ev in entry["evidence"]})
    fact("stages", stages, list(entry["stages"]))
    fact("severity (band of cvss)", _local_severity(cvss), entry["severity"])
    fact("priority_score", _local_score(entry), round(float(entry["priority_score"]), 4))
    return problems


def _check_evidence(inputs: Path, summary: dict) -> tuple[bool, str]:
    problems = []
    for risk in summary["risks"]:
        if not risk["evidence"]:
            problems.append(f"{risk['id']} has no evidence")
            continue
        records = []
        for ev in risk["evidence"]:
            source = inputs / ev["file"]
            if not source.exists():
                problems.append(f"{risk['id']} evidence file missing: {ev['file']}")
                continue
            lines = source.read_text(encoding="utf-8").splitlines()
            line_no = int(ev["line"])
            if not (1 <= line_no <= len(lines)):
                problems.append(f"{risk['id']} evidence line out of range: {ev['file']}:{line_no}")
                continue
            try:
                record = json.loads(lines[line_no - 1])
            except json.JSONDecodeError:
                problems.append(f"{risk['id']} evidence line is not valid JSON: "
                                f"{ev['file']}:{line_no}")
                continue
            if ev.get("finding_id") and record.get("id") != ev["finding_id"]:
                problems.append(f"{risk['id']} evidence id mismatch: {ev['file']}:{line_no}")
                continue
            records.append(record)
        problems.extend(_fact_problems(risk["id"], risk, records))
    if problems:
        return False, "; ".join(problems)
    total = sum(len(r["evidence"]) for r in summary["risks"])
    return True, (f"all {total} evidence references resolved and every risk's facts "
                  f"match the input lines it cites")


def _check_ranking(summary: dict) -> tuple[bool, str]:
    actual = [r["key"] for r in summary["risks"]]
    expected = [r["key"] for r in
                sorted(summary["risks"], key=lambda r: (-_local_score(r), r["key"]))]
    if expected != actual:
        for i, (a, e) in enumerate(zip(actual, expected)):
            if a != e:
                return False, (f"order diverges from recomputation at position {i + 1}: "
                               f"actual={a} expected={e}")
        return False, (f"order length mismatch: actual={len(actual)} "
                       f"expected={len(expected)}")
    return True, (f"order of {len(actual)} risks matches this validator's own "
                  f"recomputation of the formula")


def _check_register(outputs: Path, summary: dict) -> tuple[bool, str]:
    register = outputs / "risk_register.md"
    if not register.exists():
        return False, f"missing {register}"
    lines = register.read_text(encoding="utf-8").splitlines()
    try:
        header_index = lines.index(REGISTER_HEADER)
    except ValueError:
        return False, "register header row missing or altered"
    rows: list[str] = []
    for line in lines[header_index + 2:]:  # +1 is the separator row
        if not line.startswith("|"):
            break
        rows.append(line)

    risks = summary["risks"]
    if len(rows) != len(risks):
        return False, (f"register has {len(rows)} data rows, summary has {len(risks)} risks")
    for row, risk in zip(rows, risks):
        cells = _split_row(row)
        if len(cells) != len(REGISTER_COLUMNS):
            return False, (f"{risk['id']}: register row has {len(cells)} cells, "
                           f"expected {len(REGISTER_COLUMNS)}")
        expected = [
            str(risk["rank"]), risk["id"], risk["title"], risk["asset"], risk["severity"],
            str(risk["cvss"]), str(risk["priority_score"]), risk["reachability"],
            ", ".join(risk["stages"]) or "-",
            ", ".join(risk["evidence_refs"]) or "-",
            risk["remediation"] or "-",
        ]
        for column, got, want in zip(REGISTER_COLUMNS, cells, expected):
            if column in ("cvss", "priority"):
                try:
                    ok = abs(float(got) - float(want)) <= 1e-9
                except ValueError:
                    ok = False
            else:
                ok = got == want
            if not ok:
                return False, (f"{risk['id']} register cell '{column}': "
                               f"register={got!r} summary={want!r}")
    return True, (f"all {len(rows)} register rows match summary cell by cell "
                  f"({len(REGISTER_COLUMNS)} columns)")


def _check_injection(outputs: Path) -> tuple[bool, str]:
    """Re-scan the output fields that carry artifact text.

    The `injection_flags` records in summary.json are exempt on purpose: they
    are the audit trail of payloads the gate already caught and redacted, so
    they contain pattern text by design.
    """
    problems = []
    register = outputs / "risk_register.md"
    if register.exists():
        flags = detect_injection(register.read_text(encoding="utf-8"))
        if flags:
            problems.append(f"risk_register.md: {len(flags)} hit(s)")
    summary_path = outputs / "summary.json"
    if summary_path.exists():
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        for risk in summary.get("risks", []):
            for field in ("title", "note", "remediation"):
                hits = detect_injection(str(risk.get(field) or ""))
                if hits:
                    problems.append(f"summary.json {risk['id']}.{field}: {len(hits)} hit(s)")
    if problems:
        return False, "; ".join(problems)
    return True, "no text matching the known injection patterns remains in the outputs"


def _check_coverage(inputs: Path, summary: dict) -> tuple[bool, str]:
    """Completeness: every finding in the input artifacts must be accounted for.

    Two independent facts are checked here:

    * the input artifacts really contain N findings — counted here from the
      artifact files themselves, not read from the report;
    * the report accounts for all N: the risks it lists cite every input
      finding (directly, or as one of a merged group), and the totals block
      agrees with the risks it describes.

    Without this, a risk could be deleted from the report and the register
    regenerated to match, and every other check would still pass.
    """
    problems = []
    input_finding_ids = set()
    for path in sorted(inputs.glob("*.jsonl")):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                problems.append(f"input line is not valid JSON: {path.name}:{lineno}")
                continue
            if record.get("id"):
                input_finding_ids.add(str(record["id"]))

    covered = set()
    for risk in summary["risks"]:
        for ev in risk.get("evidence", []):
            if ev.get("finding_id"):
                covered.add(str(ev["finding_id"]))
        for fid in risk.get("merged_from", []):
            covered.add(str(fid))
    missing = sorted(input_finding_ids - covered)
    if missing:
        problems.append(f"{len(missing)} input finding(s) are not represented in the "
                        f"report: {', '.join(missing[:8])}"
                        + (" ..." if len(missing) > 8 else ""))

    totals = summary.get("totals") or {}
    risks = summary.get("risks") or []
    if totals:
        if totals.get("unique_risks") != len(risks):
            problems.append(f"totals.unique_risks={totals.get('unique_risks')} but the "
                            f"report lists {len(risks)} risks")
        if totals.get("raw_findings") != len(input_finding_ids):
            problems.append(f"totals.raw_findings={totals.get('raw_findings')} but the "
                            f"inputs contain {len(input_finding_ids)} findings")
        merged = sum(len(r.get("merged_from", [])) for r in risks)
        expected_merged = len(input_finding_ids) - len(risks)
        if totals.get("merged_duplicates") != expected_merged:
            problems.append(f"totals.merged_duplicates={totals.get('merged_duplicates')} "
                            f"but the risks merge {expected_merged} duplicate(s)")
        by_sev = totals.get("by_severity")
        if isinstance(by_sev, dict):
            actual = {}
            for r in risks:
                actual[r["severity"]] = actual.get(r["severity"], 0) + 1
            if by_sev != actual:
                problems.append(f"totals.by_severity={by_sev} but the risks give {actual}")
    if problems:
        return False, "; ".join(problems)
    return True, (f"all {len(input_finding_ids)} input findings are accounted for and "
                  f"the totals agree with the {len(risks)} reported risks")


def validate(inputs: Path, outputs: Path) -> tuple[int, list[tuple[str, bool, str]]]:
    summary_path = outputs / "summary.json"
    if not summary_path.exists():
        return 1, [("summary_present", False, f"missing {summary_path}")]
    summary = json.loads(summary_path.read_text(encoding="utf-8"))

    results = [
        ("digest_matches",) + _check_digest(inputs, summary),
        ("evidence_resolves",) + _check_evidence(inputs, summary),
        ("ranking_matches_recomputed",) + _check_ranking(summary),
        ("register_matches_summary",) + _check_register(outputs, summary),
        ("coverage_complete",) + _check_coverage(inputs, summary),
        ("no_known_payload_in_outputs",) + _check_injection(outputs),
    ]
    ok = all(passed for _, passed, _ in results)
    return (0 if ok else 1), results


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="EvidenceChain independent output validator")
    parser.add_argument("--inputs", required=True)
    parser.add_argument("--outputs", required=True)
    args = parser.parse_args(argv)

    code, results = validate(Path(args.inputs), Path(args.outputs))
    for name, passed, detail in results:
        print(f"[{'PASS' if passed else 'FAIL'}] {name}: {detail}")
    print(f"Verdict: {'PASS' if code == 0 else 'FAIL'}")
    return code


if __name__ == "__main__":
    sys.exit(main())
