"""Parse layer tests.

What they pin down: the parse layer reads per-stage raw artifacts into Findings,
evidence references are always `filename:line`, and line numbers are recorded
while reading from disk -- so every conclusion resolves mechanically to a real
input artifact line.
"""
import json

import pytest

from evidencechain.parse import ParseError, load_artifacts, parse_artifact


def write_lines(tmp_path, name, lines):
    p = tmp_path / name
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def test_parse_reads_fields(tmp_path):
    p = write_lines(tmp_path, "stage2_scan.jsonl", [
        json.dumps({
            "id": "F-201",
            "title": "Out-of-bounds write in image parser",
            "asset": "svc-frontend-02",
            "asset_criticality": "critical",
            "cvss": 9.1,
            "reachability": "network",
            "cve": "CVE-2024-21538",
            "remediation": "Upgrade image parser to 3.2.1",
        }),
    ])
    findings = parse_artifact(p, "stage2_scan.jsonl")
    assert len(findings) == 1
    f = findings[0]
    assert f.finding_id == "F-201"
    assert f.title == "Out-of-bounds write in image parser"
    assert f.asset == "svc-frontend-02"
    assert f.asset_criticality == "critical"
    assert f.cvss == 9.1
    assert f.reachability == "network"
    assert f.cve == "CVE-2024-21538"
    assert f.stage == "stage2_scan"


def test_evidence_ref_is_file_and_line(tmp_path):
    p = write_lines(tmp_path, "stage2_scan.jsonl", [
        json.dumps({"id": "A", "title": "t", "asset": "a", "cvss": 1.0, "reachability": "local"}),
        json.dumps({"id": "B", "title": "t2", "asset": "a", "cvss": 1.0, "reachability": "local"}),
    ])
    findings = parse_artifact(p, "stage2_scan.jsonl")
    assert findings[0].evidence.ref() == "stage2_scan.jsonl:1"
    assert findings[1].evidence.ref() == "stage2_scan.jsonl:2"
    assert findings[0].evidence.line == 1


def test_blank_lines_are_skipped_and_line_numbers_stay_true(tmp_path):
    p = write_lines(tmp_path, "s.jsonl", [
        "",
        json.dumps({"id": "A", "title": "t", "asset": "a", "cvss": 1.0, "reachability": "local"}),
        "",
    ])
    findings = parse_artifact(p, "s.jsonl")
    assert len(findings) == 1
    # Blank lines still count: line 1 is blank, the real record sits on line 2
    assert findings[0].evidence.line == 2


def test_malformed_json_raises_with_location(tmp_path):
    p = write_lines(tmp_path, "s.jsonl", ["{not json"])
    with pytest.raises(ParseError) as e:
        parse_artifact(p, "s.jsonl")
    assert "s.jsonl:1" in str(e.value)


def test_missing_required_field_raises(tmp_path):
    p = write_lines(tmp_path, "s.jsonl", [json.dumps({"id": "A", "title": "t"})])
    with pytest.raises(ParseError) as e:
        parse_artifact(p, "s.jsonl")
    assert "asset" in str(e.value)


def test_cvss_out_of_range_raises(tmp_path):
    p = write_lines(tmp_path, "s.jsonl", [
        json.dumps({"id": "A", "title": "t", "asset": "a", "cvss": 11.0, "reachability": "local"}),
    ])
    with pytest.raises(ParseError):
        parse_artifact(p, "s.jsonl")


def test_cvss_numeric_string_is_accepted(tmp_path):
    p = write_lines(tmp_path, "s.jsonl", [
        json.dumps({"id": "A", "title": "t", "asset": "a", "cvss": "5.3", "reachability": "local"}),
    ])
    assert parse_artifact(p, "s.jsonl")[0].cvss == 5.3


def test_invalid_criticality_raises(tmp_path):
    p = write_lines(tmp_path, "s.jsonl", [
        json.dumps({"id": "A", "title": "t", "asset": "a", "cvss": 1.0,
                    "reachability": "local", "asset_criticality": "extreme"}),
    ])
    with pytest.raises(ParseError):
        parse_artifact(p, "s.jsonl")


def test_invalid_reachability_raises(tmp_path):
    p = write_lines(tmp_path, "s.jsonl", [
        json.dumps({"id": "A", "title": "t", "asset": "a", "cvss": 1.0, "reachability": "satellite"}),
    ])
    with pytest.raises(ParseError):
        parse_artifact(p, "s.jsonl")


def test_load_artifacts_is_sorted_and_deterministic(tmp_path):
    write_lines(tmp_path, "stage3_manual.jsonl", [
        json.dumps({"id": "C", "title": "t3", "asset": "a", "cvss": 3.0, "reachability": "local"}),
    ])
    write_lines(tmp_path, "stage1_recon.jsonl", [
        json.dumps({"id": "A", "title": "t1", "asset": "a", "cvss": 1.0, "reachability": "local"}),
    ])
    write_lines(tmp_path, "stage2_scan.jsonl", [
        json.dumps({"id": "B", "title": "t2", "asset": "a", "cvss": 2.0, "reachability": "local"}),
    ])
    first = load_artifacts(tmp_path)
    second = load_artifacts(tmp_path)
    assert [f.finding_id for f in first] == ["A", "B", "C"]
    assert [f.finding_id for f in first] == [f.finding_id for f in second]


def test_missing_input_dir_raises(tmp_path):
    with pytest.raises(ParseError):
        load_artifacts(tmp_path / "nope")


def test_note_field_is_carried_through(tmp_path):
    p = write_lines(tmp_path, "s.jsonl", [
        json.dumps({"id": "A", "title": "t", "asset": "a", "cvss": 1.0,
                    "reachability": "local", "note": "manual observation"}),
    ])
    assert parse_artifact(p, "s.jsonl")[0].note == "manual observation"
