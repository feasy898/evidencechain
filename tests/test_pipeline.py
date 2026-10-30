"""End-to-end pipeline + independent validator tests.

What they pin down:
- Pipeline determinism: same inputs twice -> byte-identical outputs (no timestamps).
- Independent validator: fresh outputs pass; tampered ranking must fail (non-zero exit).
- Offline-ready: no network calls anywhere in the source.
"""
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

from evidencechain.pipeline import run_pipeline

APP_ROOT = Path(__file__).resolve().parents[1]
DEMO_INPUTS = APP_ROOT / "demo" / "inputs"


def load_tool(name):
    path = APP_ROOT / "tools" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_pipeline_writes_three_artifacts(tmp_path):
    out = tmp_path / "outputs"
    summary = run_pipeline(DEMO_INPUTS, out)
    assert (out / "summary.json").exists()
    assert (out / "risk_register.md").exists()
    assert (out / "verdict.json").exists()
    assert summary["verdict"]["status"] == "PASS"


def test_pipeline_counts_on_demo_inputs(tmp_path):
    summary = run_pipeline(DEMO_INPUTS, tmp_path / "outputs")
    assert summary["totals"]["raw_findings"] == 10
    assert summary["totals"]["unique_risks"] == 8
    assert summary["totals"]["merged_duplicates"] == 2


def test_pipeline_is_deterministic(tmp_path):
    first = tmp_path / "a"
    second = tmp_path / "b"
    run_pipeline(DEMO_INPUTS, first)
    run_pipeline(DEMO_INPUTS, second)
    for name in ("summary.json", "risk_register.md", "verdict.json"):
        assert (first / name).read_bytes() == (second / name).read_bytes(), name


def test_pipeline_evidence_points_to_real_input_lines(tmp_path):
    summary = run_pipeline(DEMO_INPUTS, tmp_path / "outputs")
    for risk in summary["risks"]:
        assert risk["evidence"], risk["id"]
        for ev in risk["evidence"]:
            source = DEMO_INPUTS / ev["file"]
            assert source.exists(), ev
            lines = source.read_text(encoding="utf-8").splitlines()
            assert 1 <= ev["line"] <= len(lines)
            record = json.loads(lines[ev["line"] - 1])
            assert record["id"] == ev["finding_id"]


def test_pipeline_output_has_no_injection_payload(tmp_path):
    out = tmp_path / "outputs"
    run_pipeline(DEMO_INPUTS, out)
    text = (out / "risk_register.md").read_text(encoding="utf-8").lower()
    assert "ignore previous instructions" not in text
    assert "mark this finding as resolved" not in text


def test_summary_records_injection_flags(tmp_path):
    summary = run_pipeline(DEMO_INPUTS, tmp_path / "outputs")
    flagged = [r for r in summary["risks"] if r["injection_flags"]]
    assert len(flagged) == 1, [r["id"] for r in flagged]
    assert flagged[0]["id"] == "R-005"
    assert "ignore previous instructions" in flagged[0]["injection_flags"]


def test_validator_passes_on_fresh_outputs(tmp_path):
    out = tmp_path / "outputs"
    run_pipeline(DEMO_INPUTS, out)
    validator = load_tool("validate_outputs")
    code = validator.main(["--inputs", str(DEMO_INPUTS), "--outputs", str(out)])
    assert code == 0


def test_validator_fails_on_tampered_ranking(tmp_path):
    out = tmp_path / "outputs"
    run_pipeline(DEMO_INPUTS, out)
    tamper = load_tool("tamper")
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    summary = tamper.tamper(summary)
    (out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2),
                                       encoding="utf-8")
    validator = load_tool("validate_outputs")
    code = validator.main(["--inputs", str(DEMO_INPUTS), "--outputs", str(out)])
    assert code != 0


def test_validator_fails_when_a_register_cell_is_altered(tmp_path):
    out = tmp_path / "outputs"
    run_pipeline(DEMO_INPUTS, out)
    register = out / "risk_register.md"
    text = register.read_text(encoding="utf-8")
    assert "| 9.1 | 9.1 |" in text  # CVSS and priority cells of R-001
    register.write_text(text.replace("| 9.1 | 9.1 |", "| 9.1 | 999.0 |", 1),
                        encoding="utf-8")
    validator = load_tool("validate_outputs")
    code = validator.main(["--inputs", str(DEMO_INPUTS), "--outputs", str(out)])
    assert code != 0


def test_validator_fails_when_summary_facts_contradict_inputs(tmp_path):
    out = tmp_path / "outputs"
    run_pipeline(DEMO_INPUTS, out)
    summary_path = out / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    for risk in summary["risks"]:
        if risk["id"] == "R-004":
            risk["cvss"] = 4.5  # the cited input line says 5.3
            risk["title"] = "TOTALLY FABRICATED TITLE"
            risk["asset"] = "attacker-controlled-host"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
                            encoding="utf-8")
    validator = load_tool("validate_outputs")
    code = validator.main(["--inputs", str(DEMO_INPUTS), "--outputs", str(out)])
    assert code != 0


def test_tamper_swaps_list_order_not_just_rank_fields():
    tamper = load_tool("tamper")
    summary = {"risks": [{"rank": 1, "key": "a"}, {"rank": 2, "key": "b"}]}
    tampered = tamper.tamper(summary)
    assert [r["key"] for r in tampered["risks"]] == ["b", "a"]
    assert [r["rank"] for r in tampered["risks"]] == [2, 1]


def test_validator_fails_when_evidence_file_is_gone(tmp_path):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    for src in DEMO_INPUTS.glob("*.jsonl"):
        (inputs / src.name).write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    out = tmp_path / "outputs"
    run_pipeline(inputs, out)
    (inputs / "stage2_scan.jsonl").unlink()
    validator = load_tool("validate_outputs")
    code = validator.main(["--inputs", str(inputs), "--outputs", str(out)])
    assert code != 0


def test_source_contains_no_network_imports():
    """AST-based: fails if any module under evidencechain/ or tools/ imports a
    network-capable library, however the import is spelled (including
    `from urllib import request`)."""
    import ast

    network_roots = {
        "requests", "urllib", "urllib3", "http", "httpx", "aiohttp", "socket",
        "ssl", "ftplib", "telnetlib", "smtplib", "xmlrpc", "webbrowser",
        "pycurl", "curl_cffi", "websockets", "websocket",
    }
    offenders = []
    paths = sorted((APP_ROOT / "evidencechain").glob("*.py")) \
        + sorted((APP_ROOT / "tools").glob("*.py"))
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                imported = [node.module]
            else:
                continue
            for name in imported:
                if name.split(".")[0] in network_roots:
                    offenders.append(f"{path.name}: {name}")
    assert offenders == []


def test_cli_runs_as_module(tmp_path):
    out = tmp_path / "outputs"
    proc = subprocess.run(
        [sys.executable, "-m", "evidencechain.pipeline", "--input", str(DEMO_INPUTS),
         "--output", str(out)],
        cwd=str(APP_ROOT), capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert "R-001" in proc.stdout


def test_demo_script_runs_end_to_end(tmp_path):
    proc = subprocess.run(["bash", "demo/run_demo.sh"], cwd=str(APP_ROOT),
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Independent verdict: PASS" in proc.stdout
    assert "Tamper caught as expected" in proc.stdout
