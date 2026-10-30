"""Parse layer: read per-stage raw artifacts into Findings, behind an
input-injection gate.

Two ground rules:
1. Evidence resolves: every Finding remembers which file and line it came from,
   referenced as `filename:line`.
2. Artifacts are data, not instructions: prompt-injection payloads found in free
   text are redacted in place and recorded (injection_flags).
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import List, Tuple

from .models import Evidence, Finding, ParseError

# Allowed enum values (deterministic, fixed in code)
ASSET_CRITICALITIES = ("low", "medium", "high", "critical")
REACHABILITIES = ("local", "adjacent", "network")

# Required fields; validation order == error-reporting order
REQUIRED_FIELDS = ("id", "title", "asset", "cvss", "reachability")

# Free-text fields (each one passes through the injection gate)
TEXT_FIELDS = ("title", "note", "remediation")

# Upper bound on text length (defends against oversized fields in artifacts)
MAX_TEXT_LEN = 2000

# Prompt-injection signatures: imperative override phrases (English/Chinese),
# role markers, and requests to expose or rewrite state
INJECTION_PATTERNS = (
    r"ignore\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|rules?)",
    r"disregard\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|system)",
    r"忽略(?:掉)?(?:前面|上面|上述|以上|先前)?(?:的)?(?:所有)?(?:指令|提示|规则)",
    r"忘记(?:前面|上面|上述|以上)?(?:的)?(?:所有)?(?:指令|提示)",
    r"you\s+are\s+now\b",
    r"system\s*[:>]|assistant\s*[:>]|user\s*[:>]",
    r"<\s*\|\s*im_(?:start|end)\s*\|>",
    r"reveal\s+(?:your\s+)?system\s+prompt",
    r"(?:output|print|say|echo)\s+(?:the\s+)?word\s+\w+",
    r"mark\s+(?:this|it|that)\b[^.;]{0,40}?\bas\s+\w+",
    r"<\s*script\b|javascript\s*:",
)

_INJECTION_RE = re.compile("|".join(f"(?:{p})" for p in INJECTION_PATTERNS), re.IGNORECASE)
_REDACT = "[REDACTED-INJECTION]"


def detect_injection(text: str) -> List[str]:
    """Return the injection signatures matched by the text (empty list = clean)."""
    if not text:
        return []
    return [m.group(0) for m in _INJECTION_RE.finditer(text)]


def sanitize_text(text: str) -> Tuple[str, List[str]]:
    """Replace injection payloads with `[REDACTED-INJECTION]` in place.

    Returns (sanitized text, matched signatures).
    """
    if not text:
        return "", []
    flags = detect_injection(text)
    if not flags:
        return text[:MAX_TEXT_LEN], []
    cleaned = _INJECTION_RE.sub(_REDACT, text)
    return cleaned[:MAX_TEXT_LEN], flags


def _require(obj: dict, field: str, rel: str, lineno: int):
    if field not in obj or obj[field] is None:
        raise ParseError(f"{rel}:{lineno}: missing required field {field!r}")
    return obj[field]


def _parse_cvss(value, rel: str, lineno: int) -> float:
    if isinstance(value, bool):
        raise ParseError(f"{rel}:{lineno}: cvss must be a number")
    try:
        cvss = float(value)
    except (TypeError, ValueError):
        raise ParseError(f"{rel}:{lineno}: cvss must be a number, got {value!r}") from None
    if not (0.0 <= cvss <= 10.0):
        raise ParseError(f"{rel}:{lineno}: cvss must be within 0..10, got {cvss}")
    return cvss


def parse_artifact(path: Path, rel_name: str) -> List[Finding]:
    """Parse one JSONL artifact file into Findings (line numbers are evidence lines)."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ParseError(f"{rel_name}: failed to read: {exc}") from None

    stage = Path(rel_name).stem
    findings: List[Finding] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip():
            continue
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ParseError(f"{rel_name}:{lineno}: invalid JSON ({exc.msg})") from None
        if not isinstance(obj, dict):
            raise ParseError(f"{rel_name}:{lineno}: each line must be a JSON object")

        for field in REQUIRED_FIELDS:
            _require(obj, field, rel_name, lineno)

        criticality = obj.get("asset_criticality", "medium")
        if criticality not in ASSET_CRITICALITIES:
            raise ParseError(
                f"{rel_name}:{lineno}: invalid asset_criticality {criticality!r} "
                f"(allowed: {', '.join(ASSET_CRITICALITIES)})")
        reachability = obj["reachability"]
        if reachability not in REACHABILITIES:
            raise ParseError(
                f"{rel_name}:{lineno}: invalid reachability {reachability!r} "
                f"(allowed: {', '.join(REACHABILITIES)})")

        # Injection gate: redact and record, one free-text field at a time
        clean: dict = {}
        flags: List[str] = []
        for field in TEXT_FIELDS:
            raw_text = obj.get(field) or ""
            if not isinstance(raw_text, str):
                raise ParseError(f"{rel_name}:{lineno}: {field} must be a string")
            value, hits = sanitize_text(raw_text)
            clean[field] = value
            flags.extend(hits)

        cve = obj.get("cve")
        if cve is not None:
            if not isinstance(cve, str):
                raise ParseError(f"{rel_name}:{lineno}: cve must be a string")
            cve = cve.strip().upper() or None

        findings.append(Finding(
            finding_id=str(obj["id"]).strip(),
            stage=stage,
            title=clean["title"].strip(),
            asset=str(obj["asset"]).strip(),
            asset_criticality=criticality,
            cvss=_parse_cvss(obj["cvss"], rel_name, lineno),
            reachability=reachability,
            cve=cve,
            remediation=clean["remediation"].strip(),
            note=clean["note"].strip(),
            evidence=Evidence(file=rel_name, line=lineno, finding_id=str(obj["id"]).strip()),
            injection_flags=tuple(sorted(set(flags))),
        ))
    return findings


def load_artifacts(input_dir) -> List[Finding]:
    """Load every `*.jsonl` artifact in a directory (sorted by name: deterministic)."""
    directory = Path(input_dir)
    if not directory.is_dir():
        raise ParseError(f"input directory does not exist or is not a directory: {directory}")
    findings: List[Finding] = []
    for path in sorted(directory.glob("*.jsonl"), key=lambda p: p.name):
        findings.extend(parse_artifact(path, path.name))
    return findings


def digest_inputs(input_dir) -> str:
    """Content digest (sha256) of the input artifacts; anchors reports to an input version."""
    directory = Path(input_dir)
    h = hashlib.sha256()
    for path in sorted(directory.glob("*.jsonl"), key=lambda p: p.name):
        h.update(path.name.encode("utf-8"))
        h.update(b"\0")
        h.update(path.read_bytes())
        h.update(b"\0")
    return "sha256:" + h.hexdigest()
