#!/usr/bin/env python3
"""Adversarial demo: tamper with the ranking in summary.json to produce a
polluted output.

Usage:
    python3 tools/tamper.py --outputs outputs          # rewrite outputs/summary.json in place
    python3 tools/tamper.py --outputs outputs --copy-to outputs_tampered

Purpose: prove that the independent validator is not decorative. Once the
ranking has been touched, the validator must fail with a non-zero exit code.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path


def tamper(summary: dict) -> dict:
    """Swap the list positions of the first two risks (as if a low-score risk
    had been promoted by hand).

    Note: this changes the **list order** only, not the rank fields, so the
    ranking recomputation check is what has to catch it.
    """
    risks = summary["risks"]
    if len(risks) < 2:
        raise SystemExit("need at least two risks to build a tampering sample")
    risks[0], risks[1] = risks[1], risks[0]
    return summary


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Build a tampered summary.json")
    parser.add_argument("--outputs", required=True)
    parser.add_argument("--copy-to", default=None,
                        help="copy the whole output directory first, then tamper "
                             "(default: tamper in place)")
    args = parser.parse_args(argv)

    outputs = Path(args.outputs)
    target = outputs
    if args.copy_to:
        target = Path(args.copy_to)
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(outputs, target)

    summary_path = target / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary = tamper(summary)
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
                            encoding="utf-8")
    print(f"Tampered {summary_path}: swapped risks at positions 1 and 2")
    return 0


if __name__ == "__main__":
    sys.exit(main())
