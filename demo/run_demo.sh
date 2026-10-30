#!/usr/bin/env bash
# EvidenceChain demo script (runs fully offline, no network calls)
#
#   bash demo/run_demo.sh
#
# Three acts:
#   1. Normal run: synthetic artifacts -> structured risk report + risk register
#   2. Independent validation: evidence resolved line by line, ranking
#      recomputed, register cross-checked, no injection residue
#   3. Adversarial demo: tampered ranking must be caught by the validator;
#      then re-run inside a no-network namespace and compare outputs
set -euo pipefail

cd "$(dirname "$0")/.."
OUT="outputs"
TAMPERED="outputs_tampered"
OFFLINE="outputs_offline"

echo "=== 1. Normal pipeline run ==="
python3 -m evidencechain.pipeline --input demo/inputs --output "$OUT"

echo
echo "=== 2. Independent validation (evidence refs / ranking / register / injection) ==="
python3 tools/validate_outputs.py --inputs demo/inputs --outputs "$OUT"

echo
echo "=== 3a. Adversarial: tampered ranking must be caught ==="
python3 tools/tamper.py --outputs "$OUT" --copy-to "$TAMPERED"
set +e
python3 tools/validate_outputs.py --inputs demo/inputs --outputs "$TAMPERED"
tamper_code=$?
set -e
if [ "$tamper_code" -ne 0 ]; then
  echo "Tamper caught as expected: validator exit code on tampered outputs = $tamper_code"
else
  echo "SERIOUS PROBLEM: validator failed to catch the tampered ranking" >&2
  exit 1
fi

echo
echo "=== 3b. Offline rerun (unshare network namespace); outputs must be identical ==="
OFFLINE_RUNNER=""
if command -v unshare >/dev/null 2>&1; then
  if unshare -rn true 2>/dev/null; then
    OFFLINE_RUNNER="unshare -rn"
  elif unshare -n true 2>/dev/null; then
    OFFLINE_RUNNER="unshare -n"
  fi
fi
if [ -n "$OFFLINE_RUNNER" ]; then
  $OFFLINE_RUNNER python3 -m evidencechain.pipeline --input demo/inputs --output "$OFFLINE" >/dev/null
  if diff -r "$OUT" "$OFFLINE" >/dev/null; then
    echo "Offline rerun matches: outputs and outputs_offline are identical (via $OFFLINE_RUNNER)"
  else
    echo "SERIOUS PROBLEM: offline rerun produced different outputs" >&2
    exit 1
  fi
else
  echo "unshare network namespaces unavailable on this machine; skipping the offline drill (not executed, not claimed)"
fi

echo
echo "Output files:"
ls -1 "$OUT"
