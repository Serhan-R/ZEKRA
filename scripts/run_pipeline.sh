#!/usr/bin/env bash
#################################
## run_pipeline.sh  (NEW FILE — does not modify any existing script)
#################################
# Purpose: run the ENTIRE per-application ZEKRA pipeline end-to-end from one
# command, starting from a raw embench-iot-applications/<name> directory
# (just the .c source files -- no manual pre-extraction needed) all the way
# through a verified SNARK proof. This script chains:
#
#   1. extractor.py            -- compile "main", build the CFG, extract a
#                                 sample execution path, and write
#                                 adjlist/recorded_path/translator/numified_*
#                                 into the app directory
#   2. roi_circuit_check.py    -- ROI detection + region pruning + circuit
#      compile (writes zekra.arith / zekra_Sample_Run1.in into
#      <app>/_roi_circuit_check/circuit_output). This stage ABORTS THE WHOLE
#      SCRIPT before any key/proof file is touched if no usable ROI can be
#      established (e.g. the requested function was inlined away and never
#      visited by the recorded path) or if the existing circuit rejects the
#      ROI-pruned witness -- see roi_extractor.py / region_prune.py.
#   3. run_keygen_raw          -- generate + save proving/verification keys
#   4. run_setup_serializer    -- pre-serialize the constraint system +
#                                 circuit metadata (structure-only, one-time)
#   5. run_prover_raw          -- evaluate the circuit on the real witness
#                                 and generate the actual SNARK proof
#   6. run_verifier_only       -- check the proof against the verification
#                                 key + public inputs -- ACCEPTED/REJECTED
#
# Usage:
#   ./scripts/run_pipeline.sh <app_name> [extra roi_circuit_check.py flags]
#
# <app_name> is just the directory name under embench-iot-applications/ (e.g.
# "minver", "crc32") -- change which app runs either by passing a different
# first argument each time, or by editing the APP_NAME default below if you'd
# rather hard-code one app. Any extra arguments are forwarded as-is to
# roi_circuit_check.py (NOT to extractor.py, which takes no extra flags
# here), e.g.:
#   ./scripts/run_pipeline.sh minver --provider gemini --force-redetect
#   ./scripts/run_pipeline.sh minver --function benchmark_body
#   ./scripts/run_pipeline.sh crc32  --heuristic-only
#
# NOTE: extractor.py recompiles "main" and re-extracts the CFG/sample path
# every run, even if you already ran it before -- this keeps the script
# fully self-contained from raw sources. If you'd rather skip re-extraction
# and reuse what's already in the app directory, comment out stage [1/6]
# below.
#
# Run this from WSL/Linux -- angr/nm/gcc (used by extractor.py and
# roi_circuit_check.py) are Linux-only tools in this pipeline, same as every
# other step in the project so far.
#
# If "./scripts/run_pipeline.sh ..." fails with "bad interpreter" (can happen
# if this file picks up Windows CRLF line endings from editing on the D:
# drive), run it as "bash scripts/run_pipeline.sh ..." instead, or
# "dos2unix scripts/run_pipeline.sh" once to fix it in place.
#
# Exit codes:
#   0 = proof generated AND the verifier ACCEPTED it
#   1 = pipeline ran to completion but the verifier REJECTED the proof
#   2 = did not get that far at all (extraction or ROI/circuit stage failed
#       or aborted, a required build tool was missing, or a keygen/prove
#       stage errored)

set -uo pipefail

# Default app name if none is given on the command line.
APP_NAME="${1:-minver}"
[ $# -ge 1 ] && shift   # remaining "$@" (if any) are forwarded to roi_circuit_check.py

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$REPO_ROOT" || { echo "[run_pipeline] Could not cd to repo root: $REPO_ROOT"; exit 2; }

APP_DIR="embench-iot-applications/$APP_NAME"
OUT="$APP_DIR/_roi_circuit_check/circuit_output"
BIN="jsnark/libsnark/build/libsnark/jsnark_interface"

banner() {
    echo
    echo "======================================================================"
    echo "$1"
    echo "======================================================================"
}

if [ ! -d "$APP_DIR" ]; then
    echo "[run_pipeline] FAIL -- no such app directory: $APP_DIR"
    exit 2
fi

if [ ! -f "extractor.py" ]; then
    echo "[run_pipeline] FAIL -- extractor.py not found at repo root: $REPO_ROOT/extractor.py"
    exit 2
fi

for tool in run_keygen_raw run_setup_serializer run_prover_raw run_verifier_only; do
    if [ ! -x "$BIN/$tool" ]; then
        echo "[run_pipeline] FAIL -- missing or non-executable: $BIN/$tool"
        echo "  (build it first -- see jsnark/libsnark/build, or rerun setup.sh's cmake/make step)"
        exit 2
    fi
done

# ── [1/6] Full extraction (CFG + sample path + compile "main") ──────────────
banner "[1/6] Full extraction (extractor.py) -- $APP_NAME"
# extractor.py (repo root) imports circuit_input_formatter.py (repo root),
# which in turn does "from poseidon.poseidon_hash import ...". The actual
# poseidon/ package only lives under scripts/, not at the repo root -- the
# roi_*.py scripts work around this internally via sys.path.insert(SCRIPT_DIR),
# but extractor.py has no such workaround and is off-limits to edit, so we
# add scripts/ to PYTHONPATH for just this one invocation instead.
PYTHONPATH="$REPO_ROOT/scripts${PYTHONPATH:+:$PYTHONPATH}" python3 extractor.py -a "$APP_DIR"
rc=$?
if [ $rc -ne 0 ]; then
    echo
    echo "[run_pipeline] ABORTING -- extractor.py exited $rc for $APP_NAME."
    echo "  Compilation, CFG extraction, or sample-path extraction failed --"
    echo "  see output above. Nothing below this point ran."
    exit 2
fi

for f in adjlist recorded_path translator numified_adjlist numified_path main; do
    if [ ! -f "$APP_DIR/$f" ]; then
        echo "[run_pipeline] FAIL -- extractor.py reported success but"
        echo "  $APP_DIR/$f is missing -- aborting."
        exit 2
    fi
done

# ── [2/6] ROI detection + pruning + circuit compile ──────────────────────────
banner "[2/6] ROI extraction + circuit compile -- $APP_NAME"
python3 scripts/roi_circuit_check.py -a "$APP_DIR" "$@"
rc=$?
if [ $rc -ne 0 ]; then
    echo
    echo "[run_pipeline] ABORTING -- roi_circuit_check.py exited $rc for $APP_NAME."
    echo "  Either no ROI could be established, the recorded path never visits"
    echo "  the chosen function(s), or the existing circuit rejected the"
    echo "  ROI-pruned witness -- see output above. No key/proof files were"
    echo "  touched; nothing below this point ran."
    exit 2
fi

if [ ! -f "$OUT/zekra.arith" ] || [ ! -f "$OUT/zekra_Sample_Run1.in" ]; then
    echo "[run_pipeline] FAIL -- roi_circuit_check.py reported success but the"
    echo "  expected output files are missing under $OUT/ -- aborting."
    exit 2
fi

# ── [3/6] Clean previous key/proof artifacts for this app ───────────────────
banner "[3/6] Cleaning previous key/proof artifacts -- $OUT"
rm -f "$OUT"/proving_key_raw.bin "$OUT"/proving_key.bin "$OUT"/verification_key.bin \
      "$OUT"/circuit_metadata.bin "$OUT"/constraint_system.bin \
      "$OUT"/proof.bin "$OUT"/primary_input.bin

# ── [4/6] Key generation ─────────────────────────────────────────────────────
banner "[4/6] Key generation (run_keygen_raw) -- $APP_NAME"
"$BIN/run_keygen_raw" gg "$OUT/zekra.arith" "$OUT/" --no-standard
rc=$?
if [ $rc -ne 0 ]; then
    echo "[run_pipeline] ABORTING -- run_keygen_raw exited $rc."
    exit 2
fi

# ── [5/6] Setup serializer (constraint system + metadata) ───────────────────
banner "[5/6] Setup serializer (run_setup_serializer) -- $APP_NAME"
"$BIN/run_setup_serializer" "$OUT/zekra.arith" "$OUT/"
rc=$?
if [ $rc -ne 0 ]; then
    echo "[run_pipeline] ABORTING -- run_setup_serializer exited $rc."
    exit 2
fi

# ── [6/6] Prove, then verify ─────────────────────────────────────────────────
banner "[6/6] Proof generation (run_prover_raw) -- $APP_NAME"
"$BIN/run_prover_raw" "$OUT/zekra.arith" "$OUT/proving_key_raw.bin" \
                       "$OUT/circuit_metadata.bin" "$OUT/zekra_Sample_Run1.in" "$OUT/"
rc=$?
if [ $rc -ne 0 ]; then
    echo "[run_pipeline] ABORTING -- run_prover_raw exited $rc (witness likely failed"
    echo "  the constraint-satisfaction check -- see \"Constraints satisfied:\" above)."
    exit 2
fi

banner "Verification (run_verifier_only) -- $APP_NAME"
"$BIN/run_verifier_only" gg "$OUT/verification_key.bin" "$OUT/primary_input.bin" "$OUT/proof.bin"
rc=$?

banner "RESULT -- $APP_NAME"
case $rc in
    0) echo "[run_pipeline] PASS -- proof generated and ACCEPTED for $APP_NAME."; exit 0 ;;
    1) echo "[run_pipeline] FAIL -- proof generated but REJECTED for $APP_NAME."; exit 1 ;;
    *) echo "[run_pipeline] ERROR -- run_verifier_only exited $rc (unexpected)."; exit 2 ;;
esac
