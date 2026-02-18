#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

MODE="${MODE:-bench}"              # bench | trace | both
FOLDING="${FOLDING:-8}"
LOG_TRACE_HEIGHTS="${LOG_TRACE_HEIGHTS:-17}"
THREADS="${THREADS:-16}"
BLOWUP="${BLOWUP:-8}"
QUERIES="${QUERIES:-32}"
GRINDING="${GRINDING:-16}"
REBUILD="${REBUILD:-1}"

usage() {
  cat <<'EOF'
Usage: run_winterfell_benchmarks.sh [options]

Options:
  --mode bench|trace|both        What to run (default: bench)
  --folding N                    Folding factor (2,4,8,16)
  --log-trace H[,H...]           Log2 trace heights (e.g. 17 or 16,17,18)
  --threads N                    Rayon threads (default: 16)
  --blowup N                     Blowup factor (default: 8)
  --queries N                    Number of queries (default: 32)
  --grinding N                   Grinding bits (default: 16)
  --no-rebuild                   Skip clean rebuild (default: rebuild)
  -h, --help                     Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    --folding) FOLDING="$2"; shift 2 ;;
    --log-trace) LOG_TRACE_HEIGHTS="$2"; shift 2 ;;
    --threads) THREADS="$2"; shift 2 ;;
    --blowup) BLOWUP="$2"; shift 2 ;;
    --queries) QUERIES="$2"; shift 2 ;;
    --grinding) GRINDING="$2"; shift 2 ;;
    --no-rebuild) REBUILD=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

maybe_clean() {
  if [[ "${REBUILD}" == "1" ]]; then
    (
      cd "${ROOT}"
      cargo clean -p examples
    )
  fi
}

run_winterfell_bench() {
  echo "== Winterfell bench (fold=${FOLDING}, log-trace=${LOG_TRACE_HEIGHTS}) =="
  maybe_clean
  (
    cd "${ROOT}"
    WINTERFELL_LOG_TRACE_HEIGHTS="${LOG_TRACE_HEIGHTS}" \
    WINTERFELL_FOLDING="${FOLDING}" \
    WINTERFELL_BLOWUP="${BLOWUP}" \
    WINTERFELL_QUERIES="${QUERIES}" \
    WINTERFELL_GRINDING="${GRINDING}" \
    RAYON_NUM_THREADS="${THREADS}" \
    cargo bench -p examples --bench mock72_opening --features concurrent
  )
}

run_winterfell_trace() {
  echo "== Winterfell forest log (fold=${FOLDING}, log-trace=${LOG_TRACE_HEIGHTS}) =="
  maybe_clean
  IFS=',' read -r -a LOGS <<< "${LOG_TRACE_HEIGHTS}"
  for log_h in "${LOGS[@]}"; do
    local trace_len=$((1 << log_h))
    (
      cd "${ROOT}"
      WINTER_LOG=info RAYON_NUM_THREADS="${THREADS}" \
      cargo run -p examples --release --bin winterfell --features "concurrent tracing-forest" -- \
        --hash_fn poseidon2 --field_extension 2 \
        --folding "${FOLDING}" --blowup "${BLOWUP}" --queries "${QUERIES}" \
        mock72 -n "${trace_len}"
    )
  done
}

case "${MODE}" in
  bench) run_winterfell_bench ;;
  trace) run_winterfell_trace ;;
  both)  run_winterfell_bench; run_winterfell_trace ;;
  *) echo "Invalid mode: ${MODE}" >&2; usage; exit 1 ;;
esac
