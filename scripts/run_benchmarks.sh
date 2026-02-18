#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
P3_REPO="${P3_REPO:-/Users/al/Code/zz/p3-miden}"
ARGS=("$@")

usage() {
  cat <<'EOF'
Usage: run_benchmarks.sh [options]

Options:
  --mode bench|trace|both        What to run (default: bench)
  --folding N                    Folding factor (2,4,8,16)
  --log-trace H[,H...]           Log2 trace heights (e.g. 17 or 16,17,18)
  --threads N                    Rayon threads (default: 16)
  --blowup N                     Blowup factor (default: 8)
  --queries N                    Number of queries (default: 32)
  --grinding N                   Grinding bits (default: 16)
  --p3-repo PATH                 Path to p3-miden repo
  -h, --help                     Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --p3-repo) P3_REPO="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) shift ;;
  esac
done

FILTERED_ARGS=()
skip_next=0
for arg in "${ARGS[@]}"; do
  if [[ "${skip_next}" == "1" ]]; then
    skip_next=0
    continue
  fi
  if [[ "${arg}" == "--p3-repo" ]]; then
    skip_next=1
    continue
  fi
  FILTERED_ARGS+=("${arg}")
done

bash "${ROOT}/scripts/run_winterfell_benchmarks.sh" "${FILTERED_ARGS[@]}"
bash "${P3_REPO}/scripts/run_p3_benchmarks.sh" "${FILTERED_ARGS[@]}"
