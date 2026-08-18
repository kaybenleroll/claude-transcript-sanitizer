#!/usr/bin/env bash
# Plan §7: classifier sample dispatch (measurement-only). Samples files from
# the sanitized mirror (credential-prefix files + random contrast), filters
# cache-miss lines, chunks to <=200KB on line boundaries, dispatches one
# `claude -p` call per chunk, writes latency/flag-rate metrics.
#
# Does NOT build the mirror -- the mirror must already exist
# (.scratch/sanitized-mirror/projects/), built via `just build-mirror`.
set -euo pipefail
cd "$(dirname "$0")/.."

REPO_ROOT="$(cd ../.. && pwd)"
MIRROR="${MIRROR_DEST:-$REPO_ROOT/.scratch/sanitized-mirror/projects}"
OUT="${CLASSIFY_METRICS_OUT:-$REPO_ROOT/.scratch/classifier-sample-metrics.json}"

if [ ! -d "$MIRROR" ]; then
  echo "ERROR: mirror not found at $MIRROR -- run 'just build-mirror' first." >&2
  exit 1
fi

uv run python3 -m sanitize.classify --mirror "$MIRROR" --out "$OUT"
