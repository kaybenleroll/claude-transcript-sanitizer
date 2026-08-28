#!/usr/bin/env bash
# Plan §4: mirror ~/.claude/projects/**/*.jsonl -> .scratch/sanitized-mirror/projects/**,
# sanitizing in flight. Never touches the source tree.
set -euo pipefail
cd "$(dirname "$0")/.."

REPO_ROOT="$(pwd)"
DEST="${MIRROR_DEST:-$REPO_ROOT/.scratch/sanitized-mirror/projects}"
RUN_DIR="${MIRROR_RUN_DIR:-$REPO_ROOT/.scratch/mirror-runs}"

mkdir -p "$DEST" "$RUN_DIR"

mise exec -- uv run python3 -m sanitize.mirror build --dest "$DEST" --run-dir "$RUN_DIR"
