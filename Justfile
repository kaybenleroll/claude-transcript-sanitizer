# Transcript sanitizer task runner
# Run `just` or `just --list` to see available recipes
#
# Plan at ~/.claude/plans/quirky-exploring-map.md.
# §1-§8 implemented (scaffold, recognizers, jsonl sanitizer, mirror,
# gitleaks gate, ledger/cache, classifier sample, local sync dry run).

default:
    @just --list

# ─── Test ─────────────────────────────────────────────────────────────────────

# Run the pytest suite
test:
    bash bin/test.sh

# ─── Redaction ────────────────────────────────────────────────────────────────

# Report files/lines a redaction pass would change (dry-run, writes nothing)
redact-check:
    bash bin/redact-check.sh

# TODO: phase 3 — redact the full corpus into the sanitized mirror (superseded by build-mirror)
redact-all:
    @echo "not implemented — superseded by 'just build-mirror' (plan §4)"

# ─── Mirror & Gate ────────────────────────────────────────────────────────────

# gitleaks over the RAW corpus (measurement only, exit-code 0) — confirms/updates baseline numbers
gitleaks-baseline:
    bash bin/gitleaks-baseline.sh

# Build .scratch/sanitized-mirror/projects/ from ~/.claude/projects/ (plan §4)
build-mirror:
    bash bin/build-mirror.sh

# gitleaks over the sanitized mirror — must exit 0 with zero findings (plan §5)
gitleaks-mirror:
    bash bin/gitleaks-gate.sh ../../.scratch/sanitized-mirror/projects

# ─── Classification & Ledger ──────────────────────────────────────────────────

# Claude classifier sample dispatch + latency metrics (plan §7, measurement-only)
classify-sample:
    bash bin/classify-sample.sh

# Append a manual ledger override (deny decision) — usage: just flag <content_hash> "<reason>"
flag hash reason:
    bash bin/flag.sh {{hash}} {{reason}}

# Append a manual ledger override (allow decision, undoes a prior flag) — usage: just unflag <content_hash>
unflag hash:
    bash bin/unflag.sh {{hash}}

# ─── Sync ─────────────────────────────────────────────────────────────────────

# Local-only claude-code-sync dry run against the mirror — commits into a throwaway repo, never a remote (plan §8)
sync-local:
    bash bin/sync-local.sh
