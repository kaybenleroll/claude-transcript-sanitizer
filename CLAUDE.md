# claude-transcript-sanitizer

Credential and PII redaction for Claude Code session transcripts
(`~/.claude/projects/**/*.jsonl` and their `.txt` sidecars), built to mirror
a sanitized copy of `~/.claude/projects/` for syncing to an external git
repo via `claude-code-sync` without leaking credentials or secrets.

Originally developed as `claude_code_research/artifacts/transcript-sanitizer/`
inside `kaybenleroll/random_llm_projects`; extracted to this standalone repo
(git history preserved via `git filter-repo`) so it can be depended on and
synced independently. See `README.md` for full section-by-section
implementation notes (§1-§9).

## What it does

- **Recognizers** (`sanitize/recognizers.py`) — regex/entropy-based
  detectors for credentials (Anthropic, OpenRouter, GitHub OAuth/PAT, GCP,
  Groq, AWS, Stripe, Azure AD client secret, PEM private-key blocks,
  env-assignment patterns), plus a placeholder allow-list and entropy floor.
- **Redaction engine** (`sanitize/engine.py`) — wraps Presidio
  (`AnalyzerEngine` + `AnonymizerEngine`) with narrow/broad profile
  selection and a fixed-literal replace operator.
- **JSONL sanitizer** (`sanitize/jsonl.py`) — line-count-preserving,
  recursive JSON-path redaction with atomic `.tmp` + `os.replace`, refuses
  to write under `~/.claude/projects/` (source is never touched).
- **Text sidecar sanitizer** (`sanitize/text.py`) — whole-file redaction for
  `.txt` sidecars (written by Claude Code when tool output exceeds an
  internal size threshold), strict UTF-8, oversize cap, anomalous-span
  sanity check.
- **Mirror builder** (`sanitize/mirror.py`, `bin/build-mirror.sh`) — builds
  `.scratch/sanitized-mirror/projects/` from the source tree, dispatching
  `.jsonl`/`.txt` sanitizers, with a hygiene gate (stale-tmp sweep, prune).
- **Gitleaks gate** (`bin/gitleaks-gate.sh`, `.gitleaks.toml`) — the
  acceptance gate: gitleaks must report zero findings against the mirror
  (or a sync target). `.gitleaks.toml` re-anchors gitleaks' own default
  rules to close an escape-residue blind spot gitleaks 8.30.1 has (see the
  file's header comment for the full rationale) — `[extend] useDefault =
  true` adds to, never replaces, gitleaks' built-in ruleset.
- **Recognizer gate** (`bin/recognizer-gate.sh`) — a second, independent
  compensating control: runs this repo's own fixed credential recognizer
  patterns detect-only over a target dir, asserting zero findings. Not a
  redaction pass — catches a stale-recognizer mirror or a silently-skipped
  file that the gitleaks gate alone might miss.
- **Ledger / cache** (`sanitize/ledger.py`, `sanitize/cache.py`) — an
  append-only manual-override ledger (last-entry-wins per content hash,
  `just flag`/`just unflag`) and a classification cache keyed on
  post-redaction content hash.
- **Classifier sample dispatch** (`sanitize/classify.py`,
  `bin/classify-sample.sh`) — measurement-only: samples credential-prefix
  + random-contrast files from the mirror, dispatches `claude -p` calls to
  classify cache-miss chunks as `CLEARED`/`FLAGGED`, records latency/flag
  metrics. Does not gate or filter anything (yet).
- **Local sync dry run** (`bin/sync-local.sh`) — exercises `claude-code-sync`
  init+push against a throwaway repo under `.scratch/` only — never
  `~/.claude-code-sync-repo`, never a remote.

## Working approach

- Run via `just <recipe>` — `just --list` for the full set (`test`,
  `redact-check`, `build-mirror`, `gitleaks-baseline`, `gitleaks-mirror`,
  `classify-sample`, `flag`/`unflag`, `sync-local`).
- All scratch/output state (mirror, run logs, throwaway sync repo) lives
  under `.scratch/` at repo root — `bin/*.sh` scripts resolve `REPO_ROOT` as
  their own repo root (`cd "$(dirname "$0")/.." && REPO_ROOT="$(pwd)"`), not
  a parent monorepo.
- Python deps managed via `uv` (`uv.lock`, `pyproject.toml`,
  `requires-python = ">=3.12,<3.13"`); `mise.toml` pins `python = "3.12"`
  and `gitleaks = "8.30.1"` for this repo.
- Tests: `just test` (`uv run pytest tests/ -v`).
- Never touches `~/.claude/projects/` (source) or a real
  `claude-code-sync` remote — every write target is gated to `.scratch/` or
  Claude Code's own state dir (`~/.local/state/claude-transcript-sanitizer`).
