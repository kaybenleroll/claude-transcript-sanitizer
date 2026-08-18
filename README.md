# transcript-sanitizer

Credential redaction for Claude Code session transcripts
(`~/.claude/projects/**/*.jsonl`), per the plan at
`~/.claude/plans/quirky-exploring-map.md`.

## Implemented

**§1-§3 (scaffold, recognizers, jsonl sanitizer):**

- `pyproject.toml` / `uv.lock` — `requires-python = ">=3.12,<3.13"`.
- `mise.toml` — pins `python = "3.12"`, `gitleaks = "8.30.1"` for this directory.
- `sanitize/recognizers.py` — credential recognizers (Anthropic, OpenRouter,
  GitHub OAuth, GCP, Groq, private-key block, AWS, Stripe, Azure AD client
  secret, env-assignment), the placeholder allow-list, and an entropy floor.
- `sanitize/engine.py` — `AnalyzerEngine` (`NoOpNlpEngine`,
  `supported_languages=["en"]`) + `AnonymizerEngine`, narrow/broad profile
  selection, `replace`-with-fixed-literal operator.
- `sanitize/jsonl.py` — line-count-preserving jsonl sanitizer: recursive
  JSON-path walk, `.tmp` + re-parse + `os.replace`, malformed non-final
  line raises, a truncated final line is omitted under
  `tolerate_trailing_partial=True`, keep-list of structural keys,
  write-target refusal under `~/.claude/projects/`, entity-type-counts-only
  redaction log.

**§4-§6 (mirror, gitleaks gate, ledger/cache) — added in this phase:**

- `sanitize/mirror.py` — `build_mirror()`: snapshots the source file list +
  mtimes at run start, redacts every `*.jsonl` into the mirror
  (`tolerate_trailing_partial=True` uniformly — a documented judgment call,
  see inline comment), snapshots again at run end, and exposes
  `unchanged_relpaths()` (mtime+size identical pre/post) for the
  determinism/mtime-unchanged assertions. Also `redact_check()` (dry-run,
  writes nothing) and `hash_files()` (per-file sha256 for the determinism
  comparison across two runs, since the mirror destination is overwritten
  in place each run).
- `bin/build-mirror.sh` / `bin/redact-check.sh` / `bin/gitleaks-baseline.sh`
  / `bin/gitleaks-gate.sh <target-dir>` — real implementations.
- `sanitize/ledger.py` — append-only override ledger
  (`~/.local/state/claude-transcript-sanitizer/overrides.jsonl`),
  **last-entry-wins per `content_hash`** (not `deny > allow`), `flag()` /
  `unflag()`. `bin/flag.sh` / `bin/unflag.sh` wire `just flag` / `just
  unflag` (positional args only).
- `sanitize/cache.py` — single-file classification cache
  (`~/.local/state/claude-transcript-sanitizer/classification-cache.jsonl`),
  post-redaction-bytes hash → `CLEARED`/`FLAGGED`. Not wired to anything
  yet (§7 will use it).
- `tests/` — 35 pytest cases (up from 15), including ledger/cache coverage
  and the flag→unflag round-trip test that exercises the exact bug
  last-entry-wins was designed to fix.

**§7 (classifier sample) — added in this phase:**

- `sanitize/classify.py` — measurement-only classifier sample dispatch.
  Sample selection scans the SOURCE tree (`~/.claude/projects`, not the
  already-redacted mirror — grepping the mirror for credential prefixes
  finds nothing post-redaction) for files matching known fixed-prefix
  credential shapes (`sk-ant-`, `sk-or-`, `gho_`/`ghp_`/`ghs_`/`ghu_`/`ghr_`,
  `gsk_`, `AKIA`/`ASIA`, `AIza`, `sk_`/`rk_` test|live|prod), then classifies
  the corresponding MIRROR (post-redaction) file at each matched relpath,
  plus a random ~10-file contrast sample (fixed seed, default 0, for
  reproducibility across runs — see gate-6 note below). For each sampled
  file: hashes every post-redaction line (`sanitize.cache.hash_content`),
  skips lines already in the classification cache, packs cache-miss lines
  into ≤200KB chunks split on line boundaries (never mid-line; a single
  line over 200KB is `OVERSIZED_LINE` and excluded, not truncated), and
  dispatches one `claude -p --model claude-sonnet-5
  --no-session-persistence` call per chunk with the pre-commit hook's
  system prompt lifted verbatim. `--no-session-persistence` support is
  confirmed via `claude --help` before any dispatch; refuses to run
  otherwise. `timeout 120` per call, up to 3 attempts with jittered
  backoff on timeout/nonzero-exit/malformed-output; a still-failing chunk
  after 3 attempts is a deferral (no cache write for its lines) but its
  timeout/failure events, including elapsed time, are still recorded in
  the metrics — a timeout is a latency observation, not a silent skip.
  Every line in a given chunk gets that chunk's own `CLEARED`/`FLAGGED`
  verdict written to the cache; a file's reported `file_flagged` is a
  reporting-only OR-rollup over its chunks' verdicts (chunk-scoped cache
  writes, file-scoped reporting — the plan's "any chunk flagging marks the
  whole file FLAGGED" is a verdict-reporting statement, not an instruction
  to backfill every other chunk's lines as FLAGGED too). This is
  measurement-only: nothing here reads the cache or ledger to filter or
  gate the mirror, gitleaks gate, or a future sync — §3/§4/§5/§8 are
  untouched.
- `bin/classify-sample.sh` — real implementation; refuses to run if the
  mirror doesn't exist (`just build-mirror` first).
- `tests/test_classify.py` — 24 new pytest cases: chunking (line-boundary
  splitting, byte-limit boundary, oversized-line exclusion), sample
  selection (credential-prefix detection with no bare-substring false
  positives, contrast-set exclusion, source/mirror relpath intersection),
  cache-miss filtering, and dispatch retry/backoff/deferral logic — all
  against a mocked `claude -p` caller, never a real subprocess call.
- `tests/` — 59 pytest cases total (up from 35).

**§8 (local sync dry run) — added this phase:**

- `bin/sync-local.sh` — real implementation. Sequences three
  `claude-code-sync` (v0.3.3) invocations against a throwaway repo/config
  under `.scratch/` (never `~/.claude-code-sync-repo`, never a remote):
  `init --config <init.toml>` (non-interactive, writes `state.json` +
  `config.toml`), a Python patch of `max_file_size_bytes` into the
  just-written `config.toml` (not an `init.toml`/`InitConfig` field —
  unknown keys are silently ignored, so it can only be set this way, and
  only *between* init and push since `push` alone runs onboarding-and-push
  in one process with no gap to patch in between), then `push` (no
  `remote_url` ever configured; `CLAUDE_CODE_SYNC_CLAUDE_DIR` points at the
  mirror's *parent* directory, since the tool appends `projects/` itself).
  Runs three checks, all dynamically measured (no hardcoded corpus
  counts): a session-count guard (mirror `.jsonl` count minus oversize
  files minus the tool's own `log::warn` parse-drops, all measured at run
  time), a staged-vs-reported guard (committed `.jsonl` count vs the
  tool's discovered-session count, catching a `.gitignore`-silent-drop),
  and gitleaks over the **committed, re-serialized** tree (the real
  acceptance gate — stricter than gate 4, which only checks the mirror
  input).

## Real-corpus results (2026-08-18)

- **Gitleaks baseline** (raw corpus, measurement only): 254 findings (was
  246 at plan-writing time — the +8 drift is fully attributable to this
  session's own live transcript picking up fixture credential shapes read
  during earlier testing, not corpus rot), 114 in `.jsonl` across 24 files.
- **100-file Presidio timing**: 7.2 s / 100 files (9.2 MB) → extrapolated
  ~10-20 min for the full ~1.5 GB / 8,750-file corpus. Actual full
  `build-mirror` wall-clock: **19m33s** (first run). Well under the plan's
  30-minute revisit threshold.
- **Gate 4 (gitleaks over the sanitized mirror): PASS — 0 findings, exit
  0.** Went 34 → 3 → 1 → 0 findings across four recognizer-fix iterations
  (see git history for the four real root causes found and fixed: a
  missing `\s` in the env-assignment terminator class, a wrong Azure AD
  secret shape, an under-scoped Stripe token pattern, a placeholder-tag
  self-collision fixed by switching `<TAG>` to `[TAG]`, and — closing the
  last finding — a narrower `PEM_MARKER_LITERAL` recognizer for a
  self-referential PEM-marker mention split across two adjacent JSON
  string leaves in one record, which gitleaks' raw-byte scan matched
  across a JSON leaf boundary that per-leaf redaction couldn't see by
  construction). `just gitleaks-mirror` over the full sanitized mirror
  (8,796 files) completed in 1m6.4s with `no leaks found`. See
  `~/.claude/plans/quirky-exploring-map.md`'s Implementation Notes
  (2026-08-18) for the full root-cause writeup; this paragraph previously
  stated gate 4 did not yet pass cleanly — that was stale as of this
  update.
- **Determinism (step 5)**: two mirror-build runs on identical code,
  compared over the 8,756-file intersection of both runs' unchanged sets —
  **0 mismatches**.
- **§7 classifier sample (2026-08-18)**: 35 files sampled (25
  credential-prefix files found in the source tree + 10 random contrast,
  fixed seed 0) — below the plan's design-time ~50 estimate because the
  precise fixed-prefix regexes used for sample selection are narrower than
  the full gitleaks-baseline detector the plan's ~41 figure came from (see
  `sanitize/classify.py` module docstring). 128 chunks dispatched, **all
  128 succeeded on the first attempt (0 deferred, 0 retries)**. Per-call
  latency: min 3.72s / median 5.21s / max 47.4s. Chunk flag rate: 28/128
  (21.9%); 17 of 35 files had at least one flagged chunk. 2 lines were
  `OVERSIZED_LINE` (excluded from classification, not truncated) in one
  file. Token-volume proxy (chunk byte size, not a real token count):
  ~20.9 MB dispatched across the run. Full metrics:
  `.scratch/classifier-sample-metrics.json`. Verified: a flagged verdict
  landed in the cache (`~/.local/state/claude-transcript-sanitizer/classification-cache.jsonl`,
  2,117 FLAGGED / 7,104 CLEARED lines after this phase's runs); `just flag`
  / `just unflag` round-trip still works; and — **after fixing a
  reproducibility bug** (the CLI's `--seed` defaulted to `None`, so the
  10-file random contrast set changed on every invocation and a "second
  run" wasn't actually re-classifying the same lines — fixed to a fixed
  default seed of 0) — a same-seed repeat run against the now-fully-cached
  35-file sample dispatched **0** classifier calls, confirming gate 6.
- **§8 sync dry run / gate 7 (2026-08-18): PASS.** `just sync-local` over
  the full 8,796-file mirror: `claude-code-sync push` discovered **8,795**
  sessions (one `.jsonl` dropped with a `log::warn` — `.scratch/nudge-events.jsonl`,
  a non-transcript telemetry file that happens to live under a
  `~/.claude/projects/.scratch/` path and doesn't parse as a
  `ConversationSession`; not a mirror bug), committed as 8,795 `.jsonl` +
  1 tool-written `.gitignore` = 8,796 files into a fresh throwaway repo.
  Session-count guard (8,796 mirror − 0 oversize − 1 warn-drop = 8,795)
  and the staged-vs-reported guard (8,795 committed `.jsonl` == 8,795
  discovered) both **PASS**. **Gate 7** — `gitleaks dir` over the
  committed, re-serialized tree — **PASS: 0 findings, exit 0** over 1.52 GB
  in 1m6.9s. Full wall-clock for `just sync-local` (init + push + both
  gates): **~90s**, well under the mirror build's 19.5 min — re-serialization
  is not the bottleneck gate 4 was. Two corrections to the plan found while
  implementing: (1) `push`'s `--push-remote` is a plain `SetTrue` flag in
  v0.3.3 (default `true`, no value accepted) — `--push-remote=false`
  errors (`unexpected value 'false'`); local-only safety instead comes
  from `push_remote && state.has_remote` in `src/sync/push.rs`, and
  `has_remote` is only ever true when `remote_url` was set at init — so
  omitting `remote_url` (not the flag) is what keeps this local-only, and
  the flag is simply never passed. (2) `CLAUDE_CODE_SYNC_CLAUDE_DIR` must
  point at the mirror's **parent** directory, not the mirror's `projects/`
  leaf itself — `claude_projects_dir()` appends `projects` to the override
  unconditionally, so pointing it at `.../sanitized-mirror/projects`
  directly makes the tool look for a nonexistent
  `.../sanitized-mirror/projects/projects/` and silently discover 0
  sessions (a clean-looking, exit-0, vacuous push — exactly the failure
  mode gotcha #4 warned about, just from one directory-nesting level off
  rather than a missing/relative path).

## Running

```
just test              # pytest suite (59 cases)
just redact-check      # dry-run: what would be redacted, writes nothing
just gitleaks-baseline # gitleaks over the RAW corpus (measurement only)
just build-mirror      # full corpus -> .scratch/sanitized-mirror/projects/
just gitleaks-mirror   # gate 4: must exit 0 with zero findings
just classify-sample   # §7: classifier sample dispatch, writes .scratch/classifier-sample-metrics.json
just flag <hash> "<reason>"   # ledger: deny decision
just unflag <hash>            # ledger: allow decision (undoes a flag)
just sync-local         # §8: local-only claude-code-sync dry run, gate 7 (gitleaks on the committed tree)
just --list             # all recipes
```
