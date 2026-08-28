"""Classifier sample dispatch. Plan §7:

Measurement-only. Samples files from the sanitized mirror (all files where a
known credential prefix fired in the SOURCE corpus, plus a random ~10 for
contrast), filters out lines already in the classification cache
(sanitize/cache.py), chunks cache-miss lines into <=200KB chunks split on
line boundaries, dispatches one `claude -p` subprocess call per chunk with
the pre-commit hook's system prompt lifted verbatim, and writes per-call
latency / flag-rate / chunk-count metrics to a JSON file.

Nothing here reads the ledger or the cache to filter/gate anything else —
per plan §7, "classification is measurement-only" in this slice. §3/§4/§5/§8
are untouched.

Judgment call on sample selection (documented, not silently decided): the
mirror is *already* redacted, so grepping the mirror itself for credential
prefixes (e.g. `sk-ant-`) finds nothing -- redaction already replaced them
with `[ENTITY_TYPE]` placeholders (verified: 0 hits with precise prefix
regexes over the mirror, vs 25 over the source tree with the same regexes).
"Files containing known credential prefixes" therefore has to mean: scan
the SOURCE tree (~/.claude/projects) to find which relpaths had a
credential fire, then classify the corresponding MIRROR (post-redaction)
file at that relpath -- consistent with plan §7's own framing, "these are
the files where redaction actually fired, so they are the ones worth
classifying", and with §6's invariant that classification hashes are over
post-redaction bytes. The plan's design-time count was ~41 (from the
gitleaks baseline, a broader detector than these precise prefix regexes);
this session's own precise-prefix scan over the current (drifted) corpus
found 25 -- both are "some initial pass over the corpus", the exact number
depends on which detector and corpus snapshot, and is not on its own
evidence of a bug.

Judgment call on the "chunk flagging marks the whole file FLAGGED" line
(plan §7): re-read in context, this is scoped to "as a verdict" -- i.e. the
FILE-level FLAGGED/CLEARED summary reported in the metrics is derived by
OR-ing over its chunks' verdicts. Cache writes stay chunk-scoped: every
line in a given chunk gets that chunk's own verdict written to its
line-hash key (§6: "line hash -> CLEARED|FLAGGED"), not every line in the
whole file. A file with an early flagged chunk and later clean chunks does
not retroactively mark the later chunks' (unrelated) lines FLAGGED in the
cache; the file-level FLAGGED is a reporting rollup only.

Issue #12: only CLEARED verdicts are ever written to the cache. A FLAGGED
chunk's lines are never cache-written -- a flagged line is always
re-dispatched to the classifier on every future run until it clears or is
otherwise handled (e.g. via the ledger). Caching FLAGGED is the corpus-wide
poisoning channel: an unrelated file sharing that exact line's content
would silently inherit the stale FLAGGED verdict the moment any consumer
starts reading the cache to gate/filter. CLEARED-cache-sharing across
unrelated files is fine and intended -- corpus-wide dedup is the point.
"""

from __future__ import annotations

import json
import random
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from sanitize.cache import DEFAULT_CACHE_PATH, get as cache_get, hash_content, put as cache_put
from sanitize.recognizers import CREDENTIAL_PREFIX_PATTERNS

# ---------------------------------------------------------------------------
# System prompt — lifted VERBATIM from ~/.claude-code-sync-repo/.git/hooks/
# pre-commit (the SYSTEM_PROMPT= line), per plan §7. Do not paraphrase.
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = (
    'You are a pre-commit privacy/business-sensitivity reviewer for a personal '
    'Claude Code transcript backup being synced to a private git repo. You will '
    'be shown extracted conversation TEXT from one session. Flag ONLY genuine '
    'business-sensitive content: real client/company names tied to confidential '
    'work, specific financial figures tied to a real deal or client, PII (real '
    'names plus identifying details of real people, not fictional/example '
    'data), or anything a reasonable person would not want stored in a '
    'private-but-third-party-hosted git repo. Do NOT flag: generic '
    'technical/engineering discussion, code, public knowledge, the repo owners '
    'own name or email, example/placeholder/test/seed data, ordinary software '
    'engineering content. Respond with ONLY a JSON object, no other text, no '
    'markdown fences: {"flagged": true or false, "reason": "<one sentence, do '
    'not quote any secret or sensitive value verbatim>"}'
)

MAX_CHUNK_BYTES = 200_000
CALL_TIMEOUT_SECONDS = 120
MAX_ATTEMPTS = 3

# Precise credential-prefix regex, built from the SAME PatternRecognizer
# objects sanitize/recognizers.py registers with Presidio (not a hand-copy --
# plan P0.2: the old verbatim copy here is how the \b-anchoring fix could
# have landed in only one of the two call sites; not bare substring matching,
# a bare `AKIA` or `gsk_` substring search over-matches badly; verified
# against the real corpus, see module docstring).
CREDENTIAL_PREFIX_RE = re.compile(
    "|".join(f"(?:{p})" for p in CREDENTIAL_PREFIX_PATTERNS)
)


class NoSessionPersistenceUnsupportedError(RuntimeError):
    """Raised when `claude --help` does not confirm --no-session-persistence
    support. Plan §7: refuse to dispatch rather than risk writing transcripts
    for the classification calls that sanitize transcripts."""


def assert_no_session_persistence_supported(claude_bin: str = "claude") -> None:
    result = subprocess.run(
        [claude_bin, "--help"], capture_output=True, text=True, timeout=30
    )
    if "--no-session-persistence" not in result.stdout:
        raise NoSessionPersistenceUnsupportedError(
            f"`{claude_bin} --help` does not advertise --no-session-persistence; "
            "refusing to dispatch classifier calls."
        )


# ---------------------------------------------------------------------------
# Sample selection
# ---------------------------------------------------------------------------

def find_credential_relpaths(source_root: Path) -> set[str]:
    """relpaths (relative to source_root) of *.jsonl files whose SOURCE bytes
    contain a known credential-prefix match. Scanned against source, not the
    (already-redacted) mirror -- see module docstring."""
    out: set[str] = set()
    for p in sorted(source_root.rglob("*.jsonl")):
        if not p.is_file():
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if CREDENTIAL_PREFIX_RE.search(text):
            out.add(str(p.relative_to(source_root)))
    return out


def pick_contrast_relpaths(
    mirror_root: Path, exclude: set[str], n: int, rng: random.Random
) -> list[str]:
    """n random *.jsonl relpaths from the mirror, excluding `exclude`."""
    candidates = [
        str(p.relative_to(mirror_root))
        for p in mirror_root.rglob("*.jsonl")
        if p.is_file() and str(p.relative_to(mirror_root)) not in exclude
    ]
    rng.shuffle(candidates)
    return sorted(candidates[:n])


@dataclass
class SampleSelection:
    credential_relpaths: list[str]
    contrast_relpaths: list[str]

    @property
    def all_relpaths(self) -> list[str]:
        return sorted(set(self.credential_relpaths) | set(self.contrast_relpaths))


def select_sample(
    source_root: Path,
    mirror_root: Path,
    contrast_n: int = 10,
    seed: int | None = None,
) -> SampleSelection:
    """Only relpaths that exist in BOTH source and mirror are eligible for
    the credential set -- a file present in the source scan but not (yet, or
    any longer) in the mirror can't be classified."""
    rng = random.Random(seed)
    credential = find_credential_relpaths(source_root)
    mirror_relpaths = {str(p.relative_to(mirror_root)) for p in mirror_root.rglob("*.jsonl") if p.is_file()}
    credential_in_mirror = sorted(credential & mirror_relpaths)
    contrast = pick_contrast_relpaths(mirror_root, set(credential_in_mirror), contrast_n, rng)
    return SampleSelection(credential_relpaths=credential_in_mirror, contrast_relpaths=contrast)


# ---------------------------------------------------------------------------
# Line extraction + chunking
# ---------------------------------------------------------------------------

def read_lines_bytes(path: Path) -> list[bytes]:
    """Post-redaction line bytes of a mirror file, one entry per jsonl line
    (no trailing newline in each entry, blank lines dropped)."""
    raw = path.read_bytes()
    lines = raw.split(b"\n")
    return [line for line in lines if line != b""]


@dataclass
class ChunkResult:
    chunks: list[list[bytes]] = field(default_factory=list)
    oversized_lines: list[bytes] = field(default_factory=list)


def chunk_lines(lines: list[bytes], max_bytes: int = MAX_CHUNK_BYTES) -> ChunkResult:
    """Pack `lines` into chunks of <= max_bytes, split only on line
    boundaries (a chunk is a list of whole lines, joined with b"\\n" at
    dispatch time). A single line whose own length exceeds max_bytes is
    excluded and reported separately as OVERSIZED_LINE -- never split
    mid-line, never truncated (plan §7 explicitly drops the old hook's
    `head -c 200000` truncation as a fail-open hole)."""
    result = ChunkResult()
    current: list[bytes] = []
    current_size = 0

    def flush():
        nonlocal current, current_size
        if current:
            result.chunks.append(current)
        current = []
        current_size = 0

    for line in lines:
        line_size = len(line)
        if line_size > max_bytes:
            result.oversized_lines.append(line)
            continue
        # +1 for the joining newline, except for the first line in a chunk.
        added = line_size if current_size == 0 else line_size + 1
        if current_size + added > max_bytes and current:
            flush()
            added = line_size
        current.append(line)
        current_size += added

    flush()
    return result


def filter_cache_misses(lines: list[bytes], cache_path: Path) -> tuple[list[bytes], list[bytes], int]:
    """Returns (miss_lines, hit_lines, hit_count). A line already present in
    the cache (any verdict) is a hit and is excluded from classification."""
    from sanitize.cache import load_cache

    cache = load_cache(cache_path)
    misses: list[bytes] = []
    hits: list[bytes] = []
    for line in lines:
        h = hash_content(line)
        if h in cache:
            hits.append(line)
        else:
            misses.append(line)
    return misses, hits, len(hits)


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)


class ClaudeCaller:
    """Thin wrapper around the `claude -p` subprocess call, isolated so
    tests can monkeypatch/stub `run` without touching subprocess."""

    def __init__(self, claude_bin: str = "claude", model: str = "claude-sonnet-5"):
        self.claude_bin = claude_bin
        self.model = model

    def run(self, chunk_text: bytes, timeout: int = CALL_TIMEOUT_SECONDS) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                self.claude_bin,
                "-p",
                "--model",
                self.model,
                "--no-session-persistence",
                "--system-prompt",
                SYSTEM_PROMPT,
            ],
            input=chunk_text,
            capture_output=True,
            timeout=timeout,
        )


@dataclass
class DispatchOutcome:
    status: str  # "ok" | "deferred"
    flagged: bool | None = None
    reason: str | None = None
    elapsed_seconds: float = 0.0
    attempts: int = 0
    events: list[dict] = field(default_factory=list)  # one per attempt, for metrics


def _parse_verdict(stdout: bytes) -> dict | None:
    try:
        text = stdout.decode("utf-8", errors="replace")
    except Exception:
        return None
    m = JSON_OBJECT_RE.search(text)
    if not m:
        return None
    try:
        obj = json.loads(m.group(0))
    except json.JSONDecodeError:
        return None
    if not isinstance(obj.get("flagged"), bool):
        return None
    return obj


def dispatch_chunk(
    caller: ClaudeCaller,
    chunk_lines_: list[bytes],
    *,
    max_attempts: int = MAX_ATTEMPTS,
    timeout: int = CALL_TIMEOUT_SECONDS,
    sleep_fn=time.sleep,
    rng: random.Random | None = None,
) -> DispatchOutcome:
    """One chunk -> one classification verdict, with jittered-backoff retry
    up to `max_attempts`. A timeout counts as an attempt AND is recorded as
    a latency observation at the timeout ceiling (plan §7: "a timeout is a
    latency observation, not a pure deferral") -- never as a silent skip."""
    rng = rng or random.Random()
    chunk_text = b"\n".join(chunk_lines_)
    outcome = DispatchOutcome(status="deferred")

    for attempt in range(1, max_attempts + 1):
        outcome.attempts = attempt
        start = time.monotonic()
        try:
            proc = caller.run(chunk_text, timeout=timeout)
            elapsed = time.monotonic() - start
        except subprocess.TimeoutExpired:
            elapsed = time.monotonic() - start
            outcome.events.append({"attempt": attempt, "outcome": "timeout", "elapsed_seconds": elapsed})
            if attempt < max_attempts:
                sleep_fn(rng.uniform(0.5, 2.0) * attempt)
                continue
            outcome.status = "deferred"
            outcome.elapsed_seconds = elapsed
            return outcome

        if proc.returncode != 0:
            outcome.events.append(
                {"attempt": attempt, "outcome": "nonzero_exit", "elapsed_seconds": elapsed, "returncode": proc.returncode}
            )
            if attempt < max_attempts:
                sleep_fn(rng.uniform(0.5, 2.0) * attempt)
                continue
            outcome.status = "deferred"
            outcome.elapsed_seconds = elapsed
            return outcome

        verdict = _parse_verdict(proc.stdout)
        if verdict is None:
            outcome.events.append({"attempt": attempt, "outcome": "malformed_output", "elapsed_seconds": elapsed})
            if attempt < max_attempts:
                sleep_fn(rng.uniform(0.5, 2.0) * attempt)
                continue
            outcome.status = "deferred"
            outcome.elapsed_seconds = elapsed
            return outcome

        outcome.status = "ok"
        outcome.flagged = verdict["flagged"]
        outcome.reason = verdict.get("reason", "")
        outcome.elapsed_seconds = elapsed
        outcome.events.append({"attempt": attempt, "outcome": "ok", "elapsed_seconds": elapsed})
        return outcome

    return outcome  # pragma: no cover — loop always returns above


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

@dataclass
class FileClassificationResult:
    relpath: str
    total_lines: int
    cache_hit_lines: int
    cache_miss_lines: int
    chunks: int
    oversized_lines: int
    file_flagged: bool
    deferred_chunks: int


def classify_file(
    relpath: str,
    mirror_root: Path,
    cache_path: Path,
    caller: ClaudeCaller,
    call_events: list[dict],
) -> FileClassificationResult:
    path = mirror_root / relpath
    lines = read_lines_bytes(path)
    misses, hits, hit_count = filter_cache_misses(lines, cache_path)
    chunk_result = chunk_lines(misses)

    file_flagged = False
    deferred_chunks = 0

    for chunk in chunk_result.chunks:
        outcome = dispatch_chunk(caller, chunk)
        call_events.append(
            {
                "relpath": relpath,
                "status": outcome.status,
                "flagged": outcome.flagged,
                "attempts": outcome.attempts,
                "elapsed_seconds": outcome.elapsed_seconds,
                "chunk_bytes": sum(len(l) for l in chunk) + max(0, len(chunk) - 1),
                "chunk_lines": len(chunk),
                "events": outcome.events,
            }
        )
        if outcome.status == "deferred":
            deferred_chunks += 1
            continue  # CLASSIFIER_UNAVAILABLE: no cache write for this chunk's lines
        if outcome.flagged:
            file_flagged = True
            # Never cache a FLAGGED verdict (issue #12): a flagged line must
            # always be re-dispatched to the classifier on every future run
            # until it clears or is otherwise handled (e.g. via the ledger).
            # Caching FLAGGED is the corpus-wide poisoning channel -- an
            # unrelated file sharing this exact line's content would
            # silently inherit the stale verdict from the cache. CLEARED
            # verdicts are still cached chunk-wide -- that sharing is the
            # intended corpus-wide dedup behavior.
            continue
        for line in chunk:
            cache_put(cache_path, hash_content(line), "CLEARED")

    return FileClassificationResult(
        relpath=relpath,
        total_lines=len(lines),
        cache_hit_lines=hit_count,
        cache_miss_lines=len(misses),
        chunks=len(chunk_result.chunks),
        oversized_lines=len(chunk_result.oversized_lines),
        file_flagged=file_flagged,
        deferred_chunks=deferred_chunks,
    )


def _percentile_stats(values: list[float]) -> dict:
    if not values:
        return {"min": None, "median": None, "max": None}
    s = sorted(values)
    n = len(s)
    mid = n // 2
    median = s[mid] if n % 2 == 1 else (s[mid - 1] + s[mid]) / 2
    return {"min": s[0], "median": median, "max": s[-1]}


def run_classify_sample(
    source_root: Path,
    mirror_root: Path,
    cache_path: Path = DEFAULT_CACHE_PATH,
    contrast_n: int = 10,
    seed: int | None = None,
    claude_bin: str = "claude",
    model: str = "claude-sonnet-5",
) -> dict:
    assert_no_session_persistence_supported(claude_bin)

    selection = select_sample(source_root, mirror_root, contrast_n=contrast_n, seed=seed)
    caller = ClaudeCaller(claude_bin=claude_bin, model=model)

    call_events: list[dict] = []
    file_results: list[FileClassificationResult] = []
    for relpath in selection.all_relpaths:
        file_results.append(classify_file(relpath, mirror_root, cache_path, caller, call_events))

    ok_latencies = [e["elapsed_seconds"] for e in call_events if e["status"] == "ok"]
    all_latencies = [e["elapsed_seconds"] for e in call_events]  # includes deferred/timeout, per plan §7
    dispatched = len(call_events)
    flagged_chunks = sum(1 for e in call_events if e.get("flagged") is True)
    deferred_events = [e for e in call_events if e["status"] == "deferred"]
    approx_bytes_dispatched = sum(e["chunk_bytes"] for e in call_events)

    metrics = {
        "sample": {
            "credential_relpaths": selection.credential_relpaths,
            "contrast_relpaths": selection.contrast_relpaths,
            "total_files": len(selection.all_relpaths),
        },
        "files": [
            {
                "relpath": r.relpath,
                "total_lines": r.total_lines,
                "cache_hit_lines": r.cache_hit_lines,
                "cache_miss_lines": r.cache_miss_lines,
                "chunks": r.chunks,
                "oversized_lines": r.oversized_lines,
                "file_flagged": r.file_flagged,
                "deferred_chunks": r.deferred_chunks,
            }
            for r in file_results
        ],
        "calls": {
            "dispatched": dispatched,
            "ok": len(ok_latencies),
            "deferred": len(deferred_events),
            "latency_seconds_ok": _percentile_stats(ok_latencies),
            "latency_seconds_all": _percentile_stats(all_latencies),
        },
        "flag_rate": {
            "chunks_flagged": flagged_chunks,
            "chunks_dispatched_ok": len(ok_latencies),
            "fraction": (flagged_chunks / len(ok_latencies)) if ok_latencies else None,
            "files_flagged": sum(1 for r in file_results if r.file_flagged),
        },
        "oversized_lines_total": sum(r.oversized_lines for r in file_results),
        "token_volume_proxy": {
            "note": "approximate: sum of dispatched chunk byte sizes, not a real token count",
            "total_bytes_dispatched": approx_bytes_dispatched,
        },
        "call_events": call_events,
    }
    return metrics


def _main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Plan §7 classifier sample dispatch (measurement-only).")
    parser.add_argument("--source", type=Path, default=Path.home() / ".claude" / "projects")
    parser.add_argument("--mirror", type=Path, required=True)
    parser.add_argument("--cache-path", type=Path, default=DEFAULT_CACHE_PATH)
    parser.add_argument("--contrast-n", type=int, default=10)
    # Fixed default seed (not None) — the contrast set must be reproducible
    # across repeat invocations for the cache to actually short-circuit on a
    # second run (plan §Verification gate 6: "a second run makes ZERO
    # classifier calls for cached lines"). A None/random seed re-picks a
    # different 10-file contrast set each run, so lines that were never
    # classified before look like fresh cache misses even though the
    # cache is working correctly -- this was caught by actually running
    # the gate 6 check twice, not by inspection.
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--claude-bin", type=str, default="claude")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    metrics = run_classify_sample(
        args.source,
        args.mirror,
        cache_path=args.cache_path,
        contrast_n=args.contrast_n,
        seed=args.seed,
        claude_bin=args.claude_bin,
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(f"files_sampled={metrics['sample']['total_files']}")
    print(f"calls_dispatched={metrics['calls']['dispatched']}")
    print(f"calls_deferred={metrics['calls']['deferred']}")
    print(f"flag_fraction={metrics['flag_rate']['fraction']}")
    print(f"out={args.out}")


if __name__ == "__main__":
    _main()
