"""Audit chain walker for `opendevops audit verify` (per-run files).

Pure functions: walk a per-run JSONL chain and recompute every hash. Two independent structural
consistency checks are applied:

- **linkage** — each event's ``prev_hash`` must equal the previous line's ``hash`` (and the
  first must be a ``run_started`` seed linking to ``GENESIS``).
- **recomputation** — each event's stored ``hash`` must equal ``sha256(prev_hash + canonical
  payload)``.

Together these detect any modification, reorder, or deletion of an *interior* line: an
interior deletion breaks linkage for the line that used to follow it, a reorder breaks linkage
at the swap point, a mutated byte breaks recomputation, and an injected/forged line breaks
recomputation unless the attacker also recomputes every following hash (at which point it is a
new, differently-linked chain, not an undetected edit of this one). Corrupted JSON is caught as
a parse failure at that line. Injected or altered *fields within* an existing event are also
caught: an unknown top-level key fails ``AuditEvent`` validation (``extra="forbid"``), and any
change to a known field's value — including inside free-form dicts like ``args`` — breaks hash
recomputation, since the hash covers the full canonical payload.

The CLI additionally requires a terminal ``run_completed`` event, so deletion of that tail fails
verification. ``verify_run_file(..., require_complete=False)`` remains available for diagnosing a
legitimately crashed/in-progress run. A malicious actor able to rewrite the whole file can still
recompute the unkeyed chain; authenticity requires an independently protected/WORM sink or signed
external anchor. The local verifier proves structural consistency and, in strict mode, completion.

``ts`` monotonicity is checked warn-only (clock skew is not tampering). The ``main`` helper is
the entry point the ``audit verify`` CLI subcommand calls.

Merged spool files
------------------
Vector ships every per-run chain into a durable spool, merging many runs into one append-only
day-file (``audit-merged-<date>.jsonl``) where lines from different runs are INTERLEAVED. Such a
file is not a single linear chain, so ``verify_run_file`` (which walks a file as one chain) would
fail at the first foreign line. :func:`verify_merged_file` handles it: it regroups the merged
lines by ``run_id`` and verifies each run's subsequence as an independent chain, reusing the same
:func:`_verify_chain` core (no duplicated hash math). Regrouping is sound because the spool
preserves every line verbatim and never reorders lines *within* a run — each per-run source file
is single-writer (see :class:`~opendevops.audit.logger.AuditLogger`) and Vector's file source
ships in per-file append order, so a run's events keep their original order across the merge. The
:func:`main` CLI auto-detects each ``*.jsonl`` file's shape (a file carrying >1 distinct
``run_id`` is treated as merged), so ``opendevops audit verify --dir <spool>`` works verbatim on
both a per-run audit dir and a merged spool dir with no extra flag.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from opendevops.audit.schema import (
    GENESIS_PREV_HASH,
    AuditEvent,
    EventType,
    compute_event_hash,
)


class VerifyResult(BaseModel):
    """Outcome of verifying one chain file."""

    model_config = ConfigDict(extra="forbid")

    ok: bool
    events: int
    first_bad_line: int | None = None
    reason: str | None = None
    warnings: list[str] = Field(default_factory=list)


class MergedVerifyResult(BaseModel):
    """Outcome of verifying a Vector-MERGED (interleaved multi-run) spool file.

    The file is regrouped by ``run_id`` and each run's subsequence verified as an independent chain
    (:attr:`per_run`, keyed by run_id). :attr:`ok` is ``True`` iff every run's chain verifies AND
    every line parsed. On failure :attr:`bad_run_id` / :attr:`first_bad_line` name the EARLIEST
    break in physical file order (:attr:`reason` echoes that run's reason); a file-level problem
    (unreadable / an unparseable line) sets :attr:`reason` with no :attr:`bad_run_id`.
    """

    model_config = ConfigDict(extra="forbid")

    ok: bool
    runs: int
    events: int
    per_run: dict[str, VerifyResult] = Field(default_factory=dict)
    reason: str | None = None
    bad_run_id: str | None = None
    first_bad_line: int | None = None
    warnings: list[str] = Field(default_factory=list)


def _read_events(path: Path) -> tuple[list[tuple[int, AuditEvent]], VerifyResult | None]:
    """Read + parse every non-blank line of ``path`` into ``(source_line, event)`` pairs.

    Returns ``(events, None)`` when every line parses, or ``(events_so_far, error_result)`` on the
    first read/parse failure (the ``error_result`` carries the 1-based failing line and reason).
    Parsing is intentionally split from chain verification so the merged path can regroup by
    ``run_id`` before verifying, and both paths share :func:`_verify_chain`.
    """
    path = Path(path)
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [], VerifyResult(ok=False, events=0, reason=f"cannot read file: {exc}")

    events: list[tuple[int, AuditEvent]] = []
    for lineno, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            continue  # tolerate stray blank lines (e.g. a final newline split)
        try:
            event = AuditEvent.model_validate(json.loads(line))
        except (ValueError, json.JSONDecodeError) as exc:
            return events, VerifyResult(
                ok=False,
                events=len(events),
                first_bad_line=lineno,
                reason=f"unparseable event: {exc}",
            )
        events.append((lineno, event))
    return events, None


def _verify_chain(
    events: list[tuple[int, AuditEvent]], *, require_complete: bool = False
) -> VerifyResult:
    """Verify an ordered list of ``(source_line, event)`` as ONE hash chain — the shared core.

    Performs the two tamper-evidence checks the module documents (linkage + recomputation), the
    ``run_started`` seed check, and the warn-only ``ts`` monotonicity check, then returns a
    :class:`VerifyResult`. Does NO parsing — callers pre-parse (see :func:`_read_events`). Line
    numbers in the result are the SOURCE line numbers passed in, so a failure always names where in
    the real file the break is: physical lines of the per-run file for :func:`verify_run_file`, or
    physical lines of the merged spool file for :func:`verify_merged_file`. Both the single-chain
    walker and the merged regroup path go through this one function, so the hash math lives here
    exactly once.
    """
    expected_prev = GENESIS_PREV_HASH
    prev_ts: str | None = None
    warnings: list[str] = []
    count = 0

    for lineno, event in events:
        if count == 0 and event.event_type is not EventType.run_started:
            return VerifyResult(
                ok=False,
                events=count,
                first_bad_line=lineno,
                reason="first event is not a run_started seed",
            )

        if event.prev_hash != expected_prev:
            return VerifyResult(
                ok=False,
                events=count,
                first_bad_line=lineno,
                reason="prev_hash does not link to the previous event (reordered/deleted/tampered)",
            )

        if compute_event_hash(event.prev_hash, event) != event.hash:
            return VerifyResult(
                ok=False,
                events=count,
                first_bad_line=lineno,
                reason="hash mismatch (line modified)",
            )

        if prev_ts is not None and event.ts < prev_ts:
            warnings.append(f"line {lineno}: ts regression ({event.ts} < {prev_ts})")

        prev_ts = event.ts
        expected_prev = event.hash
        count += 1

    if count == 0:
        return VerifyResult(ok=False, events=0, reason="empty chain (no events)")
    if require_complete and events[-1][1].event_type is not EventType.run_completed:
        return VerifyResult(
            ok=False,
            events=count,
            first_bad_line=events[-1][0],
            reason="incomplete chain (terminal run_completed event is missing)",
            warnings=warnings,
        )

    return VerifyResult(ok=True, events=count, warnings=warnings)


def verify_run_file(path: Path, *, require_complete: bool = False) -> VerifyResult:
    """Verify one ``<run_id>.jsonl`` chain file (a single linear chain). Line numbers are 1-based.

    Every non-blank line is one event in append order: this parses each line (a parse failure is
    reported at its line) and walks the parsed events as one hash chain via :func:`_verify_chain`.
    For a Vector-MERGED spool file (many interleaved runs in ONE file) use
    :func:`verify_merged_file` instead — this walker treats the whole file as a single chain and
    would fail at the first foreign line.
    """
    events, read_error = _read_events(path)
    if read_error is not None:
        return read_error
    return _verify_chain(events, require_complete=require_complete)


def verify_merged_file(path: Path, *, require_complete: bool = False) -> MergedVerifyResult:
    """Verify a Vector-MERGED spool file (``audit-merged-<date>.jsonl``): the interleaved lines of
    many per-run chains in one append-only file.

    Reads every line, groups them by ``run_id`` preserving file order WITHIN each run, and verifies
    each run's subsequence as an independent hash chain via the same :func:`_verify_chain` the
    per-run walker uses (no duplicated hash math).

    Order assumption (documented): within a single ``run_id`` the merged file preserves the ORIGINAL
    append order. This holds because each per-run source file is single-writer (append-only, one
    live writer per run — see :class:`~opendevops.audit.logger.AuditLogger`) and Vector's file
    source ships lines in per-file append order, so the merge never reorders lines of the same run
    relative to each other. Interleaving of DIFFERENT runs is expected and handled by the grouping.

    Fail-closed: a run whose subsequence does not verify — including a broken INTERIOR chain (a
    dropped/reordered/mutated middle event), not merely an unparseable line — fails the whole
    file, naming the run_id + physical line of the break.
    """
    events, read_error = _read_events(path)
    return _verify_merged(events, read_error, require_complete=require_complete)


def _verify_merged(
    events: list[tuple[int, AuditEvent]],
    read_error: VerifyResult | None,
    *,
    require_complete: bool = False,
) -> MergedVerifyResult:
    """Regroup pre-parsed ``(line, event)`` pairs by ``run_id`` and verify each run's chain.

    Shared core behind :func:`verify_merged_file` and the merged branch of :func:`main`.
    """
    if read_error is not None:
        return MergedVerifyResult(
            ok=False,
            runs=0,
            events=0,
            reason=read_error.reason,
            first_bad_line=read_error.first_bad_line,
        )

    groups: dict[str, list[tuple[int, AuditEvent]]] = {}
    for lineno, event in events:
        groups.setdefault(event.run_id, []).append((lineno, event))
    if not groups:
        return MergedVerifyResult(
            ok=False, runs=0, events=0, reason="empty merged file (no events)"
        )

    per_run = {
        run_id: _verify_chain(evs, require_complete=require_complete)
        for run_id, evs in groups.items()
    }
    total = sum(result.events for result in per_run.values())
    warnings = [f"{run_id}: {w}" for run_id, result in per_run.items() for w in result.warnings]

    failed = [(run_id, result) for run_id, result in per_run.items() if not result.ok]
    if not failed:
        return MergedVerifyResult(
            ok=True, runs=len(groups), events=total, per_run=per_run, warnings=warnings
        )
    # Name the EARLIEST break in physical file order (a None first_bad_line sorts last).
    bad_run_id, bad = min(
        failed,
        key=lambda item: (item[1].first_bad_line is None, item[1].first_bad_line or 0),
    )
    return MergedVerifyResult(
        ok=False,
        runs=len(groups),
        events=total,
        per_run=per_run,
        reason=bad.reason,
        bad_run_id=bad_run_id,
        first_bad_line=bad.first_bad_line,
        warnings=warnings,
    )


def verify_dir(dir: Path) -> dict[str, VerifyResult]:
    """Verify every ``*.jsonl`` chain under ``dir`` as a single per-run chain, keyed by file stem.

    This is the per-run-directory view (one linear chain per file). For a merged spool directory,
    :func:`main` auto-detects interleaved files and routes them to :func:`verify_merged_file`.
    """
    base = Path(dir)
    return {path.stem: verify_run_file(path) for path in sorted(base.glob("*.jsonl"))}


def _is_merged_file(path: Path) -> bool:
    """True if the file interleaves MORE THAN ONE distinct ``run_id`` — a Vector-merged spool file
    (vs a single per-run ``<run_id>.jsonl`` chain).

    Peeks ``run_id`` straight from each line's JSON without full chain validation (a cheap routing
    decision); unparseable lines are skipped here — the verifier the route selects still reports
    them. A file with one run (a per-run chain, or a spool day with a single run) reads as
    non-merged and verifies identically as a single chain.
    """
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError:
        return False
    seen: set[str] = set()
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            run_id = obj.get("run_id")
            if isinstance(run_id, str):
                seen.add(run_id)
                if len(seen) > 1:
                    return True
    return False


def main(dir: Path, *, allow_incomplete: bool = False) -> int:
    """CLI helper for ``opendevops audit verify``: print a summary, return an exit code.

    Auto-detects each ``*.jsonl`` file's shape so ONE command works for both a per-run audit dir
    (``<run_id>.jsonl``, one chain per file) AND a Vector-merged spool dir
    (``audit-merged-<date>.jsonl``, many interleaved runs per file): a file carrying more than one
    distinct ``run_id`` is regrouped and verified per-run via :func:`verify_merged_file`; any other
    file is verified as a single chain via :func:`verify_run_file` (unchanged). Returns 0 iff every
    chain in every file verifies, 1 otherwise.
    """
    base = Path(dir)
    files = sorted(base.glob("*.jsonl"))
    if not files:
        print(f"no audit chain files found under {base}")
        return 0

    all_ok = True
    for path in files:
        if _is_merged_file(path):
            merged = verify_merged_file(path, require_complete=not allow_incomplete)
            if merged.ok:
                suffix = f" ({len(merged.warnings)} warning(s))" if merged.warnings else ""
                print(f"OK   {path.name}: {merged.runs} run(s), {merged.events} events{suffix}")
            else:
                all_ok = False
                if merged.bad_run_id is not None:
                    where = f" at line {merged.first_bad_line}" if merged.first_bad_line else ""
                    print(
                        f"FAIL {path.name}: run {merged.bad_run_id}: {merged.reason}{where} "
                        f"({merged.runs} run(s), {merged.events} verified)"
                    )
                else:
                    print(f"FAIL {path.name}: {merged.reason}")
        else:
            result = verify_run_file(path, require_complete=not allow_incomplete)
            if result.ok:
                suffix = f" ({len(result.warnings)} warning(s))" if result.warnings else ""
                print(f"OK   {path.stem}: {result.events} events{suffix}")
            else:
                all_ok = False
                where = f" at line {result.first_bad_line}" if result.first_bad_line else ""
                print(f"FAIL {path.stem}: {result.reason}{where} ({result.events} verified)")
    return 0 if all_ok else 1
