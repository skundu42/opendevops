"""AuditLogger: per-run append-only JSONL with sha256 hash chain.

Per-run chain files (``audit/<run_id>.jsonl``) make every chain single-writer: concurrent
runs on LangGraph Server would otherwise race a shared-file ``prev_hash`` read-modify-write.
The API is synchronous — it is called from async middleware, but each write is a single tiny
``os.write`` on an ``O_APPEND`` fd, so there is nothing to gain from making it async and a
sync call keeps the hash-chain read-modify-write trivially ordered per run.

Run-level context (principal, environment, git sha, ...) captured at :meth:`start_run` is
stamped onto every subsequent event, so callers only pass the event-specific fields; a
per-call field always overrides the captured default.

Durable chain rehydration
-------------------------
The per-run in-process state (chain tip + dedupe keys) is **rebuildable from the chain file on
disk**, so a *fresh* ``AuditLogger`` — a server RESTART between an escalation suspend and its
resume, or a resume request handled by a *different* worker than the one that suspended — can
continue an already-open chain instead of failing closed or re-seeding a second genesis line.
When :meth:`append` / :meth:`end_run` / :meth:`start_run` hits a ``run_id`` absent from the
in-process ``_runs`` map but whose chain file EXISTS, :meth:`_rehydrate` reads the file, adopts
the last line's ``hash`` as the tip, and rebuilds the content-bearing dedupe key set from the
persisted events (so a replayed event still collapses ACROSS the process boundary). This matters
because on a resume the tools node re-executes BEFORE the lifecycle middleware's ``abefore_model``
seed, so the fresh logger's FIRST touch is an ``append`` — durable ``start_run`` idempotency alone
would be too late.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from opendevops.audit.schema import (
    GENESIS_PREV_HASH,
    AuditEvent,
    EventType,
    canonical_dumps,
    compute_event_hash,
)

# Volatile / chaining fields excluded from the dedupe content sha. ``event_id`` / ``ts`` are
# regenerated on every write, and ``prev_hash`` / ``hash`` move with chain position; excluding all
# four makes the sha depend only on the event's semantic content, so a replay of the same logical
# event — even one rehydrated FROM DISK with a fresh id/ts and a different chain position — hashes
# identically and dedupes.
_DEDUPE_EXCLUDE: frozenset[str] = frozenset({"event_id", "ts", "prev_hash", "hash"})

# Keys on a persisted event that are NOT part of the captured run header (structural / per-event).
# The rest of a ``run_started`` event's non-null fields ARE the header (principal, environment,
# model, policy_version, agent_git_sha), which :meth:`_rehydrate` restores so later appends stamp
# the same run context they would have in the original process.
_NON_HEADER_KEYS: frozenset[str] = frozenset(
    {
        "event_id",
        "ts",
        "schema_version",
        "event_type",
        "run_id",
        "prev_hash",
        "hash",
        "thread_id",
        "trace_id",
        "tool",
        "tool_call_id",
        "args",
        "decision",
        "execution",
        "approver",
        "summary",
    }
)


class UnknownRunError(RuntimeError):
    """Raised on append/end for a run that was never started (a chain without a seed is a bug)."""


class CorruptChainError(UnknownRunError):
    """A run's chain file exists but cannot be read/parsed while rehydrating from disk.

    A subclass of :class:`UnknownRunError` so the fail-closed callers (PolicyMiddleware) still DENY
    on it and — critically — no second genesis-linked ``run_started`` is ever written over a chain
    we could not validate. We refuse to guess a tip/dedupe state from a corrupt file.
    """


def _content_sha(event: AuditEvent) -> str:
    """Stable sha256 over an event's semantic content, for the cross-process resume-dedupe key.

    Hashes the event's canonical form MINUS the volatile per-write fields (``event_id`` / ``ts``)
    and the chaining fields (``prev_hash`` / ``hash``); see :data:`_DEDUPE_EXCLUDE`. Two replayed
    appends of the same logical event therefore hash identically and dedupe, while a genuinely
    DIVERGED event for the same ``(tool_call_id, event_type)`` — an edited-argv decision, a second
    approver's resolution across a double interrupt — hashes differently and IS recorded. Corollary:
    a byte-identical repeat of an edit/resolution for the same ``tool_call_id`` (same approver, same
    argv replayed across a re-interrupt) hashes identically and collapses under this content-bearing
    dedupe — execution-exactly-once is unaffected; the chain records the loop once.

    Deterministic (JSON-mode model dump, sorted keys, compact separators, ``default=str``) so the
    writer and a chain rehydrated FROM DISK derive the same digest: the identical dedupe key can be
    rebuilt from the persisted events after a restart / worker handoff (see
    :meth:`AuditLogger._rehydrate`). This is the single source of the dedupe sha — the rehydrate
    path reuses it rather than reimplementing the derivation.
    """
    payload = event.model_dump(mode="json", exclude=_DEDUPE_EXCLUDE)
    canonical = canonical_dumps(payload)  # the single shared serializer (audit + decision token)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _run_header(seed: AuditEvent) -> dict[str, Any]:
    """Recover the captured run header from a persisted ``run_started`` seed (rehydration).

    The header is every non-null run-scoped field the seed carries (principal, environment, model,
    policy_version, agent_git_sha) — everything except the structural / per-event keys in
    :data:`_NON_HEADER_KEYS`. Restoring it means later appends on a rehydrated logger stamp the same
    header-only fields (notably ``agent_git_sha``) a replayed event carried when first written, so
    the rebuilt canonical content matches and the dedupe still fires across the process boundary.
    """
    dumped = seed.model_dump(mode="json", exclude_none=True)
    return {k: v for k, v in dumped.items() if k not in _NON_HEADER_KEYS}


@dataclass
class _RunState:
    """In-process per-run chain state."""

    last_hash: str
    header: dict[str, Any]
    # Dedupe keys are CONTENT-BEARING: ``(tool_call_id, event_type, content_sha)``. A replayed
    # identical event collapses (same sha), but a genuinely different event for the same
    # (tool_call_id, event_type) — an edited-argv decision, a second escalation, a second
    # approver's resolution across a double interrupt — has a different sha and is recorded.
    seen_keys: set[tuple[str, EventType, str]] = field(default_factory=set)


class AuditLogger:
    """Append-only, hash-chained audit writer with one JSONL file per run."""

    def __init__(self, dir: Path) -> None:
        self._dir = Path(dir)
        self._dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._runs: dict[str, _RunState] = {}
        self._lock = threading.Lock()

    def _path(self, run_id: str) -> Path:
        return self._dir / f"{run_id}.jsonl"

    def start_run(self, run_id: str, **header: Any) -> None:
        """Write the ``run_started`` seed event (``prev_hash = GENESIS``) and capture run context.

        Idempotent — durably. If the run is already started in this process the call is a no-op;
        and if it is not in-process but its chain file already EXISTS on disk (a prior process /
        another worker seeded it), it is rehydrated and the call is STILL a no-op — so a resume
        handled by a fresh logger never writes a second genesis-linked seed over an open chain.
        A ``run_id`` with no chain file seeds fresh, exactly as before. A future upgrade can move
        the seed from the genesis constant to an ed25519-signed run header.
        """
        with self._lock:
            if run_id in self._runs:
                return
            if self._rehydrate(run_id) is not None:
                return  # already seeded in a prior process — durable idempotency, no second genesis
            state = _RunState(last_hash=GENESIS_PREV_HASH, header=dict(header))
            self._runs[run_id] = state
            self._write_event(run_id, state, event_type=EventType.run_started, **header)

    def append(
        self,
        run_id: str,
        event_type: EventType | str,
        *,
        tool_call_id: str | None = None,
        **fields: Any,
    ) -> AuditEvent | None:
        """Append one event to the run's chain; return it, or ``None`` if deduped.

        Dedupe key is ``(tool_call_id, event_type, content_sha)`` (only for events carrying a
        ``tool_call_id``): a duplicate append with the SAME canonical payload is a no-op returning
        ``None``, absorbing LangGraph node re-execution after an ``interrupt()`` resume (the tools
        node re-runs from its start, re-emitting every event above the interrupt).

        The ``content_sha`` (see :func:`_content_sha`) makes the key content-bearing AND
        reconstructible from disk: a replayed identical event dedupes even across a process boundary
        (the key set was rebuilt from the persisted events), while a DIVERGED event for the same
        ``(tool_call_id, event_type)`` hashes differently and IS recorded.

        Raises :class:`UnknownRunError` if the run was never started and has no chain file on disk;
        :class:`CorruptChainError` (a subclass) if a chain file exists but cannot be parsed.
        """
        et = EventType(event_type)
        with self._lock:
            state = self._runs.get(run_id)
            if state is None:
                state = self._rehydrate(run_id)
            if state is None:
                raise UnknownRunError(f"append to run {run_id!r} that was never started")

            merged: dict[str, Any] = {**state.header, **fields}
            if tool_call_id is not None:
                merged["tool_call_id"] = tool_call_id

            # Build the candidate first so the dedupe sha is taken over the SAME canonical event
            # form the rehydrate path derives from disk (validates per-type required fields too).
            candidate = AuditEvent(
                run_id=run_id, prev_hash=state.last_hash, event_type=et, **merged
            )
            key: tuple[str, EventType, str] | None = None
            if tool_call_id is not None:
                key = (tool_call_id, et, _content_sha(candidate))
                if key in state.seen_keys:
                    return None

            event = self._commit(run_id, state, candidate)
            if key is not None:
                state.seen_keys.add(key)
            return event

    def end_run(self, run_id: str, summary: dict[str, Any]) -> AuditEvent | None:
        """Write the ``run_completed`` event with ``summary`` and drop per-run state.

        Like :meth:`append`, this rehydrates from disk for a run absent in-process but present on
        disk (so a fresh logger can close a chain it did not open), and raises
        :class:`UnknownRunError` (or :class:`CorruptChainError`) otherwise. A run that crashes
        before this is called simply has no ``run_completed`` line; its chain still verifies (it
        just ends early).
        """
        with self._lock:
            state = self._runs.get(run_id)
            if state is None:
                state = self._rehydrate(run_id)
            if state is None:
                raise UnknownRunError(f"end of run {run_id!r} that was never started")
            merged: dict[str, Any] = {**state.header, "summary": summary}
            event = self._write_event(run_id, state, event_type=EventType.run_completed, **merged)
            del self._runs[run_id]
            return event

    def _rehydrate(self, run_id: str) -> _RunState | None:
        """Rebuild in-process chain state for ``run_id`` from its on-disk chain file.

        Returns the rehydrated (and now cached) :class:`_RunState`, or ``None`` if no chain file
        exists (the caller then treats the run as never-started). Reads the file, validates every
        line parses as an :class:`AuditEvent`, adopts the LAST line's ``hash`` as the chain tip,
        restores the run header from the first event, and rebuilds the content-bearing dedupe key
        set (same ``(tool_call_id, event_type, content_sha)`` derivation as the write path, reusing
        :func:`_content_sha`). The original operation then proceeds against the adopted tip.

        Fail-closed: a file that exists but is unreadable or does not parse raises
        :class:`CorruptChainError` — never a guess, never a second genesis line.

        Concurrency: read-only file access plus in-process state mutation under the held
        ``self._lock``; TWO workers appending concurrently to ONE run remains out of scope —
        langgraph serializes a given thread's run to a single worker at a time, so an open chain
        has one live writer and rehydration only ever runs when THIS logger has no state for a run
        another process / worker (or a prior lifetime of this one) already wrote.
        """
        path = self._path(run_id)
        if not path.exists():
            return None
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise CorruptChainError(f"cannot read chain file for run {run_id!r}: {exc}") from exc

        events: list[AuditEvent] = []
        for lineno, line in enumerate(raw.splitlines(), start=1):
            if not line.strip():
                continue  # tolerate stray blank lines (mirrors verify_run_file)
            try:
                events.append(AuditEvent.model_validate(json.loads(line)))
            except (ValueError, json.JSONDecodeError) as exc:
                raise CorruptChainError(
                    f"chain file for run {run_id!r} is corrupt at line {lineno}: {exc}"
                ) from exc
        if not events:
            return None  # an empty (whitespace-only) file is indistinguishable from no chain

        state = _RunState(last_hash=events[-1].hash, header=_run_header(events[0]))
        for event in events:
            if event.tool_call_id is not None:
                state.seen_keys.add(
                    (event.tool_call_id, event.event_type, _content_sha(event))
                )
        self._runs[run_id] = state
        return state

    def _write_event(self, run_id: str, state: _RunState, **event_fields: Any) -> AuditEvent:
        """Build the event and commit it to the chain (used by start_run / end_run seeds)."""
        candidate = AuditEvent(run_id=run_id, prev_hash=state.last_hash, **event_fields)
        return self._commit(run_id, state, candidate)

    def _commit(self, run_id: str, state: _RunState, candidate: AuditEvent) -> AuditEvent:
        """Compute a validated candidate's chained hash, append one line, advance ``last_hash``."""
        event_hash = compute_event_hash(candidate.prev_hash, candidate)
        event = candidate.model_copy(update={"hash": event_hash})
        self._append_line(run_id, event)
        state.last_hash = event_hash
        return event

    def _append_line(self, run_id: str, event: AuditEvent) -> None:
        """Serialize one event and append it via a single ``os.write`` on an ``O_APPEND`` fd."""
        payload = event.model_dump(mode="json", exclude_none=True)
        line = json.dumps(payload, separators=(",", ":"), default=str) + "\n"
        fd = os.open(self._path(run_id), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, line.encode("utf-8"))
        finally:
            os.close(fd)
