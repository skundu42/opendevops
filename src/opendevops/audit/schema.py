"""AuditEvent pydantic model, schema_version=1 (T2).

One model with optional sections (rather than a class per event type); per-type required
fields are enforced by a model validator. The hash chain binds every field except the two
chaining fields themselves (``prev_hash``/``hash``): an event's ``hash`` is::

    "sha256:" + sha256(prev_hash_of_last_event + canonical_json(event_without_hash_fields))

where ``canonical_json`` is deterministic (sorted keys, compact separators). ``prev_hash``
is prepended as the chaining input rather than hashed inline, so reordering a line is caught
by the linkage check (each event's ``prev_hash`` must equal the previous line's ``hash``) and
mutating any payload byte is caught by recomputation.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

# The chain seed. Every run's first event links back to this constant. P5 upgrades the seed
# to an ed25519-signed run header; the constant string is the P1 placeholder.
GENESIS_PREV_HASH = "sha256:genesis"

SCHEMA_VERSION = 1


# --------------------------------------------------------------------------------------
# sortable event ids (ULID: 48-bit ms timestamp + 80-bit randomness, Crockford base32)
# --------------------------------------------------------------------------------------

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _encode_base32(value: int, length: int) -> str:
    """Fixed-length Crockford base32. The alphabet is ASCII-ascending, so equal-length
    encodings sort lexicographically the same as their integer value."""
    out = [""] * length
    for i in range(length - 1, -1, -1):
        out[i] = _CROCKFORD[value & 0x1F]
        value >>= 5
    return "".join(out)


def new_event_id() -> str:
    """A 26-char ULID: time-sortable, unique. Sorting by id ~= sorting by creation time."""
    ms = int(time.time() * 1000)
    rand = int.from_bytes(os.urandom(10), "big")  # 80 bits
    return _encode_base32(ms, 10) + _encode_base32(rand, 16)


def utc_now_iso() -> str:
    """UTC ISO8601 with a trailing ``Z`` (lexically sortable at fixed precision)."""
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


# --------------------------------------------------------------------------------------
# event type
# --------------------------------------------------------------------------------------


class EventType(StrEnum):
    """The kinds of audit event. ``run_started`` seeds the chain; ``run_completed`` closes it."""

    run_started = "run_started"  # chain seed
    decision = "decision"  # pre-exec policy decision
    execution = "execution"  # post-exec result
    escalation = "escalation"  # awaiting human approval
    resolution = "resolution"  # human approve/deny (carries approver)
    budget_trip = "budget_trip"  # a budget ceiling tripped
    policy_error = "policy_error"  # policy engine failure
    run_completed = "run_completed"  # final cost + usage summary


# --------------------------------------------------------------------------------------
# nested sections
# --------------------------------------------------------------------------------------


class Principal(BaseModel):
    """Who initiated the run: the interface (cli/slack/api) and the resolved user."""

    model_config = ConfigDict(extra="forbid")

    interface: str
    user: str


class Decision(BaseModel):
    """A policy decision recorded pre-execution."""

    model_config = ConfigDict(extra="forbid")

    effect: str
    rule_id: str
    reason: str
    channel: str
    rewritten_argv: list[str] | None = None


class StagedFile(BaseModel):
    """A file staged by a tool, recorded by content hash for after-the-fact review."""

    model_config = ConfigDict(extra="forbid")

    path: str
    sha256: str


class Execution(BaseModel):
    """The result of running a tool/command post-decision."""

    model_config = ConfigDict(extra="forbid")

    exit_code: int
    duration_ms: int
    stdout_sha256: str
    stdout_excerpt: str
    truncated: bool
    staged_files: list[StagedFile] = Field(default_factory=list)


# --------------------------------------------------------------------------------------
# the event
# --------------------------------------------------------------------------------------


class AuditEvent(BaseModel):
    """A single hash-chained audit record. ``schema_version`` is 1 (final for P1)."""

    model_config = ConfigDict(extra="forbid", protected_namespaces=())

    event_id: str = Field(default_factory=new_event_id)
    ts: str = Field(default_factory=utc_now_iso)
    schema_version: int = SCHEMA_VERSION
    event_type: EventType

    run_id: str
    thread_id: str | None = None
    trace_id: str | None = None

    principal: Principal
    environment: str
    agent_git_sha: str | None = None
    policy_version: str | None = None
    model: str | None = None

    tool: str | None = None
    tool_call_id: str | None = None
    args: dict[str, Any] | None = None

    decision: Decision | None = None
    execution: Execution | None = None

    # resolution events carry the human approver; run_completed carries the cost/usage summary.
    approver: str | None = None
    summary: dict[str, Any] | None = None

    # chaining fields — excluded from the hash payload (see canonical_json).
    prev_hash: str
    hash: str = ""

    @model_validator(mode="after")
    def _validate_per_type(self) -> AuditEvent:
        """Enforce the required section for each event type (a bare 'execution' is a bug)."""
        et = self.event_type
        if et is EventType.decision and self.decision is None:
            raise ValueError("decision events must carry a 'decision' section")
        if et is EventType.execution:
            if self.execution is None:
                raise ValueError("execution events must carry an 'execution' section")
            if self.tool_call_id is None:
                raise ValueError("execution events must carry a 'tool_call_id'")
        if et is EventType.resolution and self.approver is None:
            raise ValueError("resolution events must carry an 'approver'")
        if et is EventType.run_completed and self.summary is None:
            raise ValueError("run_completed events must carry a 'summary'")
        return self


# --------------------------------------------------------------------------------------
# canonicalization + hashing (shared by logger and verifier)
# --------------------------------------------------------------------------------------


def canonical_dumps(obj: Any) -> str:
    """Deterministic JSON of an arbitrary JSON-able object (sorted keys, compact separators).

    This is the **single** canonical serializer in the codebase. It backs three call sites that
    MUST agree byte-for-byte:

    * the audit hash chain (:func:`canonical_json` below, and the logger's cross-process
      resume-dedupe ``_content_sha``); and
    * the P5 signed decision token's argv hash (``sha256(canonical_dumps(argv))``), computed on
      the signer (agent) and re-derived on the verifier (executor service) — single-sourcing it
      here is what guarantees the two sides never disagree on the bytes being signed.

    ``sort_keys`` + compact ``separators`` make the byte string reproducible regardless of dict
    insertion / on-disk key order; ``default=str`` coerces the odd non-JSON scalar (e.g. a
    ``Path``) the same way on every caller.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def canonical_json(event: AuditEvent) -> str:
    """Deterministic JSON of an event, excluding the chaining fields ``hash``/``prev_hash``.

    Sorted keys + compact separators make the byte string reproducible, so the writer and
    the verifier derive identical input for the hash regardless of on-disk key order. Delegates
    to :func:`canonical_dumps` — the one serializer shared with the logger dedupe sha and the P5
    decision-token argv hash.
    """
    payload = event.model_dump(mode="json", exclude={"hash", "prev_hash"})
    return canonical_dumps(payload)


def compute_event_hash(prev_hash: str, event: AuditEvent) -> str:
    """``sha256:`` + sha256(prev_hash + canonical_json(event)). Binds the whole payload."""
    digest = hashlib.sha256((prev_hash + canonical_json(event)).encode("utf-8")).hexdigest()
    return "sha256:" + digest
