"""Tamper-evident audit trail: per-run hash-chained JSONL events.

Public surface:
- :class:`AuditEvent` (+ nested :class:`Principal`, :class:`Decision`, :class:`Execution`,
  :class:`StagedFile`) and the :class:`EventType` enum — the schema.
- :class:`AuditLogger` — the per-run, single-writer, hash-chaining append log (with durable
  rehydration of an open chain from disk; :class:`CorruptChainError` on an unparseable one).
- :func:`verify_run_file` / :func:`verify_dir` / :func:`main` (+ :class:`VerifyResult`) — the
  chain walker behind ``opendevops audit verify``.
- :func:`verify_merged_file` (+ :class:`MergedVerifyResult`) — verify a Vector-MERGED spool file
  (interleaved multi-run) by regrouping its lines by ``run_id`` and re-checking each per-run chain.
- :data:`GENESIS_PREV_HASH`, :func:`canonical_json`, :func:`compute_event_hash` — chain
  primitives shared by the writer and verifier.
"""

from __future__ import annotations

from opendevops.audit.logger import AuditLogger, CorruptChainError, UnknownRunError
from opendevops.audit.schema import (
    GENESIS_PREV_HASH,
    SCHEMA_VERSION,
    AuditEvent,
    Decision,
    EventType,
    Execution,
    Principal,
    StagedFile,
    canonical_json,
    compute_event_hash,
    new_event_id,
    utc_now_iso,
)
from opendevops.audit.verify import (
    MergedVerifyResult,
    VerifyResult,
    main,
    verify_dir,
    verify_merged_file,
    verify_run_file,
)

__all__ = [
    "GENESIS_PREV_HASH",
    "SCHEMA_VERSION",
    "AuditEvent",
    "AuditLogger",
    "CorruptChainError",
    "Decision",
    "EventType",
    "Execution",
    "MergedVerifyResult",
    "Principal",
    "StagedFile",
    "UnknownRunError",
    "VerifyResult",
    "canonical_json",
    "compute_event_hash",
    "main",
    "new_event_id",
    "utc_now_iso",
    "verify_dir",
    "verify_merged_file",
    "verify_run_file",
]
