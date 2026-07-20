"""Audit trail tests: hash-chain round-trip, tamper detection, dedupe, per-type validation.

Covers the compliance-critical properties of `opendevops.audit`:
- an intact chain verifies and reports the right event count,
- any modified / deleted / reordered *interior* line is detected at that line,
- deleting the chain's trailing line(s) is NOT detected — a documented P1 blind spot, pinned by
  test_tamper_delete_last_line_is_undetected (see that test and verify.py's module docstring),
- LangGraph resume re-execution is absorbed by (tool_call_id, event_type, content_sha) dedupe,
- per-type required sections are enforced, and interleaved concurrent runs stay independent,
- a Vector-MERGED spool file (many per-run chains interleaved into one day-file) is regrouped by
  run_id and each run's subsequence re-verified as an independent chain (verify_merged_file / the
  audit-verify CLI auto-detecting a merged file) — a tamper or interior break in any run is caught.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from opendevops.audit import (
    GENESIS_PREV_HASH,
    AuditEvent,
    AuditLogger,
    CorruptChainError,
    EventType,
    UnknownRunError,
    verify_dir,
    verify_merged_file,
    verify_run_file,
)
from opendevops.audit.verify import main as audit_verify_main

PRINCIPAL = {"interface": "cli", "user": "sandipan"}
ENV = "staging"


def _start(logger: AuditLogger, run_id: str) -> None:
    logger.start_run(
        run_id,
        principal=PRINCIPAL,
        environment=ENV,
        agent_git_sha="deadbeef",
        policy_version="pol-1",
    )


def _standard_chain(dir_: Path, run_id: str = "run-A") -> tuple[AuditLogger, Path]:
    """seed + decision(MARKER) + execution + escalation, no end_run yet."""
    logger = AuditLogger(dir_)
    _start(logger, run_id)
    logger.append(
        run_id,
        EventType.decision,
        tool_call_id="call_1",
        tool="run_command",
        args={"argv": ["kubectl", "get", "pods"]},
        decision={
            "effect": "allow",
            "rule_id": "R1",
            "reason": "MARKER",
            "channel": "auto",
            "rewritten_argv": None,
        },
    )
    logger.append(
        run_id,
        EventType.execution,
        tool_call_id="call_1",
        tool="run_command",
        execution={
            "exit_code": 0,
            "duration_ms": 12,
            "stdout_sha256": "sha256:abc",
            "stdout_excerpt": "pod-1 Running",
            "truncated": False,
            "staged_files": [],
        },
    )
    logger.append(
        run_id,
        EventType.escalation,
        args={"reason": "needs approval"},
    )
    path = dir_ / f"{run_id}.jsonl"
    return logger, path


# --------------------------------------------------------------------------------------
# round-trip
# --------------------------------------------------------------------------------------


def test_round_trip_verifies(tmp_path: Path) -> None:
    logger, path = _standard_chain(tmp_path)
    logger.end_run("run-A", summary={"cost_usd": 0.01, "usage": {"input": 100}})

    result = verify_run_file(path)
    assert result.ok is True
    assert result.reason is None
    assert result.first_bad_line is None
    # seed + decision + execution + escalation + run_completed
    assert result.events == 5


def test_seed_uses_genesis_prev_hash(tmp_path: Path) -> None:
    logger = AuditLogger(tmp_path)
    _start(logger, "run-A")
    lines = (tmp_path / "run-A.jsonl").read_text().splitlines()
    import json

    seed = json.loads(lines[0])
    assert seed["event_type"] == "run_started"
    assert seed["prev_hash"] == GENESIS_PREV_HASH
    assert seed["hash"].startswith("sha256:")
    assert seed["hash"] != GENESIS_PREV_HASH
    # sortable id + iso ts present
    assert len(seed["event_id"]) == 26
    assert seed["ts"].endswith("Z")


def test_crashed_run_without_completed_still_verifies(tmp_path: Path) -> None:
    """A run that never wrote run_completed must still verify — the chain just ends."""
    _logger, path = _standard_chain(tmp_path)
    result = verify_run_file(path)
    assert result.ok is True
    assert result.events == 4  # seed + 3, no run_completed


# --------------------------------------------------------------------------------------
# tamper detection
# --------------------------------------------------------------------------------------


def test_tamper_modify_byte_in_middle_line(tmp_path: Path) -> None:
    logger, path = _standard_chain(tmp_path)
    logger.end_run("run-A", summary={"cost_usd": 0.01})

    lines = path.read_text().splitlines()
    # line index 1 (0-based) is the decision event carrying "MARKER"
    assert "MARKER" in lines[1]
    lines[1] = lines[1].replace("MARKER", "MARKEX", 1)
    path.write_text("\n".join(lines) + "\n")

    result = verify_run_file(path)
    assert result.ok is False
    assert result.first_bad_line == 2  # 1-based
    assert result.reason is not None


def test_tamper_delete_line(tmp_path: Path) -> None:
    logger, path = _standard_chain(tmp_path)
    logger.end_run("run-A", summary={"cost_usd": 0.01})

    lines = path.read_text().splitlines()
    del lines[2]  # drop the execution event
    path.write_text("\n".join(lines) + "\n")

    result = verify_run_file(path)
    assert result.ok is False
    assert result.first_bad_line == 3  # the line now at position 3 fails linkage


def test_tamper_swap_lines(tmp_path: Path) -> None:
    logger, path = _standard_chain(tmp_path)
    logger.end_run("run-A", summary={"cost_usd": 0.01})

    lines = path.read_text().splitlines()
    lines[2], lines[3] = lines[3], lines[2]  # swap execution and escalation
    path.write_text("\n".join(lines) + "\n")

    result = verify_run_file(path)
    assert result.ok is False
    assert result.first_bad_line == 3


def test_tamper_corrupt_json(tmp_path: Path) -> None:
    logger, path = _standard_chain(tmp_path)
    lines = path.read_text().splitlines()
    lines[1] = lines[1][:-3]  # truncate -> invalid JSON
    path.write_text("\n".join(lines) + "\n")

    result = verify_run_file(path)
    assert result.ok is False
    assert result.first_bad_line == 2


def test_tamper_delete_last_line_is_undetected(tmp_path: Path) -> None:
    """Documented P1 blind spot, pinned so it can't regress silently.

    Deleting the LAST line(s) of a chain leaves a strictly shorter, but fully self-consistent,
    prefix chain: every surviving event's prev_hash/hash still link up correctly. Linkage and
    recomputation (the two checks verify_run_file performs) only ever compare a line against
    its neighbors *within the file*, so there is nothing in the remaining bytes that reveals an
    event used to follow the new last line. This is indistinguishable from a run that crashed
    or was interrupted before writing more events (see
    test_crashed_run_without_completed_still_verifies) — and a crashed run legitimately must
    still verify ok=True. See the module docstring in verify.py for what tail-truncation
    detection would require (a signed run header/trailer or an external tip anchor, P5).

    If a future change (e.g. a signed trailer) makes tail truncation detectable, this test
    should start failing its `ok is True` assertion — update it consciously rather than
    patching it to pass.
    """
    logger, path = _standard_chain(tmp_path)
    logger.end_run("run-A", summary={"cost_usd": 0.01})

    lines = path.read_text().splitlines()
    assert len(lines) == 5  # seed + decision + execution + escalation + run_completed
    del lines[-1]  # drop the trailing run_completed line only
    path.write_text("\n".join(lines) + "\n")

    result = verify_run_file(path)
    assert result.ok is True  # accepted blind spot, not a bug — see docstring above
    assert result.events == 4


# --------------------------------------------------------------------------------------
# dedupe
# --------------------------------------------------------------------------------------


def test_dedupe_same_key_appended_twice_is_one_line(tmp_path: Path) -> None:
    logger = AuditLogger(tmp_path)
    _start(logger, "run-A")
    dec = {
        "effect": "allow",
        "rule_id": "R1",
        "reason": "x",
        "channel": "auto",
        "rewritten_argv": None,
    }
    first = logger.append("run-A", EventType.decision, tool_call_id="call_1", decision=dec)
    second = logger.append("run-A", EventType.decision, tool_call_id="call_1", decision=dec)
    assert first is not None
    assert second is None  # duplicate absorbed

    lines = (tmp_path / "run-A.jsonl").read_text().splitlines()
    assert len(lines) == 2  # seed + one decision


def test_dedupe_different_event_type_same_call_keeps_both(tmp_path: Path) -> None:
    logger = AuditLogger(tmp_path)
    _start(logger, "run-A")
    logger.append(
        "run-A",
        EventType.decision,
        tool_call_id="call_1",
        decision={
            "effect": "allow",
            "rule_id": "R1",
            "reason": "x",
            "channel": "auto",
            "rewritten_argv": None,
        },
    )
    logger.append(
        "run-A",
        EventType.execution,
        tool_call_id="call_1",
        execution={
            "exit_code": 0,
            "duration_ms": 1,
            "stdout_sha256": "sha256:0",
            "stdout_excerpt": "",
            "truncated": False,
            "staged_files": [],
        },
    )
    lines = (tmp_path / "run-A.jsonl").read_text().splitlines()
    assert len(lines) == 3  # seed + decision + execution


def test_dedupe_is_content_bearing_diverged_payload_same_key_is_kept(tmp_path: Path) -> None:
    """Same (tool_call_id, event_type) but DIVERGED payload is recorded, not first-write-wins.

    The dedupe key is content-bearing (I1): an identical replay collapses, but a genuinely
    different event for the same tool_call_id (an edited-argv decision on the escalate resume,
    a second approver's resolution) must still append or the chain would affirmatively mislead.
    """
    logger = AuditLogger(tmp_path)
    _start(logger, "run-A")

    def _decision(argv: list[str]) -> dict[str, object]:
        return {
            "effect": "escalate",
            "rule_id": "R1",
            "reason": "x",
            "channel": "none",
            "rewritten_argv": None,
        }

    original = logger.append(
        "run-A", EventType.decision, tool_call_id="call_1",
        args={"argv": ["kubectl", "delete", "pod", "x"]}, decision=_decision([]),
    )
    # An identical replay of the SAME event still dedupes (absorbs the resume node re-run).
    replay = logger.append(
        "run-A", EventType.decision, tool_call_id="call_1",
        args={"argv": ["kubectl", "delete", "pod", "x"]}, decision=_decision([]),
    )
    # A DIVERGED event (edited argv) for the same (tool_call_id, event_type) IS recorded.
    diverged = logger.append(
        "run-A", EventType.decision, tool_call_id="call_1",
        args={"argv": ["kubectl", "get", "pods"]}, decision=_decision([]),
    )
    assert original is not None
    assert replay is None  # identical content deduped
    assert diverged is not None  # diverged content kept

    lines = (tmp_path / "run-A.jsonl").read_text().splitlines()
    assert len(lines) == 3  # seed + original decision + diverged decision
    assert verify_run_file(tmp_path / "run-A.jsonl").ok is True


# --------------------------------------------------------------------------------------
# durable chain rehydration (T16): a FRESH logger continues an on-disk chain
#
# Models a server RESTART between an escalation suspend and its resume, or a resume request
# handled by a DIFFERENT worker than the one that suspended: a brand-new AuditLogger (empty
# in-process `_runs`) whose first touch of the run is an append/end_run/start_run against a chain
# file only the previous process wrote.
# --------------------------------------------------------------------------------------


def _read(path: Path) -> list[dict[str, object]]:
    import json

    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_fresh_logger_append_continues_on_disk_chain(tmp_path: Path) -> None:
    """A fresh AuditLogger on an existing chain dir appends onto the rehydrated tip; verifies."""
    _logger1, path = _standard_chain(tmp_path)  # seed + decision + execution + escalation
    assert len(_read(path)) == 4

    logger2 = AuditLogger(tmp_path)  # restart / other worker: empty _runs, same dir
    resolved = logger2.append(
        "run-A",
        EventType.resolution,
        tool_call_id="call_1",
        approver="alice",
        summary={"type": "approve"},
    )
    assert resolved is not None  # not deduped — a genuinely new event
    assert resolved.prev_hash.startswith("sha256:")  # linked onto the rehydrated tip, not genesis
    assert resolved.prev_hash != GENESIS_PREV_HASH

    result = verify_run_file(path)
    assert result.ok is True
    assert result.events == 5  # seed + decision + execution + escalation + resolution


def test_fresh_logger_dedupes_replayed_event_across_process_boundary(tmp_path: Path) -> None:
    """The content-bearing dedupe key set is rebuilt FROM DISK, so a replayed identical event
    (the resume node re-execution on a fresh logger) still collapses — while a diverged one is
    recorded. This is the pin for the I1 dedupe surviving a restart / worker handoff."""
    _logger1, path = _standard_chain(tmp_path)
    before = path.read_text()

    logger2 = AuditLogger(tmp_path)
    # Byte-for-byte replay of the decision the first logger already wrote (same header + fields).
    replay = logger2.append(
        "run-A",
        EventType.decision,
        tool_call_id="call_1",
        tool="run_command",
        args={"argv": ["kubectl", "get", "pods"]},
        decision={
            "effect": "allow",
            "rule_id": "R1",
            "reason": "MARKER",
            "channel": "auto",
            "rewritten_argv": None,
        },
    )
    assert replay is None  # deduped across the boundary
    assert path.read_text() == before  # no duplicate line written

    # A DIVERGED decision (different argv) for the same (tool_call_id, event_type) IS recorded.
    diverged = logger2.append(
        "run-A",
        EventType.decision,
        tool_call_id="call_1",
        tool="run_command",
        args={"argv": ["kubectl", "get", "svc"]},
        decision={
            "effect": "allow",
            "rule_id": "R1",
            "reason": "MARKER",
            "channel": "auto",
            "rewritten_argv": None,
        },
    )
    assert diverged is not None
    assert verify_run_file(path).ok is True


def test_fresh_logger_end_run_closes_rehydrated_chain(tmp_path: Path) -> None:
    """A fresh logger can close a chain it did not open (end_run rehydrates then appends)."""
    _logger1, path = _standard_chain(tmp_path)
    logger2 = AuditLogger(tmp_path)

    completed = logger2.end_run("run-A", summary={"status": "completed", "cost_usd": 0.0})
    assert completed is not None
    result = verify_run_file(path)
    assert result.ok is True
    assert result.events == 5  # seed + decision + execution + escalation + run_completed
    assert [e["event_type"] for e in _read(path)][-1] == "run_completed"


def test_fresh_logger_start_run_is_durably_idempotent(tmp_path: Path) -> None:
    """start_run on a run already seeded on disk is a no-op — no SECOND genesis run_started."""
    _logger1, path = _standard_chain(tmp_path)
    before = path.read_text()

    logger2 = AuditLogger(tmp_path)
    _start(logger2, "run-A")  # would seed a fresh chain — but the file already exists on disk
    assert path.read_text() == before  # byte-identical: no duplicate seed
    assert [e["event_type"] for e in _read(path)].count("run_started") == 1

    # …and the rehydrated logger still appends onto the single, open chain.
    assert logger2.append("run-A", EventType.escalation, args={"reason": "second"}) is not None
    assert verify_run_file(path).ok is True


def test_rehydrate_corrupt_chain_file_fails_closed(tmp_path: Path) -> None:
    """An existing-but-corrupt chain file makes rehydration raise CorruptChainError (an
    UnknownRunError, so PolicyMiddleware still DENIES) — no guess, no second genesis line."""
    _logger1, path = _standard_chain(tmp_path)
    lines = path.read_text().splitlines()
    lines[-1] = lines[-1][:30]  # truncate the last line to invalid JSON
    path.write_text("\n".join(lines) + "\n")
    corrupt = path.read_text()

    logger2 = AuditLogger(tmp_path)
    with pytest.raises(CorruptChainError) as exc_info:
        logger2.append(
            "run-A",
            EventType.resolution,
            tool_call_id="call_1",
            approver="alice",
            summary={"type": "approve"},
        )
    assert isinstance(exc_info.value, UnknownRunError)  # fail-closed class the caller handles
    assert path.read_text() == corrupt  # nothing written

    # start_run over the same corrupt file also refuses — never lays a second genesis line.
    with pytest.raises(CorruptChainError):
        _start(logger2, "run-A")
    assert path.read_text() == corrupt


def test_unknown_run_without_file_still_raises_and_writes_nothing(tmp_path: Path) -> None:
    """A run with NO chain file behaves exactly as before rehydration: append/end_run raise the
    base UnknownRunError (NOT CorruptChainError) and no file is created."""
    logger = AuditLogger(tmp_path)
    with pytest.raises(UnknownRunError) as exc_info:
        logger.append("no-file", EventType.escalation, args={"reason": "x"})
    assert not isinstance(exc_info.value, CorruptChainError)
    with pytest.raises(UnknownRunError):
        logger.end_run("no-file", summary={})
    assert not (tmp_path / "no-file.jsonl").exists()


# --------------------------------------------------------------------------------------
# per-type validation
# --------------------------------------------------------------------------------------


def test_execution_without_tool_call_id_raises(tmp_path: Path) -> None:
    logger = AuditLogger(tmp_path)
    _start(logger, "run-A")
    with pytest.raises(ValidationError):
        logger.append(
            "run-A",
            EventType.execution,
            execution={
                "exit_code": 0,
                "duration_ms": 1,
                "stdout_sha256": "sha256:0",
                "stdout_excerpt": "",
                "truncated": False,
                "staged_files": [],
            },
        )


def test_execution_model_requires_tool_call_id_directly() -> None:
    with pytest.raises(ValidationError):
        AuditEvent(
            event_type=EventType.execution,
            run_id="run-A",
            principal=PRINCIPAL,
            environment=ENV,
            prev_hash=GENESIS_PREV_HASH,
            execution={
                "exit_code": 0,
                "duration_ms": 1,
                "stdout_sha256": "sha256:0",
                "stdout_excerpt": "",
                "truncated": False,
                "staged_files": [],
            },
        )


def test_decision_event_requires_decision_section() -> None:
    with pytest.raises(ValidationError):
        AuditEvent(
            event_type=EventType.decision,
            run_id="run-A",
            principal=PRINCIPAL,
            environment=ENV,
            prev_hash=GENESIS_PREV_HASH,
            tool_call_id="call_1",
        )


def test_run_completed_requires_summary() -> None:
    with pytest.raises(ValidationError):
        AuditEvent(
            event_type=EventType.run_completed,
            run_id="run-A",
            principal=PRINCIPAL,
            environment=ENV,
            prev_hash=GENESIS_PREV_HASH,
        )


# --------------------------------------------------------------------------------------
# lifecycle guards
# --------------------------------------------------------------------------------------


def test_append_to_unstarted_run_raises(tmp_path: Path) -> None:
    logger = AuditLogger(tmp_path)
    with pytest.raises(UnknownRunError):
        logger.append("never-started", EventType.escalation)


def test_end_unstarted_run_raises(tmp_path: Path) -> None:
    logger = AuditLogger(tmp_path)
    with pytest.raises(UnknownRunError):
        logger.end_run("never-started", summary={})


# --------------------------------------------------------------------------------------
# interleaved concurrent runs
# --------------------------------------------------------------------------------------


def test_interleaved_runs_verify_independently(tmp_path: Path) -> None:
    logger = AuditLogger(tmp_path)
    _start(logger, "run-A")
    _start(logger, "run-B")

    dec = {
        "effect": "allow",
        "rule_id": "R1",
        "reason": "x",
        "channel": "auto",
        "rewritten_argv": None,
    }
    logger.append("run-A", EventType.decision, tool_call_id="a1", decision=dec)
    logger.append("run-B", EventType.decision, tool_call_id="b1", decision=dec)
    logger.append("run-A", EventType.escalation, args={"reason": "A esc"})
    logger.append("run-B", EventType.escalation, args={"reason": "B esc"})
    logger.end_run("run-A", summary={"cost_usd": 0.0})
    logger.end_run("run-B", summary={"cost_usd": 0.0})

    results = verify_dir(tmp_path)
    assert set(results) == {"run-A", "run-B"}
    assert results["run-A"].ok is True
    assert results["run-B"].ok is True
    assert results["run-A"].events == 4  # seed + decision + escalation + completed
    assert results["run-B"].events == 4


# --------------------------------------------------------------------------------------
# ts monotonicity is warn-only
# --------------------------------------------------------------------------------------


def test_ts_regression_is_warn_only_not_failure(tmp_path: Path) -> None:
    """A backwards ts is surfaced as a warning but does not break the chain."""
    import json

    logger = AuditLogger(tmp_path)
    _start(logger, "run-A")
    logger.append("run-A", EventType.escalation, args={"reason": "x"})
    path = tmp_path / "run-A.jsonl"

    lines = path.read_text().splitlines()
    # rewrite the second event with an earlier ts, then re-chain it honestly so only
    # ts (not the hash) is "off" — verify must still pass but warn.
    from opendevops.audit import canonical_json, compute_event_hash

    ev = AuditEvent.model_validate(json.loads(lines[1]))
    seed = AuditEvent.model_validate(json.loads(lines[0]))
    ev = ev.model_copy(update={"ts": "2000-01-01T00:00:00.000000Z", "hash": ""})
    new_hash = compute_event_hash(seed.hash, ev)
    ev = ev.model_copy(update={"hash": new_hash})
    lines[1] = json.dumps(ev.model_dump(mode="json", exclude_none=True), separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")

    # sanity: the re-chained line is internally consistent
    assert canonical_json(ev)  # smoke
    result = verify_run_file(path)
    assert result.ok is True
    assert result.warnings  # ts regression surfaced


# --------------------------------------------------------------------------------------
# merged spool verification (T18): a Vector day-file interleaves many per-run chains
#
# Vector tails every per-run chain and MERGES them, verbatim and in append order, into one
# durable spool day-file. verify_merged_file regroups that interleaved stream by run_id and
# re-verifies each run's subsequence as an independent chain. These tests build a merged file
# by ROUND-ROBIN interleaving 2-3 real per-run chains (written by AuditLogger), which puts a
# foreign line between consecutive lines of every run — exactly the layout that makes the
# single-chain verify_run_file walker fail at the first foreign line.
# --------------------------------------------------------------------------------------


def _build_merged(tmp_path: Path, run_ids: list[str]) -> tuple[Path, dict[str, list[str]]]:
    """Write real per-run chains, then round-robin interleave their lines into one merged file."""
    src = tmp_path / "perrun"
    per_run_lines: dict[str, list[str]] = {}
    for run_id in run_ids:
        logger, path = _standard_chain(src, run_id)
        logger.end_run(run_id, summary={"cost_usd": 0.0})
        per_run_lines[run_id] = path.read_text().splitlines()

    queues = {run_id: list(lines) for run_id, lines in per_run_lines.items()}
    merged: list[str] = []
    while any(queues.values()):
        for run_id in run_ids:  # deterministic round-robin keeps within-run order intact
            if queues[run_id]:
                merged.append(queues[run_id].pop(0))

    spool = tmp_path / "spool"
    spool.mkdir()
    merged_path = spool / "audit-merged-2026-07-18.jsonl"
    merged_path.write_text("\n".join(merged) + "\n")
    return merged_path, per_run_lines


def test_merged_file_passes_and_reports_run_count(tmp_path: Path) -> None:
    merged_path, per_run_lines = _build_merged(tmp_path, ["run-A", "run-B", "run-C"])

    # The interleaved file is NOT a single linear chain: the single-chain walker fails on it.
    assert verify_run_file(merged_path).ok is False

    # …but the merged verifier regroups by run_id and passes, reporting the right run count.
    result = verify_merged_file(merged_path)
    assert result.ok is True
    assert result.runs == 3
    # each per-run chain is seed + decision + execution + escalation + run_completed = 5 events
    assert result.events == sum(len(v) for v in per_run_lines.values()) == 15
    assert set(result.per_run) == {"run-A", "run-B", "run-C"}
    assert all(r.ok for r in result.per_run.values())
    assert result.bad_run_id is None


def test_merged_file_tamper_in_one_run_fails_naming_that_run(tmp_path: Path) -> None:
    merged_path, _ = _build_merged(tmp_path, ["run-A", "run-B"])
    lines = merged_path.read_text().splitlines()

    # Mutate a byte inside run-B's decision event (its reason carries the MARKER token). Recompute
    # must catch it, and ONLY run-B's chain must be implicated.
    for i, line in enumerate(lines):
        if '"run_id":"run-B"' in line and "MARKER" in line:
            lines[i] = line.replace("MARKER", "MARKEX", 1)
            break
    else:  # pragma: no cover - guards the test's own precondition
        raise AssertionError("expected a run-B MARKER line in the merged file")
    merged_path.write_text("\n".join(lines) + "\n")

    result = verify_merged_file(merged_path)
    assert result.ok is False
    assert result.bad_run_id == "run-B"
    assert result.first_bad_line is not None
    assert result.per_run["run-B"].ok is False
    assert result.per_run["run-A"].ok is True  # the untampered run still verifies


def test_merged_file_interior_deletion_is_caught(tmp_path: Path) -> None:
    """Deleting a middle event of one run must fail (an interior chain break, not just a parse
    error): the event that followed it no longer links, and the merged verifier catches it."""
    merged_path, _ = _build_merged(tmp_path, ["run-A", "run-B"])
    lines = merged_path.read_text().splitlines()

    # Drop run-A's execution event (an INTERIOR line — run-A's escalation follows it).
    for i, line in enumerate(lines):
        if '"run_id":"run-A"' in line and '"event_type":"execution"' in line:
            del lines[i]
            break
    else:  # pragma: no cover - guards the test's own precondition
        raise AssertionError("expected a run-A execution line in the merged file")
    merged_path.write_text("\n".join(lines) + "\n")

    result = verify_merged_file(merged_path)
    assert result.ok is False
    assert result.bad_run_id == "run-A"
    assert result.per_run["run-A"].reason is not None
    assert result.per_run["run-B"].ok is True


def test_merged_file_unparseable_line_fails_file_level(tmp_path: Path) -> None:
    merged_path, _ = _build_merged(tmp_path, ["run-A", "run-B"])
    lines = merged_path.read_text().splitlines()
    lines[2] = lines[2][:-3]  # truncate -> invalid JSON
    merged_path.write_text("\n".join(lines) + "\n")

    result = verify_merged_file(merged_path)
    assert result.ok is False
    assert result.reason is not None and "unparseable" in result.reason
    assert result.first_bad_line == 3
    assert result.bad_run_id is None  # a file-level parse failure is not attributed to one run


def test_audit_verify_cli_auto_detects_merged_spool_dir(tmp_path: Path) -> None:
    """`opendevops audit verify --dir <spool>` (main) auto-detects the merged file and passes;
    tampering one run flips the exit code — the runbook's end-to-end check on a healthy stack no
    longer raises a false alarm."""
    merged_path, _ = _build_merged(tmp_path, ["run-A", "run-B"])
    spool_dir = merged_path.parent

    assert audit_verify_main(spool_dir) == 0  # healthy merged spool verifies

    lines = merged_path.read_text().splitlines()
    lines[0] = lines[0].replace("MARKER", "MARKEX", 1) if "MARKER" in lines[0] else lines[0][:-3]
    merged_path.write_text("\n".join(lines) + "\n")
    assert audit_verify_main(spool_dir) == 1  # a tampered merged spool fails


def test_audit_verify_cli_still_handles_per_run_dir(tmp_path: Path) -> None:
    """A plain per-run audit dir (one chain per file) is unaffected by the merged auto-detection."""
    logger, _ = _standard_chain(tmp_path, "run-solo")
    logger.end_run("run-solo", summary={"cost_usd": 0.0})
    assert audit_verify_main(tmp_path) == 0
