"""ops/maintenance.py pure computations: idle-thread filtering, spend rows, pg_dump argv.

Only the pure functions are exercised — the live ``langgraph_sdk`` / subprocess seams are never
called in CI (faked responses / argv inspection). Idle-thread filtering is the brief's named case.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from ops.maintenance import (
    TIMEOUT_APPROVER,
    TIMEOUT_MESSAGE,
    InterruptedRun,
    SpendRow,
    build_spend_rows,
    interrupted_runs_from_threads,
    pg_dump_argv,
    render_spend_report,
    resume_timed_out,
    select_idle_thread_ids,
    select_timed_out,
    timeout_reject_decisions,
)

NOW = datetime(2026, 7, 19, 12, 0, 0, tzinfo=UTC)


def _thread(thread_id: str, updated_at: str | None, **extra: object) -> dict[str, object]:
    t: dict[str, object] = {"thread_id": thread_id}
    if updated_at is not None:
        t["updated_at"] = updated_at
    t.update(extra)
    return t


# --------------------------------------------------------------------------------------
# select_idle_thread_ids — the named "idle-thread filtering" case
# --------------------------------------------------------------------------------------


def test_selects_only_threads_older_than_cutoff() -> None:
    threads = [
        _thread("old", "2026-06-01T00:00:00+00:00"),   # ~48d old -> idle
        _thread("recent", "2026-07-18T00:00:00+00:00"),  # ~1.5d old -> keep
        _thread("edge", "2026-06-19T12:00:00+00:00"),   # exactly 30d -> not strictly older -> keep
    ]
    idle = select_idle_thread_ids(threads, now=NOW, older_than_days=30)
    assert idle == ["old"]


def test_protects_busy_and_interrupted_threads_even_if_old() -> None:
    """A busy run / a pending-escalation (interrupted) thread must never be pruned by hygiene."""
    threads = [
        _thread("old-busy", "2026-01-01T00:00:00+00:00", status="busy"),
        _thread("old-interrupted", "2026-01-01T00:00:00+00:00", status="interrupted"),
        _thread("old-idle", "2026-01-01T00:00:00+00:00", status="idle"),
    ]
    idle = select_idle_thread_ids(threads, now=NOW, older_than_days=30)
    assert idle == ["old-idle"]


def test_skips_threads_with_no_parseable_timestamp() -> None:
    """A thread we cannot date is left alone — never prune what we cannot prove is old."""
    threads = [
        _thread("no-ts", None),
        _thread("bad-ts", "not-a-date"),
        _thread("old", "2026-01-01T00:00:00+00:00"),
    ]
    assert select_idle_thread_ids(threads, now=NOW, older_than_days=30) == ["old"]


def test_falls_back_to_created_at_when_no_updated_at() -> None:
    threads = [{"thread_id": "c", "created_at": "2026-01-01T00:00:00+00:00"}]
    assert select_idle_thread_ids(threads, now=NOW, older_than_days=30) == ["c"]


def test_handles_z_suffixed_and_naive_timestamps() -> None:
    threads = [
        _thread("z", "2026-01-01T00:00:00Z"),       # Z suffix
        _thread("naive", "2026-01-01T00:00:00"),    # no tzinfo -> treated as UTC
    ]
    assert set(select_idle_thread_ids(threads, now=NOW, older_than_days=30)) == {"z", "naive"}


# --------------------------------------------------------------------------------------
# spend rows + report rendering
# --------------------------------------------------------------------------------------


def test_build_spend_rows_pairs_scope_with_governing_cap() -> None:
    rows = build_spend_rows(
        {"global": 40.0, "principal:alice": 10.0},
        global_cap=50.0,
        principal_cap=25.0,
    )
    by_scope = {r.scope: r for r in rows}
    assert by_scope["global"].cap == 50.0
    assert by_scope["principal:alice"].cap == 25.0
    assert by_scope["global"].fraction == 0.8


def test_render_spend_report_json() -> None:
    rows = [SpendRow(scope="global", spent=40.0, cap=50.0)]
    out = json.loads(render_spend_report(rows, as_json=True))
    assert out == [{"scope": "global", "spent_usd": 40.0, "cap_usd": 50.0, "fraction": 0.8}]


def test_render_spend_report_text_contains_scope_and_pct() -> None:
    rows = [SpendRow(scope="global", spent=40.0, cap=50.0)]
    text = render_spend_report(rows, as_json=False)
    assert "global" in text
    assert "80.0%" in text


def test_render_spend_report_empty() -> None:
    assert "no spend" in render_spend_report([], as_json=False)


# --------------------------------------------------------------------------------------
# pg_dump argv (argv-only, never shell)
# --------------------------------------------------------------------------------------


def test_pg_dump_argv_is_a_list_with_expected_flags() -> None:
    argv = pg_dump_argv("postgres://u@h:5432/db", "/backup/db.dump")
    assert argv[0] == "pg_dump"
    assert "--dbname" in argv and "postgres://u@h:5432/db" in argv
    assert "--file" in argv and "/backup/db.dump" in argv
    assert "--format" in argv and "custom" in argv
    # No shell metacharacters / no single joined string — argv is a proper list of tokens.
    assert all(isinstance(tok, str) for tok in argv)
    assert not any(";" in tok or "|" in tok or "&&" in tok for tok in argv)


def test_pg_dump_argv_honors_format() -> None:
    argv = pg_dump_argv("postgres://u@h/db", "/out", fmt="plain")
    assert argv[argv.index("--format") + 1] == "plain"


# --------------------------------------------------------------------------------------
# escalation-timeout sweeper — pure selection (the named cases)
# --------------------------------------------------------------------------------------


def _run(
    thread_id: str,
    *,
    timeout_s: int | None,
    escalation_ts: datetime | None,
    rule_id: str | None = "kubectl-delete-workload-escalate",
) -> InterruptedRun:
    return InterruptedRun(
        thread_id=thread_id, rule_id=rule_id, timeout_s=timeout_s, escalation_ts=escalation_ts
    )


def test_select_timed_out_picks_only_past_timeout() -> None:
    runs = [
        _run("old", timeout_s=1800, escalation_ts=NOW - timedelta(seconds=1801)),  # timed out
        _run("fresh", timeout_s=1800, escalation_ts=NOW - timedelta(seconds=60)),  # within timeout
        _run("edge", timeout_s=1800, escalation_ts=NOW - timedelta(seconds=1800)),  # exactly: skip
    ]
    assert [r.thread_id for r in select_timed_out(runs, now=NOW)] == ["old"]


def test_select_timed_out_skips_run_with_no_escalation_payload() -> None:
    """An interrupted run whose timeout_s could not be read (shouldn't happen) is left alone."""
    runs = [_run("no-timeout", timeout_s=None, escalation_ts=NOW - timedelta(days=1))]
    assert select_timed_out(runs, now=NOW) == []


def test_select_timed_out_skips_undateable_run() -> None:
    """Fail-safe: never resume-reject a run we cannot prove is timed out (no escalation_ts)."""
    runs = [_run("undateable", timeout_s=1800, escalation_ts=None)]
    assert select_timed_out(runs, now=NOW) == []


# --------------------------------------------------------------------------------------
# sweeper — pure adapter from threads.search results
# --------------------------------------------------------------------------------------


def _interrupt_payload(rule_id: str, timeout_s: int) -> dict:
    """The middleware's interrupt payload shape (review_configs[0] carries rule_id + timeout_s)."""
    return {
        "action_requests": [{"action": "run_command", "args": {"argv": ["kubectl", "delete"]}}],
        "review_configs": [
            {
                "rule_id": rule_id,
                "reason": "destructive",
                "allowed_decisions": ["approve", "edit", "reject"],
                "timeout_s": timeout_s,
            }
        ],
    }


def test_interrupted_runs_from_threads_reads_rule_timeout_and_ts() -> None:
    payload = _interrupt_payload("kubectl-delete-workload-escalate", 1800)
    threads = [
        {
            "thread_id": "t1",
            "status": "interrupted",
            "updated_at": "2026-07-19T11:00:00Z",
            "interrupts": {"ns:0": [{"value": payload, "id": "i1"}]},
            "metadata": {"run_id": "run-xyz"},
        }
    ]
    runs = interrupted_runs_from_threads(threads)
    assert len(runs) == 1
    run = runs[0]
    assert run.thread_id == "t1"
    assert run.rule_id == "kubectl-delete-workload-escalate"
    assert run.timeout_s == 1800
    assert run.run_id == "run-xyz"
    assert run.escalation_ts == datetime(2026, 7, 19, 11, 0, 0, tzinfo=UTC)
    # It IS timed out at NOW (2026-07-19 12:00) since 3600s > 1800s.
    assert [r.thread_id for r in select_timed_out(runs, now=NOW)] == ["t1"]


def test_interrupted_runs_from_threads_skips_thread_without_id() -> None:
    assert interrupted_runs_from_threads([{"status": "interrupted"}]) == []


def test_interrupted_runs_from_threads_missing_interrupts_yields_none_timeout() -> None:
    runs = interrupted_runs_from_threads([{"thread_id": "t", "updated_at": "2026-07-19T11:00:00Z"}])
    assert runs[0].timeout_s is None
    # ...and that run is therefore conservatively skipped by selection.
    assert select_timed_out(runs, now=NOW) == []


# --------------------------------------------------------------------------------------
# sweeper — resume-reject wiring (approver=__timeout__, message, reject decision)
# --------------------------------------------------------------------------------------


async def test_timeout_reject_decisions_shape() -> None:
    assert timeout_reject_decisions() == [{"type": "reject", "message": "escalation timed out"}]
    assert TIMEOUT_MESSAGE == "escalation timed out"
    assert TIMEOUT_APPROVER == "__timeout__"


async def test_resume_timed_out_calls_resume_with_reject_and_timeout_approver() -> None:
    calls: list[dict] = []

    async def spy_resume(thread_id: str, decisions: list[dict], *, approver: str) -> str:
        calls.append({"thread_id": thread_id, "decisions": decisions, "approver": approver})
        return "resumed"

    runs = [
        _run("t1", timeout_s=1800, escalation_ts=NOW - timedelta(hours=2)),
        _run("t2", timeout_s=1800, escalation_ts=NOW - timedelta(hours=2)),
    ]
    resumed = await resume_timed_out(spy_resume, runs)

    assert resumed == ["t1", "t2"]
    assert [c["thread_id"] for c in calls] == ["t1", "t2"]
    for call in calls:
        assert call["approver"] == "__timeout__"
        assert call["decisions"] == [{"type": "reject", "message": "escalation timed out"}]
