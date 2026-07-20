"""ops/maintenance.py — operator hygiene jobs + the escalation-timeout sweeper.

A typer app whose commands are each a thin fetch/side-effect wrapped around a PURE, unit-tested
computation (the computation is what CI exercises; the live I/O is never called in CI):

* ``prune-threads`` — delete LangGraph Server threads idle > N days. The set of threads to delete is
  chosen by :func:`select_idle_thread_ids` (pure); the command only lists + deletes.
* ``spend-report`` — mirror the daily counter's per-scope totals to stdout/JSON via
  :func:`render_spend_report` (pure).
* ``pg-dump`` — back up the server's Postgres. The argv is built by :func:`pg_dump_argv` (pure) and
  run with ``subprocess.run(argv, shell=False)`` — argv-only, **never** ``shell=True`` (no shell
  metacharacter surface), honoring the ambient environment (``PGPASSWORD`` / ``PGHOST`` / ...).
* ``sweep-escalations`` — the ESCALATION-TIMEOUT SWEEPER: the enforcement mechanism behind a
  rule's ``on_timeout: deny``. ``interrupt()`` parks an escalated run *indefinitely* and a
  caller-side cancel would leave NO resolution record, so this sweeper lists interrupted runs whose
  escalation age exceeds the rule's ``timeout_s`` (pure :func:`select_timed_out` over records the
  pure adapter :func:`interrupted_runs_from_threads` builds from ``threads.search``) and resumes
  each with ``{"decisions": [{"type": "reject", "message": "escalation timed out",
  "approver": "__timeout__"}]}``. That flows through the normal policy pipeline: the model receives
  the deny ToolMessage and a ``resolution`` audit event is written with ``approver="__timeout__"``.

Split — pure selection vs live resume
-------------------------------------
The sweeper's SELECTION is pure and directly unit-tested (:func:`select_timed_out`,
:func:`interrupted_runs_from_threads`, :func:`timeout_reject_decisions`), and the resume itself is
driven through a small ``resume`` callable shaped exactly like
:meth:`~opendevops.gateway.base.AgentGateway.resume_interrupt` (``(thread_id, decisions, *,
approver)``) — so a test can pass a stub OR a real ``LocalGateway`` (the strongest pin: a run
escalates, the sweeper resume-rejects it, and the ``resolution(approver=__timeout__)`` + deny
ToolMessage + verifying chain are asserted end-to-end). Only :func:`sweep_timed_out_escalations`
(the ``threads.search`` + ``runs.wait`` I/O over the sdk) is a live seam.

SDK-firewall exception (deliberate, documented)
-----------------------------------------------
:class:`~opendevops.gateway.server.ServerGateway` is normally the *only* module allowed to import
``langgraph_sdk`` (the compatibility firewall). ``prune-threads`` needs ``threads.search`` /
``threads.delete`` and the sweeper needs ``threads.search`` / ``runs.wait``, none of which are on
the transport-neutral :class:`AgentGateway` protocol. Rather than widen that protocol for ops-only
jobs, this module imports ``langgraph_sdk`` **directly** and is called out here as the sanctioned
ops-tool exception: it is not part of the shipped agent, runs out-of-band by an operator/scheduler,
and a FastAPI-embedded fallback would re-point ``_build_client`` without touching the agent. A
never-prune guard protects ``busy`` / ``interrupted`` threads so a pending escalation is never
dropped by hygiene.
"""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import typer

app = typer.Typer(
    name="maintenance",
    help="opendevops service-stack hygiene jobs.",
    no_args_is_help=True,
    add_completion=False,
)

# Threads in these states are never pruned by hygiene: a ``busy`` run is in flight and an
# ``interrupted`` one holds a PENDING ESCALATION awaiting an approver — deleting it would silently
# drop a human-in-the-loop decision.
_PROTECTED_STATUSES: frozenset[str] = frozenset({"busy", "interrupted"})


# --------------------------------------------------------------------------------------
# pure computations (unit-tested; no I/O)
# --------------------------------------------------------------------------------------


def _parse_ts(value: Any) -> datetime | None:
    """Parse a thread timestamp (ISO-8601 str, possibly ``Z``-suffixed) to an aware datetime.

    Returns ``None`` for anything unparseable so the caller can conservatively SKIP a thread it
    cannot date (never prune what we cannot prove is old).
    """
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def select_idle_thread_ids(
    threads: list[dict[str, Any]], *, now: datetime, older_than_days: float
) -> list[str]:
    """Return the ids of threads last touched more than ``older_than_days`` before ``now``.

    Pure. ``updated_at`` (fallback ``created_at``) dates the thread; a thread with no parseable
    timestamp, or whose ``status`` is protected (``busy`` / ``interrupted``), is left alone —
    hygiene must never race a live run or drop a pending escalation.
    """
    cutoff = now - timedelta(days=older_than_days)
    idle: list[str] = []
    for thread in threads:
        if thread.get("status") in _PROTECTED_STATUSES:
            continue
        when = _parse_ts(thread.get("updated_at") or thread.get("created_at"))
        if when is None:
            continue
        if when < cutoff:
            thread_id = thread.get("thread_id")
            if thread_id is not None:
                idle.append(str(thread_id))
    return idle


@dataclass(frozen=True)
class SpendRow:
    """One scope's daily spend vs its cap."""

    scope: str
    spent: float
    cap: float

    @property
    def fraction(self) -> float:
        return self.spent / self.cap if self.cap > 0 else 0.0


def build_spend_rows(
    totals: dict[str, float], *, global_cap: float, principal_cap: float
) -> list[SpendRow]:
    """Pair each scope's total with the cap governing it (``global`` vs ``principal:*``). Pure."""
    rows: list[SpendRow] = []
    for scope in sorted(totals):
        cap = global_cap if scope == "global" else principal_cap
        rows.append(SpendRow(scope=scope, spent=totals[scope], cap=cap))
    return rows


def render_spend_report(rows: list[SpendRow], *, as_json: bool) -> str:
    """Render spend rows as a JSON document or an aligned text table. Pure."""
    if as_json:
        payload = [
            {
                "scope": r.scope,
                "spent_usd": round(r.spent, 6),
                "cap_usd": r.cap,
                "fraction": round(r.fraction, 4),
            }
            for r in rows
        ]
        return json.dumps(payload, indent=2)
    if not rows:
        return "(no spend recorded today)"
    width = max(len(r.scope) for r in rows)
    lines = [
        f"{r.scope:<{width}}  ${r.spent:8.4f} / ${r.cap:7.2f}  ({r.fraction * 100:5.1f}%)"
        for r in rows
    ]
    return "\n".join(lines)


def pg_dump_argv(database_uri: str, out_path: str, *, fmt: str = "custom") -> list[str]:
    """Build the ``pg_dump`` argv (argv-only — never a shell string). Pure.

    ``--format custom`` (compressed, restorable with ``pg_restore``); ``--no-owner`` /
    ``--no-privileges`` keep the dump portable across roles. The database URI carries host/db/user;
    the password comes from the environment (``PGPASSWORD``), never argv.
    """
    return [
        "pg_dump",
        "--dbname",
        database_uri,
        "--format",
        fmt,
        "--no-owner",
        "--no-privileges",
        "--file",
        out_path,
    ]


# --------------------------------------------------------------------------------------
# escalation-timeout sweeper — pure selection (unit-tested; no I/O)
# --------------------------------------------------------------------------------------

# The synthetic approver stamped on a timed-out resolution, so the audit chain records that the
# TIMEOUT (not a human) rejected the escalation. The middleware reads ``decision["approver"]``.
TIMEOUT_APPROVER = "__timeout__"
# The reject message the model sees in the deny ToolMessage and the resolution event records.
TIMEOUT_MESSAGE = "escalation timed out"

# The resume-callable shape the sweeper drives — identical to ``AgentGateway.resume_interrupt``:
# ``async (thread_id, decisions, *, approver) -> <run result>``. A stub OR a real gateway fits.
ResumeFn = Callable[..., Awaitable[Any]]


@dataclass(frozen=True)
class InterruptedRun:
    """One interrupted run's escalation facts, enough to decide + resume it.

    * ``thread_id`` — the suspended thread the resume targets.
    * ``rule_id`` — the escalate rule that suspended it (audit/diagnostic; not used by selection).
    * ``timeout_s`` — the rule's ``on_timeout`` deadline; ``None`` when it could not be read.
    * ``escalation_ts`` — when the run suspended (the escalation age is ``now - escalation_ts``);
      ``None`` when the thread had no parseable timestamp.
    * ``run_id`` — the correlation id, when known (diagnostic).
    """

    thread_id: str
    rule_id: str | None
    timeout_s: int | None
    escalation_ts: datetime | None
    run_id: str | None = None


def timeout_reject_decisions() -> list[dict[str, str]]:
    """The reject decision the sweeper resumes a timed-out escalation with (pure).

    ``approver`` is injected by the resume callable (the gateway does it; the sdk seam does it
    explicitly), so this carries only ``type`` + ``message`` — mirroring the human reject shape.
    """
    return [{"type": "reject", "message": TIMEOUT_MESSAGE}]


def select_timed_out(
    runs: list[InterruptedRun], *, now: datetime
) -> list[InterruptedRun]:
    """Return the interrupted runs whose escalation age exceeds their rule's ``timeout_s``. Pure.

    Fail-safe (never resume-reject a run we cannot PROVE is timed out): a run missing ``timeout_s``
    or ``escalation_ts`` (an undateable thread, or one whose escalation payload could not be read —
    shouldn't happen for a real interrupt) is SKIPPED. Selection is strictly greater-than, so a run
    exactly at its deadline is not yet timed out.
    """
    timed_out: list[InterruptedRun] = []
    for run in runs:
        if run.timeout_s is None or run.escalation_ts is None:
            continue
        age_s = (now - run.escalation_ts).total_seconds()
        if age_s > run.timeout_s:
            timed_out.append(run)
    return timed_out


def _iter_interrupt_values(interrupts: Any) -> list[Any]:
    """Yield each interrupt's ``value`` payload from a ``threads.search`` thread's ``interrupts``.

    ``interrupts`` is a ``{interrupt_id: [interrupt, ...]}`` map (or, defensively, a plain list) of
    interrupt objects each shaped ``{"value": <payload>, ...}``. Returns the payloads, tolerating
    either container and a bare payload.
    """
    groups: list[Any]
    if isinstance(interrupts, dict):
        groups = list(interrupts.values())
    elif isinstance(interrupts, list):
        groups = [interrupts]
    else:
        return []
    values: list[Any] = []
    for group in groups:
        items = group if isinstance(group, list) else [group]
        for item in items:
            if isinstance(item, dict) and "value" in item:
                values.append(item["value"])
            else:
                values.append(item)
    return values


def _first_review_config(value: Any) -> dict[str, Any] | None:
    """The first ``review_configs`` entry from an escalation interrupt payload, or ``None``."""
    if not isinstance(value, dict):
        return None
    configs = value.get("review_configs")
    if isinstance(configs, list) and configs and isinstance(configs[0], dict):
        return configs[0]
    return None


def _thread_run_id(thread: dict[str, Any]) -> str | None:
    """The correlation ``run_id`` a run stamped into thread ``metadata``, if present."""
    metadata = thread.get("metadata")
    if isinstance(metadata, dict) and metadata.get("run_id"):
        return str(metadata["run_id"])
    return None


def interrupted_runs_from_threads(threads: list[dict[str, Any]]) -> list[InterruptedRun]:
    """Adapt ``threads.search(status="interrupted")`` results to :class:`InterruptedRun`. Pure.

    The escalate rule's ``rule_id`` / ``timeout_s`` come from the thread's pending interrupt payload
    (the middleware's ``review_configs[0]``); the escalation age is dated from ``updated_at``
    (fallback ``created_at``) — the suspend was the last thing to touch the thread. A thread with no
    id is skipped; missing/unparseable fields become ``None`` (and :func:`select_timed_out` then
    conservatively skips that run).
    """
    runs: list[InterruptedRun] = []
    for thread in threads:
        thread_id = thread.get("thread_id")
        if thread_id is None:
            continue
        rule_id: str | None = None
        timeout_s: int | None = None
        for value in _iter_interrupt_values(thread.get("interrupts")):
            review = _first_review_config(value)
            if review is not None:
                rid = review.get("rule_id")
                rule_id = str(rid) if rid is not None else None
                raw_timeout = review.get("timeout_s")
                timeout_s = int(raw_timeout) if isinstance(raw_timeout, int) else None
                break
        runs.append(
            InterruptedRun(
                thread_id=str(thread_id),
                rule_id=rule_id,
                timeout_s=timeout_s,
                escalation_ts=_parse_ts(thread.get("updated_at") or thread.get("created_at")),
                run_id=_thread_run_id(thread),
            )
        )
    return runs


async def resume_timed_out(resume: ResumeFn, runs: list[InterruptedRun]) -> list[str]:
    """Resume each run in ``runs`` with the timeout reject decision (``approver="__timeout__"``).

    ``resume`` is any awaitable shaped like ``AgentGateway.resume_interrupt`` — the strongest test
    passes a real ``LocalGateway.resume_interrupt`` so the whole policy pipeline runs; production
    passes the sdk-backed :func:`_sdk_resume_fn`. Returns the thread ids resumed, in order. A resume
    that raises propagates (the caller decides whether to continue the sweep) — the SELECTION above
    already guaranteed each target is genuinely timed out.
    """
    resumed: list[str] = []
    for run in runs:
        await resume(run.thread_id, timeout_reject_decisions(), approver=TIMEOUT_APPROVER)
        resumed.append(run.thread_id)
    return resumed


# --------------------------------------------------------------------------------------
# live seams (thin; not exercised in CI)
# --------------------------------------------------------------------------------------


def _build_client(url: str, api_key_env: str | None) -> Any:  # pragma: no cover - live seam
    """Build a ``langgraph_sdk`` async client (the documented SDK-firewall exception)."""
    from langgraph_sdk import get_client

    api_key = os.environ.get(api_key_env) if api_key_env else None
    return get_client(url=url, api_key=api_key)


def _load_config(config_root: str | None) -> Any:  # pragma: no cover - live seam
    from pathlib import Path

    from opendevops.config import load_config

    return load_config(Path(config_root) if config_root is not None else None)


def _sdk_resume_fn(client: Any, assistant_id: str) -> ResumeFn:  # pragma: no cover - live seam
    """A :data:`ResumeFn` that resumes a server run via ``runs.wait`` with a ``resume`` command.

    Injects ``approver`` into each decision (as both gateways do) and delivers exactly
    ``{"decisions": [...]}`` to the graph's ``interrupt()`` — the shape ``PolicyMiddleware`` reads.
    """

    async def _resume(thread_id: str, decisions: list[dict[str, Any]], *, approver: str) -> Any:
        injected = [{**d, "approver": approver} for d in decisions]
        return await client.runs.wait(
            thread_id, assistant_id, command={"resume": {"decisions": injected}}
        )

    return _resume


async def sweep_timed_out_escalations(  # pragma: no cover - live orchestration over pure selection
    client: Any,
    *,
    assistant_id: str = "devops",
    now: datetime | None = None,
    limit: int = 1000,
    dry_run: bool = True,
) -> list[InterruptedRun]:
    """List interrupted runs, select timed-out ones, and (unless ``dry_run``) resume-reject them.

    The live seam over the SDK-firewall exception: ``threads.search(status="interrupted")`` lists,
    the pure :func:`interrupted_runs_from_threads` + :func:`select_timed_out` decide, and
    :func:`resume_timed_out` over :func:`_sdk_resume_fn` drives the resume. Returns the selected
    (timed-out) runs so the caller can report them.
    """
    threads = await client.threads.search(status="interrupted", limit=limit)
    victims = select_timed_out(
        interrupted_runs_from_threads(threads), now=now or datetime.now(UTC)
    )
    if not dry_run:
        await resume_timed_out(_sdk_resume_fn(client, assistant_id), victims)
    return victims


# --------------------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------------------


@app.command("prune-threads")
def prune_threads(  # pragma: no cover - live orchestration over the pure selector
    url: str = typer.Option(..., help="LangGraph Server base URL."),
    older_than_days: float = typer.Option(30.0, help="Delete threads idle longer than this."),
    api_key_env: str | None = typer.Option(None, help="Env var holding the server API key."),
    limit: int = typer.Option(
        1000,
        help="Max threads to scan in ONE call (a single page — no pagination). If more idle "
        "threads exist beyond this, they are simply not pruned this run: under-prunes only, the "
        "safe direction. Raise it (or re-run) to reach the rest.",
    ),
    dry_run: bool = typer.Option(True, help="List what would be deleted without deleting."),
) -> None:
    """Delete LangGraph Server threads idle beyond ``--older-than-days`` (protects live runs)."""
    import asyncio

    async def _run() -> None:
        client = _build_client(url, api_key_env)
        try:
            threads = await client.threads.search(limit=limit)
            victims = select_idle_thread_ids(
                threads, now=datetime.now(UTC), older_than_days=older_than_days
            )
            typer.echo(f"{len(victims)} idle thread(s) selected (of {len(threads)} scanned)")
            for thread_id in victims:
                if dry_run:
                    typer.echo(f"  would delete {thread_id}")
                else:
                    await client.threads.delete(thread_id)
                    typer.echo(f"  deleted {thread_id}")
        finally:
            await client.aclose()

    asyncio.run(_run())


@app.command("spend-report")
def spend_report(  # pragma: no cover - live orchestration over the pure renderer
    config_root: str | None = typer.Option(None, help="Project root with config/ (default: cwd)."),
    principal: list[str] | None = typer.Option(  # noqa: B008 - typer.Option belongs in the default
        None, help="Principal scopes to include (repeatable)."
    ),
    as_json: bool = typer.Option(False, "--json", help="Emit JSON instead of a table."),
) -> None:
    """Mirror the daily counter's per-scope totals (global + named principals) to stdout."""
    import asyncio

    from opendevops.budget.daily import build_daily_counter

    async def _run() -> None:
        cfg = _load_config(config_root)
        counter = build_daily_counter(cfg)
        scopes = ["global", *(f"principal:{p}" for p in (principal or []))]
        totals = {scope: await counter.total(scope) for scope in scopes}
        rows = build_spend_rows(
            totals,
            global_cap=cfg.budgets.daily.global_usd,
            principal_cap=cfg.budgets.daily.per_principal_usd,
        )
        typer.echo(render_spend_report(rows, as_json=as_json))

    asyncio.run(_run())


@app.command("pg-dump")
def pg_dump(  # pragma: no cover - subprocess side effect over the pure argv builder
    database_uri: str = typer.Option(..., help="Postgres URI (password via PGPASSWORD env)."),
    out_path: str = typer.Option(..., help="Output file for the dump."),
    fmt: str = typer.Option("custom", help="pg_dump --format (custom|plain|directory|tar)."),
) -> None:
    """Back up the server's Postgres with ``pg_dump`` — argv-only, never a shell string."""
    argv = pg_dump_argv(database_uri, out_path, fmt=fmt)
    # shell=False (default): argv is passed to execve directly, so no shell metacharacter surface.
    result = subprocess.run(argv, env=os.environ.copy(), check=False)  # noqa: S603
    if result.returncode != 0:
        raise typer.Exit(code=result.returncode)
    typer.echo(f"wrote {out_path}")


@app.command("sweep-escalations")
def sweep_escalations(  # pragma: no cover - live orchestration over the pure selector
    url: str = typer.Option(..., help="LangGraph Server base URL."),
    api_key_env: str | None = typer.Option(None, help="Env var holding the server API key."),
    assistant_id: str = typer.Option("devops", help="Graph id to resume (langgraph.json)."),
    limit: int = typer.Option(1000, help="Max interrupted threads to scan in ONE call."),
    dry_run: bool = typer.Option(
        True, help="List timed-out escalations without resume-rejecting them."
    ),
) -> None:
    """Resolve timed-out escalations: resume-reject each with approver=__timeout__ (on_timeout)."""
    import asyncio

    async def _run() -> None:
        client = _build_client(url, api_key_env)
        try:
            victims = await sweep_timed_out_escalations(
                client, assistant_id=assistant_id, limit=limit, dry_run=dry_run
            )
            verb = "would resume-reject" if dry_run else "resume-rejected"
            typer.echo(f"{len(victims)} timed-out escalation(s) {verb}")
            for run in victims:
                typer.echo(f"  {run.thread_id} (rule={run.rule_id}, timeout_s={run.timeout_s})")
        finally:
            await client.aclose()

    asyncio.run(_run())


if __name__ == "__main__":  # pragma: no cover
    app()
