"""``SchedulerService`` — our own APScheduler service that drives scheduled agent runs (P4, T20).

Why our own scheduler and not LangGraph Server crons: PLAN §3.7 — it removes the server-license
dependency and unifies cron + event triggers under one mechanism. The service is deliberately THIN;
all the interesting, order-dependent logic (job-spec parsing + the fixed-default application) lives
in the PURE :mod:`opendevops.interfaces.scheduler.jobs` module, and the per-job execution below is
directly unit-testable with a stub gateway.

Per job execution
-----------------
* a ``command`` job → a fresh thread (``gateway.create_thread()``) then
  ``gateway.run(..., profile="scheduled", interface="scheduled", environment=<job env>)`` wrapped in
  a caller-side ``asyncio.wait_for`` at the job's ``timeout_s``. The gateway's own wall-clock also
  bounds the run — the caller-side timer is the scheduled-run **belt**: on timeout we cancel the
  thread and RECORD a ``timeout`` outcome (never swallow it).
* a ``job_type`` job → a registered non-agent runner (``hygiene`` mirrors ``ops/maintenance.py``,
  ``escalation-sweep`` runs the timeout sweeper). Same caller-side timeout + outcome recording.

Every job run produces a :class:`JobOutcome` that the scheduled callable LOGS (a failed or
timed-out scheduled job must leave a trace, not vanish). ``run_job`` never raises — a job runner
crash becomes an ``error`` outcome so one bad job never tears down the scheduler loop.

The live APScheduler wiring (:meth:`start`, ``add_job``, the coroutine job callable) is a thin seam:
the pure defaults it applies are asserted via
:func:`~opendevops.interfaces.scheduler.jobs.scheduler_job_kwargs`.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

from opendevops.interfaces.scheduler.jobs import JobSpec, scheduler_job_kwargs

if TYPE_CHECKING:
    from opendevops.gateway.base import AgentGateway

logger = logging.getLogger(__name__)

# The budget profile + audit interface tag every scheduled run carries. ``"scheduled"`` is already
# a T14 ``context.Interface`` literal and a shipped ``budgets.yaml`` profile.
SCHEDULED_PROFILE = "scheduled"
SCHEDULED_INTERFACE = "scheduled"
# The synthetic principal a scheduled run is attributed to (audit ``principal.user`` + the
# per-principal daily budget scope). Not a human — the scheduler acts on its own behalf.
DEFAULT_SCHEDULED_PRINCIPAL = "scheduler"

# A job_type runner: an async callable taking the JobSpec, doing its side effect, returning nothing.
JobTypeRunner = Callable[[JobSpec], Awaitable[Any]]

JobStatus = Literal["ok", "escalated", "timeout", "error"]


@dataclass
class JobOutcome:
    """The recorded result of one job run (logged by the scheduled callable; never swallowed).

    * ``ok`` — the job completed. For a ``command`` job ``run_id`` is the run it drove.
    * ``escalated`` — a ``command`` run SUSPENDED on a policy escalation (parked for the sweeper).
    * ``timeout`` — the job exceeded its ``timeout_s`` and was cancelled.
    * ``error`` — the job runner raised (captured, not propagated).
    """

    job_id: str
    status: JobStatus
    thread_id: str | None = None
    run_id: str | None = None
    error: str | None = None


class SchedulerService:
    """Drive a set of :class:`JobSpec`\\ s on an ``AsyncIOScheduler`` over an :class:`AgentGateway`.

    Args:
        gateway: the :class:`~opendevops.gateway.base.AgentGateway` a ``command`` job runs on.
        specs: the validated job specs (from
            :func:`~opendevops.interfaces.scheduler.jobs.load_jobs`).
        job_types: optional map of ``job_type`` name -> async runner for the non-agent jobs
            (``hygiene`` / ``escalation-sweep``). A spec naming an unregistered job_type yields an
            ``error`` outcome rather than crashing.
        principal: the principal scheduled runs are attributed to (default ``"scheduler"``).
        scheduler: an optional pre-built ``AsyncIOScheduler`` (the test/live seam); ``start`` builds
            a UTC one when omitted.
    """

    def __init__(
        self,
        gateway: AgentGateway,
        specs: list[JobSpec],
        *,
        job_types: dict[str, JobTypeRunner] | None = None,
        principal: str = DEFAULT_SCHEDULED_PRINCIPAL,
        scheduler: Any = None,
    ) -> None:
        self._gateway = gateway
        self._specs = specs
        self._job_types = dict(job_types or {})
        self._principal = principal
        self._scheduler = scheduler

    # -- per-job execution (pure orchestration over the gateway; directly unit-tested) --------

    async def run_job(self, spec: JobSpec) -> JobOutcome:
        """Run one job to an outcome. Never raises — a failure becomes an ``error`` outcome."""
        if spec.job_type is not None:
            return await self._run_job_type(spec)
        return await self._run_command_job(spec)

    async def _run_command_job(self, spec: JobSpec) -> JobOutcome:
        """A fresh thread + a scheduled ``gateway.run`` bounded by the caller-side ``timeout_s``."""
        thread_id = await self._gateway.create_thread()
        assert spec.command is not None  # guaranteed by JobSpec validation
        try:
            result = await asyncio.wait_for(
                self._gateway.run(
                    thread_id,
                    spec.command,
                    profile=SCHEDULED_PROFILE,
                    principal=self._principal,
                    interface=SCHEDULED_INTERFACE,
                    environment=spec.environment,
                ),
                timeout=spec.timeout_s,
            )
        except TimeoutError:
            # The caller-side belt fired: cancel the in-flight run and RECORD the timeout.
            await self._gateway.cancel(thread_id)
            return JobOutcome(
                job_id=spec.id,
                status="timeout",
                thread_id=thread_id,
                error=f"exceeded timeout_s={spec.timeout_s}",
            )
        except Exception as exc:  # noqa: BLE001 - one bad job must not tear down the scheduler loop
            logger.exception("scheduled command job %r failed", spec.id)
            return JobOutcome(job_id=spec.id, status="error", thread_id=thread_id, error=str(exc))

        status: JobStatus = "escalated" if result.interrupted is not None else "ok"
        return JobOutcome(
            job_id=spec.id,
            status=status,
            thread_id=thread_id,
            run_id=result.run_id,
            error=result.error,
        )

    async def _run_job_type(self, spec: JobSpec) -> JobOutcome:
        """Dispatch a ``job_type`` job to its registered runner, bounded by ``timeout_s``."""
        runner = self._job_types.get(spec.job_type or "")
        if runner is None:
            logger.error("scheduled job %r names unknown job_type %r", spec.id, spec.job_type)
            return JobOutcome(
                job_id=spec.id, status="error", error=f"unknown job_type {spec.job_type!r}"
            )
        try:
            await asyncio.wait_for(runner(spec), timeout=spec.timeout_s)
        except TimeoutError:
            return JobOutcome(
                job_id=spec.id, status="timeout", error=f"exceeded timeout_s={spec.timeout_s}"
            )
        except Exception as exc:  # noqa: BLE001 - capture, never propagate into the scheduler loop
            logger.exception("scheduled job_type job %r failed", spec.id)
            return JobOutcome(job_id=spec.id, status="error", error=str(exc))
        return JobOutcome(job_id=spec.id, status="ok")

    # -- live APScheduler wiring (thin seam; the applied defaults are asserted purely) --------

    def start(self) -> Any:  # pragma: no cover - live APScheduler wiring
        """Build (if needed) the ``AsyncIOScheduler``, register every job, and start it.

        Must be called with a running asyncio event loop (``AsyncIOScheduler`` binds to it). Each
        job is registered with :func:`scheduler_job_kwargs` (the FIXED knobs + 60s jitter) and a
        coroutine callable that runs the job and logs its outcome.
        """
        from apscheduler.schedulers.asyncio import AsyncIOScheduler

        scheduler = self._scheduler
        if scheduler is None:
            scheduler = AsyncIOScheduler(timezone="UTC")
        for spec in self._specs:
            scheduler.add_job(self._job_callable(spec), **scheduler_job_kwargs(spec))
        scheduler.start()
        self._scheduler = scheduler
        return scheduler

    def shutdown(self) -> None:  # pragma: no cover - live APScheduler wiring
        """Stop the scheduler (idempotent; a no-op if never started)."""
        scheduler = self._scheduler
        if scheduler is not None and getattr(scheduler, "running", False):
            scheduler.shutdown(wait=False)

    def _job_callable(self, spec: JobSpec) -> Callable[[], Awaitable[None]]:  # pragma: no cover
        """A no-arg coroutine APScheduler fires that runs ``spec`` and logs the outcome."""

        async def _fire() -> None:
            outcome = await self.run_job(spec)
            _log_outcome(outcome)

        return _fire


def _log_outcome(outcome: JobOutcome) -> None:  # pragma: no cover - trivial log dispatch
    """Log a job outcome at a severity matching its status (a bad scheduled job leaves a trace)."""
    if outcome.status in ("timeout", "error"):
        logger.warning("scheduled job %r -> %s: %s", outcome.job_id, outcome.status, outcome.error)
    else:
        logger.info(
            "scheduled job %r -> %s (run_id=%s)", outcome.job_id, outcome.status, outcome.run_id
        )


def build_escalation_sweep_runner(  # pragma: no cover - live seam (out-of-wheel ops tool)
    client: Any, *, assistant_id: str = "devops"
) -> JobTypeRunner:
    """A ``job_type`` runner that runs the escalation-timeout SWEEPER over a ``langgraph_sdk`` seam.

    Register the result under ``"escalation-sweep"`` in :class:`SchedulerService`'s ``job_types`` so
    the scheduler drives it. The sweeper itself lives in the out-of-wheel ``ops/maintenance.py`` (it
    reuses that module's documented ``langgraph_sdk`` SDK-firewall exception to LIST + resume-reject
    interrupted runs) and is imported lazily here so the shipped package never depends on ``ops``.

    The production sweeper resumes via the SDK client directly — NOT ``gateway.resume_interrupt`` —
    because a fresh sweeper process never suspended those runs, so it holds no in-memory suspended
    record to resume through the gateway. The single-process strongest-pin test does use the gateway
    (valid there because the same instance suspended the run).
    """
    from ops.maintenance import sweep_timed_out_escalations

    async def _run(spec: JobSpec) -> None:
        await sweep_timed_out_escalations(client, assistant_id=assistant_id, dry_run=False)

    return _run
