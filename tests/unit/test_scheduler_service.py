"""SchedulerService per-job execution.

Directly unit-tested with a stub gateway (no live APScheduler). A ``command`` job must build a
FRESH thread and run with ``profile=scheduled`` / ``interface=scheduled`` under the caller-side
``timeout_s``; a job that exceeds its timeout is CANCELLED and its outcome RECORDED (not swallowed);
a ``job_type`` job dispatches to its registered runner with the same timeout + outcome discipline.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from opendevops.gateway.base import Escalation, RunResult
from opendevops.interfaces.scheduler.jobs import JobSpec, parse_jobs
from opendevops.interfaces.scheduler.service import (
    SCHEDULED_INTERFACE,
    SCHEDULED_PROFILE,
    JobOutcome,
    SchedulerService,
)


class StubGateway:
    """Records create_thread / run / cancel calls; ``run`` returns a canned result or blocks."""

    def __init__(
        self, *, result: RunResult | None = None, block: bool = False, boom: bool = False
    ) -> None:
        self._result = result
        self._block = block
        self._boom = boom
        self.threads_created = 0
        self.run_calls: list[dict[str, Any]] = []
        self.cancelled: list[str] = []

    async def create_thread(self, thread_id: str | None = None) -> str:
        self.threads_created += 1
        return thread_id or f"thread-{self.threads_created}"

    async def run(self, thread_id: str, user_input: str, **kwargs: Any) -> RunResult:
        self.run_calls.append({"thread_id": thread_id, "user_input": user_input, **kwargs})
        if self._boom:
            raise RuntimeError("model exploded")
        if self._block:
            await asyncio.Event().wait()  # never completes -> the caller-side timeout must fire
        assert self._result is not None
        return self._result

    async def cancel(self, thread_id: str) -> None:
        self.cancelled.append(thread_id)


def _ok_result(run_id: str = "run-1") -> RunResult:
    return RunResult(
        final_text="done", run_id=run_id, cost_usd_state=0.0, cost_usd_authoritative=0.0
    )


def _cmd_spec(**over: Any) -> JobSpec:
    base: dict[str, Any] = {
        "id": "drift",
        "trigger": {"cron": "0 * * * *"},
        "command": "investigate drift",
        "timeout_s": 30,
        "environment": "prod",
    }
    base.update(over)
    return parse_jobs({"jobs": [base]})[0]


# --------------------------------------------------------------------------------------
# command job: fresh thread + scheduled profile/interface + environment
# --------------------------------------------------------------------------------------


async def test_command_job_builds_fresh_thread_and_runs_scheduled() -> None:
    gw = StubGateway(result=_ok_result("run-42"))
    svc = SchedulerService(gw, [], principal="scheduler")  # type: ignore[arg-type]
    spec = _cmd_spec()

    outcome = await svc.run_job(spec)

    assert gw.threads_created == 1  # a fresh thread per run
    call = gw.run_calls[0]
    assert call["thread_id"] == "thread-1"
    assert call["user_input"] == "investigate drift"
    assert call["profile"] == SCHEDULED_PROFILE == "scheduled"
    assert call["interface"] == SCHEDULED_INTERFACE == "scheduled"
    assert call["environment"] == "prod"  # from the job spec
    assert call["principal"] == "scheduler"
    assert outcome == JobOutcome(
        job_id="drift", status="ok", thread_id="thread-1", run_id="run-42", error=None
    )


async def test_command_job_records_escalation_as_escalated() -> None:
    interrupted = RunResult(
        final_text="",
        run_id="run-e",
        cost_usd_state=0.0,
        cost_usd_authoritative=0.0,
        interrupted=Escalation(payload={}, run_id="run-e", thread_id="thread-1"),
    )
    gw = StubGateway(result=interrupted)
    svc = SchedulerService(gw, [])  # type: ignore[arg-type]

    outcome = await svc.run_job(_cmd_spec())
    assert outcome.status == "escalated"
    assert outcome.run_id == "run-e"


async def test_command_job_timeout_cancels_and_records_not_swallowed() -> None:
    gw = StubGateway(block=True)
    svc = SchedulerService(gw, [])  # type: ignore[arg-type]

    outcome = await svc.run_job(_cmd_spec(timeout_s=1))  # blocks forever -> 1s caller-side timeout

    assert outcome.status == "timeout"
    assert outcome.thread_id == "thread-1"
    assert gw.cancelled == ["thread-1"]  # the belt cancelled the in-flight run
    assert "timeout_s=1" in (outcome.error or "")


async def test_command_job_error_is_captured_not_propagated() -> None:
    gw = StubGateway(boom=True)
    svc = SchedulerService(gw, [])  # type: ignore[arg-type]

    outcome = await svc.run_job(_cmd_spec())
    assert outcome.status == "error"
    assert "model exploded" in (outcome.error or "")


# --------------------------------------------------------------------------------------
# job_type job: dispatch + timeout + error + unknown
# --------------------------------------------------------------------------------------


def _jobtype_spec(job_type: str = "hygiene", **over: Any) -> JobSpec:
    base: dict[str, Any] = {
        "id": job_type,
        "trigger": {"cron": "0 3 * * *"},
        "job_type": job_type,
        "timeout_s": 30,
    }
    base.update(over)
    return parse_jobs({"jobs": [base]})[0]


async def test_job_type_dispatches_to_registered_runner() -> None:
    seen: list[str] = []

    async def hygiene(spec: JobSpec) -> None:
        seen.append(spec.id)

    gw = StubGateway(result=_ok_result())
    svc = SchedulerService(gw, [], job_types={"hygiene": hygiene})  # type: ignore[arg-type]

    outcome = await svc.run_job(_jobtype_spec("hygiene"))
    assert outcome.status == "ok"
    assert seen == ["hygiene"]
    assert gw.threads_created == 0  # a job_type job does NOT open an agent thread


async def test_unknown_job_type_is_error() -> None:
    svc = SchedulerService(StubGateway(), [])  # type: ignore[arg-type]
    outcome = await svc.run_job(_jobtype_spec("nope"))
    assert outcome.status == "error"
    assert "nope" in (outcome.error or "")


async def test_job_type_runner_error_is_captured() -> None:
    async def boom(spec: JobSpec) -> None:
        raise RuntimeError("hygiene failed")

    svc = SchedulerService(StubGateway(), [], job_types={"hygiene": boom})  # type: ignore[arg-type]
    outcome = await svc.run_job(_jobtype_spec("hygiene"))
    assert outcome.status == "error"
    assert "hygiene failed" in (outcome.error or "")


async def test_job_type_timeout_is_recorded() -> None:
    async def slow(spec: JobSpec) -> None:
        await asyncio.Event().wait()

    svc = SchedulerService(StubGateway(), [], job_types={"hygiene": slow})  # type: ignore[arg-type]
    outcome = await svc.run_job(_jobtype_spec("hygiene", timeout_s=1))
    assert outcome.status == "timeout"


@pytest.mark.parametrize("status", ["ok", "timeout", "error", "escalated"])
def test_job_outcome_dataclass_carries_status(status: str) -> None:
    assert JobOutcome(job_id="x", status=status).status == status  # type: ignore[arg-type]
