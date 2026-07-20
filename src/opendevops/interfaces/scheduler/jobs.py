"""Job-spec parsing + the FIXED per-job default application for the scheduler (P4, T20).

This module is the PURE, directly-testable heart of the scheduler service. It owns:

* the on-disk ``scheduler/jobs.yaml`` schema (strict ``extra="forbid"`` pydantic models, so an
  unexpected key or a malformed trigger is a hard boot error — fail-closed, matching the rest of
  the config surface);
* :func:`build_trigger` — turn a job's ``{cron: ...}`` / ``{interval: {...}}`` into a live
  APScheduler trigger with the FIXED **60s jitter** applied (spreads a fleet of jobs off the exact
  cron edge so N jobs never fire simultaneously);
* :func:`scheduler_job_kwargs` — the exact keyword arguments the service passes to
  ``AsyncIOScheduler.add_job`` for a job, carrying the FIXED knobs
  (``misfire_grace_time=300`` — run a job missed by up to 5 min, e.g. across a short restart;
  ``coalesce=True`` — collapse a backlog of missed fires into one; ``max_instances=1`` — never run
  two copies of the same hygiene job concurrently).

Everything here is synchronous and I/O-free except :func:`load_jobs` (a single YAML read). The live
APScheduler wiring lives in :mod:`opendevops.interfaces.scheduler.service`; these functions let a
unit test assert the defaults are applied to every job without standing up a scheduler.

APScheduler 3.11 probe (installed): ``CronTrigger.from_crontab(expr, timezone=...)`` builds a cron
trigger but takes NO ``jitter`` kwarg — jitter is set on the trigger instance (``trigger.jitter``);
``IntervalTrigger(**units, jitter=..., timezone=...)`` accepts it directly. ``add_job`` takes
``misfire_grace_time`` / ``coalesce`` / ``max_instances`` as per-job keyword arguments.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

if TYPE_CHECKING:
    from apscheduler.triggers.base import BaseTrigger

# --------------------------------------------------------------------------------------
# the FIXED per-job knobs (PLAN §3.7 Scheduler bullet — not per-job configurable)
# --------------------------------------------------------------------------------------

# Run a job that was missed (e.g. across a short restart) if it is less than this many seconds late.
FIXED_MISFIRE_GRACE_TIME = 300
# Collapse a backlog of missed fires into a single run rather than replaying each one.
FIXED_COALESCE = True
# Never run two copies of the same job concurrently (a long hygiene run must not overlap itself).
FIXED_MAX_INSTANCES = 1
# Randomize each fire by up to this many seconds so a fleet of jobs never all fire on the cron edge.
FIXED_JITTER_S = 60

# The interval units APScheduler's IntervalTrigger accepts (validated so a typo is a boot error).
_INTERVAL_UNITS: frozenset[str] = frozenset({"weeks", "days", "hours", "minutes", "seconds"})

# All triggers run against UTC — the audit/ULID clock is UTC, and a wall-clock-local cron would
# drift under DST. Documented, fixed.
_TZ = "UTC"


# --------------------------------------------------------------------------------------
# schema
# --------------------------------------------------------------------------------------


class TriggerSpec(BaseModel):
    """A job's schedule: exactly one of a ``cron`` string or an ``interval`` unit-map.

    * ``cron`` — a 5-field crontab expression (``"0 3 * * *"``), parsed by
      ``CronTrigger.from_crontab``.
    * ``interval`` — a map of APScheduler interval units (``{minutes: 15}``,
      ``{hours: 6}``), passed straight to ``IntervalTrigger``.
    """

    model_config = ConfigDict(extra="forbid")

    cron: str | None = None
    interval: dict[str, int] | None = None

    @model_validator(mode="after")
    def _exactly_one(self) -> TriggerSpec:
        if (self.cron is None) == (self.interval is None):
            raise ValueError("trigger requires exactly one of 'cron' or 'interval'")
        if self.interval is not None:
            if not self.interval:
                raise ValueError("interval trigger requires at least one unit (e.g. {minutes: 15})")
            unknown = set(self.interval) - _INTERVAL_UNITS
            if unknown:
                raise ValueError(
                    f"interval trigger has unknown unit(s) {sorted(unknown)}; "
                    f"allowed: {sorted(_INTERVAL_UNITS)}"
                )
            if any(v <= 0 for v in self.interval.values()):
                raise ValueError("interval trigger units must be positive")
        return self


class JobSpec(BaseModel):
    """One scheduled job: a trigger plus what it runs and the caller-side timeout that bounds it.

    Exactly one of ``command`` / ``job_type`` is set:

    * ``command`` — the agent task text a fresh scheduled run executes (the drift-detection /
      cert-expiry / backup-verification RCA prompts).
    * ``job_type`` — the name of a registered non-agent runner (``hygiene``, ``escalation-sweep``)
      the service dispatches to; these do maintenance/sweeper work rather than an agent turn.

    ``timeout_s`` is the caller-side cancel deadline the service wraps the job in (belt to the
    gateway's own wall-clock). ``environment`` is the policy overlay stamped onto a ``command`` run.
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    trigger: TriggerSpec
    command: str | None = None
    job_type: str | None = None
    timeout_s: int = Field(gt=0)
    environment: Literal["staging", "prod"] = "staging"

    @model_validator(mode="after")
    def _exactly_one_action(self) -> JobSpec:
        if (self.command is None) == (self.job_type is None):
            raise ValueError("job requires exactly one of 'command' or 'job_type'")
        return self


class JobsFile(BaseModel):
    """The top-level ``scheduler/jobs.yaml`` document: a list of jobs with unique ids."""

    model_config = ConfigDict(extra="forbid")

    jobs: list[JobSpec]

    @model_validator(mode="after")
    def _unique_ids(self) -> JobsFile:
        ids = [job.id for job in self.jobs]
        if len(ids) != len(set(ids)):
            dupes = sorted({i for i in ids if ids.count(i) > 1})
            raise ValueError(f"duplicate job id(s): {dupes}")
        return self


# --------------------------------------------------------------------------------------
# parsing (pure) + a single-read loader
# --------------------------------------------------------------------------------------


def parse_jobs(raw: dict[str, Any]) -> list[JobSpec]:
    """Validate a raw ``jobs.yaml`` mapping into a list of :class:`JobSpec` (pure, fail-closed).

    Raises ``pydantic.ValidationError`` on any schema violation (unknown key, a trigger that is
    neither/both cron+interval, a missing/empty id, a non-positive timeout, a job with neither or
    both of command/job_type, a duplicate id).
    """
    return JobsFile.model_validate(raw).jobs


def load_jobs(path: Path) -> list[JobSpec]:
    """Read and validate ``jobs.yaml`` at ``path`` (the only I/O in this module)."""
    with Path(path).open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    if raw is None:
        raw = {"jobs": []}
    if not isinstance(raw, dict):
        raise ValueError(f"{path} must contain a YAML mapping, got {type(raw).__name__}")
    return parse_jobs(raw)


# --------------------------------------------------------------------------------------
# default application (pure) — trigger construction + add_job kwargs
# --------------------------------------------------------------------------------------


def build_trigger(spec: JobSpec) -> BaseTrigger:
    """Build the APScheduler trigger for ``spec`` with the FIXED 60s jitter applied.

    Cron: ``CronTrigger.from_crontab`` takes no jitter kwarg (probed), so it is set on the instance.
    Interval: ``IntervalTrigger`` accepts ``jitter`` directly. Both run against UTC.
    """
    from apscheduler.triggers.cron import CronTrigger
    from apscheduler.triggers.interval import IntervalTrigger

    if spec.trigger.cron is not None:
        trigger = CronTrigger.from_crontab(spec.trigger.cron, timezone=_TZ)
        trigger.jitter = FIXED_JITTER_S
        return trigger
    assert spec.trigger.interval is not None  # guaranteed by TriggerSpec validation
    return IntervalTrigger(**spec.trigger.interval, jitter=FIXED_JITTER_S, timezone=_TZ)


def scheduler_job_kwargs(spec: JobSpec) -> dict[str, Any]:
    """The exact ``AsyncIOScheduler.add_job`` keyword arguments for ``spec``.

    Pure: carries the trigger (with 60s jitter) plus the three FIXED per-job knobs, so a test can
    assert the defaults are applied to every job without a live scheduler. ``replace_existing`` lets
    a restart re-register the job set idempotently.
    """
    return {
        "trigger": build_trigger(spec),
        "id": spec.id,
        "name": spec.id,
        "misfire_grace_time": FIXED_MISFIRE_GRACE_TIME,
        "coalesce": FIXED_COALESCE,
        "max_instances": FIXED_MAX_INSTANCES,
        "replace_existing": True,
    }
