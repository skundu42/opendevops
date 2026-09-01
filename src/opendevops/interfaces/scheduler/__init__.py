"""The scheduler interface: our own APScheduler service driving scheduled agent runs.

Split into a PURE core and a thin live seam:

* :mod:`opendevops.interfaces.scheduler.jobs` — the ``scheduler/jobs.yaml`` schema, the job-spec
  parser, and the FIXED per-job default application (``misfire_grace_time=300``, ``coalesce=True``,
  ``max_instances=1``, 60s jitter). All pure / unit-tested.
* :mod:`opendevops.interfaces.scheduler.service` — :class:`SchedulerService`, whose per-job
  execution (fresh thread + ``profile=scheduled`` run under a caller-side timeout) is directly
  testable; only the ``AsyncIOScheduler`` wiring in ``start`` is a live seam.

The packaged maintenance module owns backup/spend/prune hygiene and the escalation-timeout
sweeper; ``ops/maintenance.py`` is only its Typer frontend.

``apscheduler`` ships in the ``scheduler`` extra; this subpackage imports it lazily (inside
``build_trigger`` / ``start``), so importing the package does not require it.
"""

from opendevops.interfaces.scheduler.jobs import (
    JobsFile,
    JobSpec,
    TriggerSpec,
    build_trigger,
    load_jobs,
    parse_jobs,
    scheduler_job_kwargs,
)
from opendevops.interfaces.scheduler.service import (
    DEFAULT_SCHEDULED_PRINCIPAL,
    SCHEDULED_INTERFACE,
    SCHEDULED_PROFILE,
    JobOutcome,
    SchedulerService,
    build_escalation_sweep_runner,
    build_hygiene_runner,
    serve_scheduler,
)

__all__ = [
    "DEFAULT_SCHEDULED_PRINCIPAL",
    "SCHEDULED_INTERFACE",
    "SCHEDULED_PROFILE",
    "JobOutcome",
    "JobSpec",
    "JobsFile",
    "SchedulerService",
    "TriggerSpec",
    "build_escalation_sweep_runner",
    "build_hygiene_runner",
    "build_trigger",
    "load_jobs",
    "parse_jobs",
    "scheduler_job_kwargs",
    "serve_scheduler",
]
