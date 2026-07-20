"""The scheduler interface: our own APScheduler service driving scheduled agent runs (P4, T20).

Split into a PURE core and a thin live seam:

* :mod:`opendevops.interfaces.scheduler.jobs` — the ``scheduler/jobs.yaml`` schema, the job-spec
  parser, and the FIXED per-job default application (``misfire_grace_time=300``, ``coalesce=True``,
  ``max_instances=1``, 60s jitter). All pure / unit-tested.
* :mod:`opendevops.interfaces.scheduler.service` — :class:`SchedulerService`, whose per-job
  execution (fresh thread + ``profile=scheduled`` run under a caller-side timeout) is directly
  testable; only the ``AsyncIOScheduler`` wiring in ``start`` is a live seam.

The escalation-timeout SWEEPER (the enforcement behind ``on_timeout: deny``) lives in
``ops/maintenance.py`` — see its module docstring — because it reuses that module's documented
``langgraph_sdk`` SDK-firewall exception to LIST interrupted runs. The scheduler invokes it as the
``escalation-sweep`` job_type.

``apscheduler`` ships in the ``slack`` extra; importing this subpackage's ``service`` pulls it in
lazily (inside ``build_trigger`` / ``start``), so importing the package does not require it.
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
    "build_trigger",
    "load_jobs",
    "parse_jobs",
    "scheduler_job_kwargs",
]
