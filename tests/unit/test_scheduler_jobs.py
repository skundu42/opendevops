"""Scheduler job-spec parsing + FIXED default application (T20).

Pure: no live scheduler is stood up. The FIXED knobs (``misfire_grace_time=300``, ``coalesce=True``,
``max_instances=1``, 60s jitter) must be applied to EVERY job, and a malformed job spec must be
rejected fail-closed. The shipped ``scheduler/jobs.yaml`` is loaded and checked too.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from pydantic import ValidationError

from opendevops.interfaces.scheduler.jobs import (
    FIXED_COALESCE,
    FIXED_JITTER_S,
    FIXED_MAX_INSTANCES,
    FIXED_MISFIRE_GRACE_TIME,
    build_trigger,
    load_jobs,
    parse_jobs,
    scheduler_job_kwargs,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
SHIPPED_JOBS = REPO_ROOT / "scheduler" / "jobs.yaml"


def _cron_job(**over: object) -> dict[str, object]:
    job: dict[str, object] = {
        "id": "j1",
        "trigger": {"cron": "0 3 * * *"},
        "command": "investigate drift",
        "timeout_s": 600,
    }
    job.update(over)
    return job


# --------------------------------------------------------------------------------------
# parse + default application
# --------------------------------------------------------------------------------------


def test_parses_cron_and_interval_jobs() -> None:
    specs = parse_jobs(
        {
            "jobs": [
                _cron_job(),
                {
                    "id": "sweep",
                    "trigger": {"interval": {"minutes": 5}},
                    "job_type": "escalation-sweep",
                    "timeout_s": 300,
                },
            ]
        }
    )
    assert [s.id for s in specs] == ["j1", "sweep"]
    assert specs[0].command == "investigate drift"
    assert specs[0].environment == "staging"  # default overlay
    assert specs[1].job_type == "escalation-sweep"


def test_fixed_knobs_and_jitter_applied_to_every_job() -> None:
    """The 4 fixed knobs (+60s jitter) are applied to EVERY job by scheduler_job_kwargs."""
    specs = parse_jobs(
        {
            "jobs": [
                _cron_job(id="a"),
                _cron_job(id="b", trigger={"interval": {"hours": 6}}, command="x"),
            ]
        }
    )
    for spec in specs:
        kwargs = scheduler_job_kwargs(spec)
        assert kwargs["misfire_grace_time"] == FIXED_MISFIRE_GRACE_TIME == 300
        assert kwargs["coalesce"] is FIXED_COALESCE is True
        assert kwargs["max_instances"] == FIXED_MAX_INSTANCES == 1
        assert kwargs["id"] == spec.id
        assert kwargs["replace_existing"] is True
        # jitter rides on the trigger (probed: cron takes no jitter kwarg; set on the instance).
        assert kwargs["trigger"].jitter == FIXED_JITTER_S == 60


def test_build_trigger_cron() -> None:
    trig = build_trigger(parse_jobs({"jobs": [_cron_job()]})[0])
    assert isinstance(trig, CronTrigger)
    assert trig.jitter == 60


def test_build_trigger_interval() -> None:
    spec = parse_jobs({"jobs": [_cron_job(trigger={"interval": {"minutes": 15}})]})[0]
    trig = build_trigger(spec)
    assert isinstance(trig, IntervalTrigger)
    assert trig.jitter == 60
    assert trig.interval.total_seconds() == 15 * 60


# --------------------------------------------------------------------------------------
# fail-closed rejection of malformed specs
# --------------------------------------------------------------------------------------

_CRON = {"cron": "0 3 * * *"}
# Each case starts from a valid cron/command job and mutates one field into an invalid state.
_BAD_SPECS: dict[str, dict[str, object]] = {
    "trigger-neither": _cron_job(trigger={}),
    "trigger-both": _cron_job(trigger={**_CRON, "interval": {"minutes": 5}}),
    "action-neither": {"id": "x", "trigger": _CRON, "timeout_s": 60},
    "action-both": _cron_job(job_type="hygiene"),
    "timeout-zero": _cron_job(timeout_s=0),
    "empty-id": _cron_job(id=""),
    "bad-interval-unit": _cron_job(trigger={"interval": {"fortnights": 2}}),
    "unknown-key": _cron_job(bogus=1),
    "bad-environment": _cron_job(environment="prod-ish"),
}


@pytest.mark.parametrize("bad", _BAD_SPECS.values(), ids=list(_BAD_SPECS))
def test_rejects_invalid_job_spec(bad: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        parse_jobs({"jobs": [bad]})


def test_rejects_duplicate_job_ids() -> None:
    with pytest.raises(ValidationError):
        parse_jobs({"jobs": [_cron_job(id="dup"), _cron_job(id="dup", command="y")]})


def test_rejects_unknown_top_level_key() -> None:
    with pytest.raises(ValidationError):
        parse_jobs({"jobs": [_cron_job()], "extra": 1})


# --------------------------------------------------------------------------------------
# the shipped jobs.yaml
# --------------------------------------------------------------------------------------


def test_shipped_jobs_yaml_parses_and_gets_defaults() -> None:
    specs = load_jobs(SHIPPED_JOBS)
    ids = {s.id for s in specs}
    expected = {
        "drift-detection", "cert-expiry", "backup-verification", "hygiene", "escalation-sweep"
    }
    assert expected <= ids
    for spec in specs:
        kwargs = scheduler_job_kwargs(spec)
        assert kwargs["misfire_grace_time"] == 300
        assert kwargs["coalesce"] is True
        assert kwargs["max_instances"] == 1
        assert kwargs["trigger"].jitter == 60
