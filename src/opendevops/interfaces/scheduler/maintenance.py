"""Reusable scheduler and operator maintenance routines."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from opendevops.budget.daily import build_daily_counter

if TYPE_CHECKING:
    from opendevops.config import AppConfig

logger = logging.getLogger(__name__)
_PROTECTED_STATUSES = frozenset({"busy", "interrupted"})
TIMEOUT_APPROVER = "__timeout__"
TIMEOUT_MESSAGE = "escalation timed out"
ResumeFn = Callable[..., Awaitable[Any]]


def _parse_ts(value: Any) -> datetime | None:
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
    cutoff = now - timedelta(days=older_than_days)
    return [
        str(thread["thread_id"])
        for thread in threads
        if thread.get("status") not in _PROTECTED_STATUSES
        and thread.get("thread_id") is not None
        and (when := _parse_ts(thread.get("updated_at") or thread.get("created_at"))) is not None
        and when < cutoff
    ]


@dataclass(frozen=True)
class SpendRow:
    scope: str
    spent: float
    cap: float

    @property
    def fraction(self) -> float:
        return self.spent / self.cap if self.cap > 0 else 0.0


def build_spend_rows(
    totals: dict[str, float], *, global_cap: float, principal_cap: float
) -> list[SpendRow]:
    return [
        SpendRow(scope, totals[scope], global_cap if scope == "global" else principal_cap)
        for scope in sorted(totals)
    ]


def render_spend_report(rows: list[SpendRow], *, as_json: bool) -> str:
    if as_json:
        return json.dumps(
            [
                {
                    "scope": row.scope,
                    "spent_usd": round(row.spent, 6),
                    "cap_usd": row.cap,
                    "fraction": round(row.fraction, 4),
                }
                for row in rows
            ],
            indent=2,
        )
    if not rows:
        return "(no spend recorded today)"
    width = max(len(row.scope) for row in rows)
    return "\n".join(
        f"{row.scope:<{width}}  ${row.spent:8.4f} / ${row.cap:7.2f}  "
        f"({row.fraction * 100:5.1f}%)"
        for row in rows
    )


def pg_dump_argv(database_uri: str, out_path: str, *, fmt: str = "custom") -> list[str]:
    return [
        "pg_dump", "--dbname", database_uri, "--format", fmt,
        "--no-owner", "--no-privileges", "--file", out_path,
    ]


def validate_backup_settings(database_uri: str, backup_dir: Path, environ: dict[str, str]) -> None:
    parsed = urlsplit(database_uri)
    if parsed.scheme not in {"postgres", "postgresql"} or not parsed.hostname:
        raise ValueError("OPENDEVOPS_BACKUP_DATABASE_URI must be a PostgreSQL URI")
    if parsed.password is not None:
        raise ValueError(
            "OPENDEVOPS_BACKUP_DATABASE_URI must not contain a password; use PGPASSWORD"
        )
    if not environ.get("PGPASSWORD"):
        raise ValueError("PGPASSWORD is required for scheduler backups")
    if not str(backup_dir):
        raise ValueError("OPENDEVOPS_BACKUP_DIR must not be empty")


def require_pg_dump_16() -> str:
    """Return pg_dump's path, refusing missing or non-16 client tooling."""
    executable = shutil.which("pg_dump")
    if executable is None:
        raise RuntimeError("pg_dump is required for the scheduler hygiene job")
    result = subprocess.run(
        [executable, "--version"], check=True, capture_output=True, text=True
    )  # noqa: S603
    if re.search(r"\b16(?:\.|\b)", result.stdout) is None:
        raise RuntimeError(f"PostgreSQL 16 pg_dump is required; found {result.stdout.strip()}")
    return executable


def run_pg_dump_atomic(
    database_uri: str,
    backup_dir: Path,
    *,
    now: datetime | None = None,
    environ: dict[str, str] | None = None,
) -> Path:
    env = dict(os.environ if environ is None else environ)
    validate_backup_settings(database_uri, backup_dir, env)
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = (now or datetime.now(UTC)).astimezone(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    destination = backup_dir / f"opendevops-{stamp}.dump"
    fd, temporary = tempfile.mkstemp(prefix=".pgdump-", suffix=".tmp", dir=backup_dir)
    os.close(fd)
    try:
        subprocess.run(pg_dump_argv(database_uri, temporary), env=env, check=True)  # noqa: S603
        os.replace(temporary, destination)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
    return destination


async def spend_report_for_principal(cfg: AppConfig, principal: str) -> str:
    counter = build_daily_counter(cfg)
    scopes = ["global", f"principal:{principal}"]
    totals = {scope: await counter.total(scope) for scope in scopes}
    return render_spend_report(
        build_spend_rows(totals, global_cap=cfg.budgets.daily.global_usd,
                         principal_cap=cfg.budgets.daily.per_principal_usd),
        as_json=False,
    )


async def prune_idle_threads(
    client: Any, *, older_than_days: float = 30, limit: int = 1000
) -> list[str]:
    threads = await client.threads.search(limit=min(limit, 1000))
    victims = select_idle_thread_ids(
        list(threads), now=datetime.now(UTC), older_than_days=older_than_days
    )
    for thread_id in victims:
        await client.threads.delete(thread_id)
    return victims


async def run_daily_hygiene(
    client: Any, cfg: AppConfig, *, principal: str, database_uri: str, backup_dir: Path
) -> dict[str, Any]:
    """Back up first, log spend second, then prune; old dumps are never touched."""
    dump = await asyncio.to_thread(run_pg_dump_atomic, database_uri, backup_dir)
    report = await spend_report_for_principal(cfg, principal)
    logger.info("daily spend after backup %s:\n%s", dump, report)
    pruned = await prune_idle_threads(client, older_than_days=30, limit=1000)
    logger.info("daily hygiene pruned %d idle thread(s)", len(pruned))
    return {"backup": str(dump), "spend": report, "pruned": pruned}


@dataclass(frozen=True)
class InterruptedRun:
    thread_id: str
    rule_id: str | None
    timeout_s: int | None
    escalation_ts: datetime | None
    run_id: str | None = None


def timeout_reject_decisions() -> list[dict[str, str]]:
    return [{"type": "reject", "message": TIMEOUT_MESSAGE}]


def select_timed_out(runs: list[InterruptedRun], *, now: datetime) -> list[InterruptedRun]:
    return [
        run for run in runs
        if run.timeout_s is not None and run.escalation_ts is not None
        and (now - run.escalation_ts).total_seconds() > run.timeout_s
    ]


def _iter_interrupt_values(interrupts: Any) -> list[Any]:
    if not isinstance(interrupts, (dict, list)):
        return []
    groups = list(interrupts.values()) if isinstance(interrupts, dict) else [interrupts]
    return [
        item.get("value") if isinstance(item, dict) and "value" in item else item
        for group in groups for item in (group if isinstance(group, list) else [group])
    ]


def interrupted_runs_from_threads(threads: list[dict[str, Any]]) -> list[InterruptedRun]:
    runs: list[InterruptedRun] = []
    for thread in threads:
        if thread.get("thread_id") is None:
            continue
        review: dict[str, Any] = {}
        for value in _iter_interrupt_values(thread.get("interrupts")):
            configs = value.get("review_configs") if isinstance(value, dict) else None
            if isinstance(configs, list) and configs and isinstance(configs[0], dict):
                review = configs[0]
                break
        metadata = thread.get("metadata")
        raw_timeout = review.get("timeout_s")
        runs.append(InterruptedRun(
            thread_id=str(thread["thread_id"]),
            rule_id=str(review["rule_id"]) if review.get("rule_id") is not None else None,
            timeout_s=raw_timeout if isinstance(raw_timeout, int) else None,
            escalation_ts=_parse_ts(thread.get("updated_at") or thread.get("created_at")),
            run_id=(str(metadata["run_id"])
                    if isinstance(metadata, dict) and metadata.get("run_id") else None),
        ))
    return runs


async def resume_timed_out(resume: ResumeFn, runs: list[InterruptedRun]) -> list[str]:
    resumed: list[str] = []
    for run in runs:
        await resume(run.thread_id, timeout_reject_decisions(), approver=TIMEOUT_APPROVER)
        resumed.append(run.thread_id)
    return resumed


def _sdk_resume_fn(client: Any, assistant_id: str) -> ResumeFn:
    async def _resume(thread_id: str, decisions: list[dict[str, Any]], *, approver: str) -> Any:
        injected = [{**decision, "approver": approver} for decision in decisions]
        return await client.runs.wait(
            thread_id, assistant_id, command={"resume": {"decisions": injected}}
        )
    return _resume


async def sweep_timed_out_escalations(
    client: Any, *, assistant_id: str = "devops", now: datetime | None = None,
    limit: int = 1000, dry_run: bool = True,
) -> list[InterruptedRun]:
    threads = await client.threads.search(status="interrupted", limit=min(limit, 1000))
    victims = select_timed_out(
        interrupted_runs_from_threads(list(threads)), now=now or datetime.now(UTC)
    )
    if not dry_run:
        await resume_timed_out(_sdk_resume_fn(client, assistant_id), victims)
    return victims
