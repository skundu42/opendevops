"""Thin Typer frontend for shipped maintenance routines."""

from __future__ import annotations

import asyncio
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import typer

from opendevops.interfaces.scheduler.maintenance import (
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
    sweep_timed_out_escalations,
    timeout_reject_decisions,
)

app = typer.Typer(name="maintenance", help="opendevops service-stack hygiene jobs.")

__all__ = [
    "TIMEOUT_APPROVER", "TIMEOUT_MESSAGE", "InterruptedRun", "SpendRow",
    "build_spend_rows", "interrupted_runs_from_threads", "pg_dump_argv",
    "render_spend_report", "resume_timed_out", "select_idle_thread_ids",
    "select_timed_out", "timeout_reject_decisions",
]


def _build_client(url: str, api_key_env: str | None) -> Any:
    from langgraph_sdk import get_client
    return get_client(url=url, api_key=os.environ.get(api_key_env) if api_key_env else None)


@app.command("prune-threads")
def prune_threads(
    url: str = typer.Option(...), older_than_days: float = typer.Option(30.0),
    api_key_env: str | None = typer.Option(None), limit: int = typer.Option(1000),
    dry_run: bool = typer.Option(True),
) -> None:
    """Delete idle server threads, protecting busy and interrupted work."""
    async def _run() -> None:
        client = _build_client(url, api_key_env)
        try:
            threads = await client.threads.search(limit=min(limit, 1000))
            victims = select_idle_thread_ids(
                list(threads), now=datetime.now(UTC), older_than_days=older_than_days
            )
            typer.echo(f"{len(victims)} idle thread(s) selected")
            for thread_id in victims:
                if not dry_run:
                    await client.threads.delete(thread_id)
                typer.echo(f"  {'would delete' if dry_run else 'deleted'} {thread_id}")
        finally:
            await client.aclose()
    asyncio.run(_run())


@app.command("spend-report")
def spend_report(
    config_root: Path | None = typer.Option(None),  # noqa: B008
    principal: list[str] | None = typer.Option(None),  # noqa: B008
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Print daily global and selected principal spend."""
    from opendevops.budget.daily import build_daily_counter
    from opendevops.config import load_config

    async def _run() -> None:
        cfg = load_config(config_root)
        counter = build_daily_counter(cfg)
        scopes = ["global", *(f"principal:{value}" for value in (principal or []))]
        totals = {scope: await counter.total(scope) for scope in scopes}
        rows = build_spend_rows(
            totals, global_cap=cfg.budgets.daily.global_usd,
            principal_cap=cfg.budgets.daily.per_principal_usd,
        )
        typer.echo(render_spend_report(rows, as_json=as_json))
    asyncio.run(_run())


@app.command("pg-dump")
def pg_dump(
    database_uri: str = typer.Option(...),
    out_path: Path = typer.Option(...),  # noqa: B008
    fmt: str = typer.Option("custom"),
) -> None:
    """Back up Postgres to the requested operator path."""
    result = subprocess.run(
        pg_dump_argv(database_uri, str(out_path), fmt=fmt),
        env=os.environ.copy(),
        check=False,
    )  # noqa: S603
    if result.returncode:
        raise typer.Exit(code=result.returncode)
    typer.echo(f"wrote {out_path}")


@app.command("sweep-escalations")
def sweep_escalations(
    url: str = typer.Option(...), api_key_env: str | None = typer.Option(None),
    assistant_id: str = typer.Option("devops"), limit: int = typer.Option(1000),
    dry_run: bool = typer.Option(True),
) -> None:
    """Resume-reject timed-out escalations."""
    async def _run() -> None:
        client = _build_client(url, api_key_env)
        try:
            victims = await sweep_timed_out_escalations(
                client, assistant_id=assistant_id, limit=limit, dry_run=dry_run
            )
            typer.echo(f"{len(victims)} timed-out escalation(s) selected")
        finally:
            await client.aclose()
    asyncio.run(_run())


if __name__ == "__main__":
    app()
