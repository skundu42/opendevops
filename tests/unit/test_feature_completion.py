"""Regression pins for the completed service, approval, and hygiene seams."""

from __future__ import annotations

import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from opendevops.gateway import Escalation, escalation_details
from opendevops.interfaces.dashboard import ApprovalRequest, _scope_approval_details
from opendevops.interfaces.dashboard_auth import DashboardSession
from opendevops.interfaces.scheduler import maintenance


def _session(role: str) -> DashboardSession:
    return DashboardSession(
        issuer="test",
        subject=role,
        roles=[role],
        csrf_token="csrf",
        created_at=0,
        expires_at=10,
        auth_mode="static",
    )


def test_escalation_details_are_shared_scrubbed_and_role_scoped() -> None:
    escalation = Escalation(
        payload={
            "action_requests": [
                {"action": "run_command", "args": {"argv": ["echo", "xoxb-123456789012"]}}
            ],
            "review_configs": [
                {"rule_id": "delete-prod", "reason": "needs review", "timeout_s": 300}
            ],
        },
        run_id="run-1",
        thread_id="thread-1",
    )
    details = escalation_details(escalation)
    assert details.argv == ["echo", "***"]
    live = {
        "pending_approvals": [
            {
                "thread_id": "thread-1",
                "requester": "alice",
                "tool": details.tool,
                "argv": details.argv,
                "rule_id": details.rule_id,
                "reason": details.reason,
                "timeout_s": details.timeout_s,
            }
        ]
    }
    assert "argv" not in _scope_approval_details(live, _session("viewer"))["pending_approvals"][0]
    assert _scope_approval_details(live, _session("approver"))["pending_approvals"][0][
        "argv"
    ] == ["echo", "***"]


def test_approval_edit_schema_preserves_arguments_and_rejects_malformed_argv() -> None:
    request = ApprovalRequest.model_validate(
        {"decisions": [{"type": "edit", "args": {"argv": ["echo", "two words"]}}]}
    )
    assert request.decisions[0].model_dump()["args"]["argv"] == ["echo", "two words"]
    with pytest.raises(ValidationError):
        ApprovalRequest.model_validate(
            {"decisions": [{"type": "edit", "args": {"argv": []}}]}
        )
    with pytest.raises(ValidationError):
        ApprovalRequest.model_validate({"decisions": [{"type": "approve", "args": {}}]})


def test_atomic_dump_keeps_existing_backups_and_removes_failed_temp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    old = tmp_path / "opendevops-old.dump"
    old.write_text("old")

    def _run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        Path(argv[-1]).write_text("new")
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(maintenance.subprocess, "run", _run)
    dump = maintenance.run_pg_dump_atomic(
        "postgresql://postgres@db/postgres",
        tmp_path,
        now=datetime(2026, 9, 1, tzinfo=UTC),
        environ={"PGPASSWORD": "secret"},
    )
    assert dump.read_text() == "new"
    assert old.read_text() == "old"
    assert not list(tmp_path.glob(".pgdump-*.tmp"))


@pytest.mark.asyncio
async def test_failed_backup_prevents_spend_and_pruning(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def _fail(*args: Any, **kwargs: Any) -> None:
        calls.append("backup")
        raise subprocess.CalledProcessError(1, ["pg_dump"])

    async def _spend(*args: Any, **kwargs: Any) -> str:
        calls.append("spend")
        return ""

    async def _prune(*args: Any, **kwargs: Any) -> list[str]:
        calls.append("prune")
        return []

    monkeypatch.setattr(maintenance, "run_pg_dump_atomic", _fail)
    monkeypatch.setattr(maintenance, "spend_report_for_principal", _spend)
    monkeypatch.setattr(maintenance, "prune_idle_threads", _prune)
    with pytest.raises(subprocess.CalledProcessError):
        await maintenance.run_daily_hygiene(
            object(),
            object(),
            principal="scheduler",
            database_uri="postgresql://postgres@db/postgres",
            backup_dir=Path("/backups"),
        )
    assert calls == ["backup"]
