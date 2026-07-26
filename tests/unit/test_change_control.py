"""Identity separation and loop-safe capability grant state machine."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from opendevops.config import ControlPlaneConfig
from opendevops.control_plane import (
    ActionIdentity,
    CapabilityGrantRequest,
    ChangeControlError,
    ChangeControlService,
)


def _identity(subject: str) -> ActionIdentity:
    return ActionIdentity(issuer="https://issuer.example", subject=subject)


def _request(environment: str = "prod") -> CapabilityGrantRequest:
    return CapabilityGrantRequest(
        environment=environment,
        capability="kubernetes_deploy",
        targets=["cluster-a/default/api"],
        reason="deploy a reviewed and signed release",
        max_executions=2,
        max_identical_per_run=1,
        cooldown_s=0,
    )


def _service(path: Path, **config: object) -> ChangeControlService:
    return ChangeControlService(
        ControlPlaneConfig(
            database=path,
            minimum_cooldown_s=0,
            enforce_runtime_grants=True,
            grant_required_environments=["staging", "prod"],
            **config,
        )
    )


def test_production_request_requires_different_approver_and_separate_activation(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path / "control.sqlite3")
    proposal = service.propose(_request(), _identity("requester"))

    with pytest.raises(ChangeControlError, match="different from the requester"):
        service.approve(proposal.proposal_id, _identity("requester"))

    approved = service.approve(proposal.proposal_id, _identity("approver"))
    active = service.activate(proposal.proposal_id, _identity("admin"))

    assert approved.status.value == "approved"
    assert active.status.value == "active"
    events = service.events()
    assert events[0]["issuer"] == "https://issuer.example"
    assert events[0]["subject"] == "admin"
    assert events[-1]["prev_hash"] == "sha256:genesis"


def test_runtime_grant_is_consumed_and_repeated_action_loop_is_stopped(tmp_path: Path) -> None:
    service = _service(tmp_path / "control.sqlite3")
    proposal = service.propose(_request("staging"), _identity("requester"))
    service.approve(proposal.proposal_id, _identity("approver"))
    service.activate(proposal.proposal_id, _identity("admin"))

    grant_id = service.authorize_rw(
        run_id="run-1",
        environment="staging",
        principal="operator",
        tool_family="kubectl",
        fingerprint="same-action",
    )
    with pytest.raises(ChangeControlError, match="loop|repeat"):
        service.authorize_rw(
            run_id="run-1",
            environment="staging",
            principal="operator",
            tool_family="kubectl",
            fingerprint="same-action",
        )

    assert grant_id == proposal.proposal_id
    assert service.get(proposal.proposal_id).executions_used == 1


def test_no_active_grant_fails_closed_and_wildcard_targets_are_invalid(tmp_path: Path) -> None:
    service = _service(tmp_path / "control.sqlite3")
    with pytest.raises(ChangeControlError, match="no active"):
        service.authorize_rw(
            run_id="run-1",
            environment="prod",
            principal="operator",
            tool_family="aws",
            fingerprint="deploy",
        )

    with pytest.raises(ValidationError, match="wildcards"):
        CapabilityGrantRequest(
            environment="prod",
            capability="aws_deploy",
            targets=["*"],
            reason="deploy an approved production release",
        )
