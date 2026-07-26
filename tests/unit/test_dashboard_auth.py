"""Opaque dashboard sessions, revocation, RBAC, and OIDC claim mapping."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from graph.helpers import MODELS, budgets
from opendevops.config import AppConfig
from opendevops.interfaces.dashboard_auth import (
    DashboardAuth,
    DashboardAuthError,
    DashboardSession,
    MemorySessionStore,
    require_permission,
)


def _session(**values: object) -> DashboardSession:
    payload: dict[str, object] = {
        "issuer": "https://issuer.example",
        "subject": "subject-1",
        "roles": ["viewer"],
        "csrf_token": "csrf",
        "created_at": 1,
        "expires_at": 100,
        "auth_mode": "oidc",
    }
    payload.update(values)
    return DashboardSession.model_validate(payload)


async def test_opaque_session_can_be_revoked_by_issuer_and_subject() -> None:
    store = MemorySessionStore(now=lambda: 10)
    session = _session()
    token = await store.create(session, 90)

    assert "." not in token
    assert await store.get(token) == session
    assert await store.revoke_identity(session.issuer, session.subject) == 1
    assert await store.get(token) is None


def test_rbac_does_not_treat_operator_as_approver() -> None:
    session = _session(roles=["operator"])
    require_permission(session, "run.cancel")
    with pytest.raises(DashboardAuthError, match="approval.resolve"):
        require_permission(session, "approval.resolve")


def test_oidc_role_claims_map_to_explicit_dashboard_roles(tmp_path: Path) -> None:
    cfg = AppConfig.model_validate(
        {
            "targets": {
                "kubernetes": {
                    "kubeconfig_ro": "/tmp/k.yaml",
                    "allowed_contexts": ["kind-opendevops"],
                }
            },
            "execution": {
                "cmd_timeout_seconds": 60,
                "output_max_chars": 50000,
                "env_allowlist": ["PATH", "HOME"],
            },
            "audit": {"dir": str(tmp_path)},
            "policy": {"dir": "/tmp/policy"},
            "server": {
                "dashboard_auth_mode": "oidc",
                "dashboard_session_backend": "memory",
                "oidc": {
                    "issuer": "https://issuer.example",
                    "client_id_env": "OIDC_CLIENT_ID",
                    "redirect_uri": "https://agent.example/dashboard/oidc/callback",
                    "roles_claim": "realm_access.groups",
                    "role_mappings": {
                        "viewer": ["devops-readers"],
                        "approver": ["change-approvers"],
                    },
                },
            },
            "control_plane": {"database": str(tmp_path / "control.sqlite3")},
            "models": copy.deepcopy(MODELS),
            "budgets": budgets(),
        }
    )
    auth = DashboardAuth(cfg, MemorySessionStore())

    roles = auth._roles(  # noqa: SLF001 - focused claim-mapping unit contract
        {"realm_access": {"groups": ["devops-readers", "change-approvers"]}}
    )

    assert roles == ["viewer", "approver"]
