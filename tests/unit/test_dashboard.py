"""Authenticated dashboard routes and audit-derived end-to-end snapshot."""

from __future__ import annotations

import copy
from collections.abc import AsyncIterator
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest

from graph.helpers import MODELS, budgets
from opendevops.audit import AuditLogger
from opendevops.audit.schema import EventType
from opendevops.config import AppConfig
from opendevops.gateway.base import (
    AssistantText,
    RunEnd,
    RunResult,
    ToolCall,
    ToolResult,
)
from opendevops.interfaces.dashboard import build_dashboard_snapshot
from opendevops.interfaces.webapp import create_app

_TOKEN_ENV = "TEST_DASHBOARD_TOKEN"
_TOKEN = "dashboard-token-with-enough-entropy"


def _cfg(audit_dir: Path, **server: object) -> AppConfig:
    return AppConfig.model_validate(
        {
            "targets": {
                "kubernetes": {
                    "kubeconfig_ro": "/tmp/k.yaml",
                    "allowed_contexts": ["kind-opendevops"],
                },
                "aws": {"credential_env": ["AWS_ACCESS_KEY_ID"]},
            },
            "execution": {
                "cmd_timeout_seconds": 60,
                "output_max_chars": 50000,
                "env_allowlist": ["PATH", "HOME"],
            },
            "audit": {"dir": str(audit_dir)},
            "policy": {"dir": "/tmp/policy"},
            "server": {
                "url": "http://localhost:8123",
                "dashboard_token_env": _TOKEN_ENV,
                **server,
            },
            "control_plane": {"database": str(audit_dir / "control-plane.sqlite3")},
            "models": copy.deepcopy(MODELS),
            "budgets": budgets(),
        }
    )


def _client(app: object) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://dashboard.test",
        follow_redirects=False,
    )


def _seed_run(audit_dir: Path) -> None:
    audit = AuditLogger(audit_dir)
    audit.start_run(
        "run-dashboard",
        thread_id="thread-dashboard",
        principal={"interface": "webhook", "user": "alertmanager"},
        environment="staging",
        model="anthropic:claude-opus-4-8",
        policy_version="sha256:policy-version",
    )
    audit.append(
        "run-dashboard",
        EventType.decision,
        tool="run_command",
        tool_call_id="call-1",
        args={"argv": ["kubectl", "get", "pods"]},
        decision={
            "effect": "allow",
            "rule_id": "kubectl-read",
            "reason": "read command",
            "channel": "ro",
        },
        summary={"duration_ms": 6},
    )
    audit.append(
        "run-dashboard",
        EventType.execution,
        tool="run_command",
        tool_call_id="call-1",
        execution={
            "exit_code": 0,
            "duration_ms": 18,
            "stdout_sha256": "abc123",
            "stdout_excerpt": "pod/api-0",
            "truncated": False,
        },
    )
    audit.append(
        "run-dashboard",
        EventType.decision,
        tool="run_command",
        tool_call_id="call-2",
        args={"argv": ["kubectl", "delete", "pod", "api-0"]},
        decision={
            "effect": "deny",
            "rule_id": "no-delete",
            "reason": "destructive command",
            "channel": "ro",
        },
        summary={"duration_ms": 4},
    )
    audit.append(
        "run-dashboard",
        EventType.escalation,
        tool="run_command",
        tool_call_id="call-3",
        summary={"reason": "approval required"},
    )
    audit.end_run(
        "run-dashboard",
        summary={
            "status": "completed",
            "cost_state": 0.11,
            "cost_authoritative": 0.12,
            "usage": {"input_tokens": 100, "output_tokens": 20},
        },
    )


async def test_dashboard_redirects_to_login_without_session(tmp_path: Path) -> None:
    app = create_app(_cfg(tmp_path), AsyncMock())
    async with _client(app) as client:
        response = await client.get("/dashboard")
    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard/login"
    assert "no-store" in response.headers["cache-control"]


async def test_dashboard_login_fails_closed_when_secret_is_unset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(_TOKEN_ENV, raising=False)
    app = create_app(_cfg(tmp_path), AsyncMock())
    async with _client(app) as client:
        response = await client.post("/dashboard/login", data={"token": _TOKEN})
    assert response.status_code == 503
    assert "not configured" in response.text


async def test_dashboard_rejects_bad_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(_TOKEN_ENV, _TOKEN)
    app = create_app(_cfg(tmp_path), AsyncMock())
    async with _client(app) as client:
        response = await client.post("/dashboard/login", data={"token": "wrong"})
    assert response.status_code == 401
    assert "invalid" in response.text
    assert "set-cookie" not in response.headers


async def test_dashboard_login_sets_hardened_cookie_and_exposes_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(_TOKEN_ENV, _TOKEN)
    _seed_run(tmp_path)
    app = create_app(_cfg(tmp_path), AsyncMock())

    async with _client(app) as client:
        login = await client.post("/dashboard/login", data={"token": _TOKEN})
        page = await client.get("/dashboard")
        snapshot = await client.get("/dashboard/api/snapshot")

    assert login.status_code == 303
    cookie = login.headers["set-cookie"]
    assert "HttpOnly" in cookie
    assert "SameSite=strict" in cookie
    assert "Path=/dashboard" in cookie
    assert page.status_code == 200
    assert "Agent operations" in page.text
    assert snapshot.status_code == 200
    payload = snapshot.json()
    assert payload["overview"]["audit_verified"] == 1
    assert payload["policy"] == {
        "decisions": 2,
        "executions": 1,
        "denials": 1,
        "escalations": 1,
    }
    assert payload["runs"][0]["cost_usd"] == 0.12
    assert payload["slis"]["policy_latency_ms"] == 5.0
    assert payload["runs"][0]["principal"] == "alertmanager"
    assert payload["integrations"][0]["state"] == "configured"
    serialized = snapshot.text
    assert '"args":' not in serialized
    assert '"stdout_excerpt":' not in serialized
    assert '"delete"' not in serialized
    assert "pod/api-0" not in serialized
    assert "AWS_ACCESS_KEY_ID" not in serialized


async def test_dashboard_secure_cookie_is_configurable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(_TOKEN_ENV, _TOKEN)
    app = create_app(_cfg(tmp_path, dashboard_cookie_secure=True), AsyncMock())
    async with _client(app) as client:
        login = await client.post("/dashboard/login", data={"token": _TOKEN})
    assert "Secure" in login.headers["set-cookie"]


async def test_dashboard_api_rejects_tampered_cookie(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(_TOKEN_ENV, _TOKEN)
    app = create_app(_cfg(tmp_path), AsyncMock())
    async with _client(app) as client:
        client.cookies.set("opendevops_dashboard_session", "9999999999.invalid", path="/dashboard")
        response = await client.get("/dashboard/api/snapshot")
    assert response.status_code == 401


async def test_dashboard_assets_are_public_but_bounded(tmp_path: Path) -> None:
    app = create_app(_cfg(tmp_path), AsyncMock())
    async with _client(app) as client:
        css = await client.get("/dashboard/assets/dashboard.css")
        dashboard_script = await client.get("/dashboard/assets/dashboard.js")
        login_script = await client.get("/dashboard/assets/login.js")
        missing = await client.get("/dashboard/assets/../../config.yaml")
    assert css.status_code == 200
    assert "max-age=3600" in css.headers["cache-control"]
    assert dashboard_script.status_code == 200
    assert dashboard_script.headers["content-type"].startswith("application/javascript")
    assert login_script.status_code == 200
    assert "dashboard.ts" not in dashboard_script.text
    assert missing.status_code == 404


def test_dashboard_browser_sources_are_typescript_only() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    frontend = repo_root / "frontend"
    asset_root = repo_root / "src" / "opendevops" / "interfaces" / "dashboard_assets"

    assert sorted(path.name for path in frontend.glob("*.ts")) == ["dashboard.ts", "login.ts"]
    assert list(frontend.rglob("*.js")) == []
    assert list(asset_root.glob("*.js")) == []


def test_snapshot_is_safe_and_useful_when_audit_dir_is_empty(tmp_path: Path) -> None:
    snapshot = build_dashboard_snapshot(_cfg(tmp_path))
    assert snapshot["overview"]["runs_today"] == 0
    assert snapshot["runs"] == []
    assert len(snapshot["daily"]) == 7
    assert all("credential_env" not in integration for integration in snapshot["integrations"])


async def test_dashboard_configuration_mutations_require_csrf_and_follow_lifecycle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(_TOKEN_ENV, _TOKEN)
    app = create_app(_cfg(tmp_path), AsyncMock())
    async with _client(app) as client:
        await client.post("/dashboard/login", data={"token": _TOKEN})
        snapshot = await client.get("/dashboard/api/snapshot")
        csrf = snapshot.json()["identity"]["csrf_token"]
        payload = {
            "environment": "staging",
            "capability": "kubernetes_deploy",
            "targets": ["kind-opendevops/default/api"],
            "reason": "deploy the reviewed api release",
        }
        missing_csrf = await client.post("/dashboard/api/config/proposals", json=payload)
        proposed = await client.post(
            "/dashboard/api/config/proposals",
            json=payload,
            headers={"X-CSRF-Token": csrf},
        )
        proposal_id = proposed.json()["proposal_id"]
        approved = await client.post(
            f"/dashboard/api/config/proposals/{proposal_id}/approve",
            json={},
            headers={"X-CSRF-Token": csrf},
        )
        activated = await client.post(
            f"/dashboard/api/config/proposals/{proposal_id}/activate",
            json={},
            headers={"X-CSRF-Token": csrf},
        )

    assert missing_csrf.status_code == 403
    assert proposed.status_code == 201
    assert approved.json()["status"] == "approved"
    assert activated.json()["status"] == "active"


async def test_dashboard_production_configuration_rejects_self_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(_TOKEN_ENV, _TOKEN)
    app = create_app(_cfg(tmp_path), AsyncMock())
    async with _client(app) as client:
        await client.post("/dashboard/login", data={"token": _TOKEN})
        csrf = (await client.get("/dashboard/api/snapshot")).json()["identity"]["csrf_token"]
        proposal = await client.post(
            "/dashboard/api/config/proposals",
            json={
                "environment": "prod",
                "capability": "aws_deploy",
                "targets": ["account-123/us-east-1/api"],
                "reason": "deploy the approved production release",
            },
            headers={"X-CSRF-Token": csrf},
        )
        response = await client.post(
            f"/dashboard/api/config/proposals/{proposal.json()['proposal_id']}/approve",
            json={},
            headers={"X-CSRF-Token": csrf},
        )

    assert response.status_code == 409
    assert "different from the requester" in response.json()["detail"]


async def test_dashboard_chat_streams_safe_events_and_persists_private_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(_TOKEN_ENV, _TOKEN)
    gateway = AsyncMock()
    gateway.create_thread.return_value = "thread-chat"
    observed: dict[str, object] = {}

    async def stream(
        thread_id: str,
        user_input: str,
        *,
        profile: str,
        principal: str,
        interface: str,
        environment: str,
    ) -> AsyncIterator[object]:
        observed.update(
            {
                "thread_id": thread_id,
                "user_input": user_input,
                "profile": profile,
                "principal": principal,
                "interface": interface,
                "environment": environment,
            }
        )
        yield AssistantText("I found a policy-blocked operation.")
        yield ToolCall(
            name="run_command",
            argv=["kubectl", "delete", "secret", "do-not-leak"],
        )
        yield ToolResult(
            excerpt="SENSITIVE EXECUTOR OUTPUT",
            denied=True,
            rule_id="prod-delete-denied",
        )
        yield RunEnd(
            RunResult(
                final_text="I found a policy-blocked operation.",
                run_id="run-chat",
                cost_usd_state=0.01,
                cost_usd_authoritative=0.012,
            )
        )

    gateway.stream = stream
    app = create_app(_cfg(tmp_path), gateway)

    async with _client(app) as client:
        await client.post("/dashboard/login", data={"token": _TOKEN})
        csrf = (await client.get("/dashboard/api/snapshot")).json()["identity"]["csrf_token"]
        missing_csrf = await client.post(
            "/dashboard/api/chat/threads",
            json={"environment": "prod"},
        )
        created = await client.post(
            "/dashboard/api/chat/threads",
            json={"environment": "prod"},
            headers={"X-CSRF-Token": csrf},
        )
        streamed = await client.post(
            "/dashboard/api/chat/threads/thread-chat/messages",
            json={"message": "Investigate production safely"},
            headers={"X-CSRF-Token": csrf},
        )
        history = await client.get("/dashboard/api/chat/threads/thread-chat")

    assert missing_csrf.status_code == 403
    assert created.status_code == 201
    assert created.json()["environment"] == "prod"
    assert streamed.status_code == 200
    assert streamed.headers["content-type"].startswith("text/event-stream")
    assert "I found a policy-blocked operation." in streamed.text
    assert "Invoking run_command" in streamed.text
    assert "prod-delete-denied" in streamed.text
    assert "do-not-leak" not in streamed.text
    assert "SENSITIVE EXECUTOR OUTPUT" not in streamed.text
    assert observed == {
        "thread_id": "thread-chat",
        "user_input": "Investigate production safely",
        "profile": "default",
        "principal": "oidc:local-development#static-token",
        "interface": "http",
        "environment": "prod",
    }
    serialized_history = history.text
    assert history.status_code == 200
    assert "Investigate production safely" in serialized_history
    assert "I found a policy-blocked operation." in serialized_history
    assert "prod-delete-denied" in serialized_history
    assert "do-not-leak" not in serialized_history
    assert "SENSITIVE EXECUTOR OUTPUT" not in serialized_history


async def test_dashboard_chat_can_be_disabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(_TOKEN_ENV, _TOKEN)
    app = create_app(_cfg(tmp_path, dashboard_chat_enabled=False), AsyncMock())
    async with _client(app) as client:
        await client.post("/dashboard/login", data={"token": _TOKEN})
        page = await client.get("/dashboard")
        response = await client.get("/dashboard/api/chat/threads")
    assert '<meta name="chat-enabled" content="false">' in page.text
    assert 'class="panel chat-panel is-hidden"' in page.text
    assert response.status_code == 404
