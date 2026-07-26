"""Webapp: Alertmanager + GitHub webhooks, run-complete, healthz, metrics.

Every test drives :func:`create_app` with an ``AsyncMock`` gateway stub over an in-process ASGI
transport (``httpx.ASGITransport``), so no real gateway, server, or ``langgraph_sdk`` is involved.
Payload fixtures model realistic Alertmanager v4 (`alerts[].fingerprint`, `status`, `commonLabels`)
and GitHub ``workflow_run`` shapes. Fire-and-forget runs are drained via ``app.state`` before
asserting on the gateway.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import hmac
import json
import logging
import re
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest

from graph.helpers import MODELS, budgets
from opendevops.config import AppConfig
from opendevops.interfaces import webapp
from opendevops.interfaces.webapp import (
    _MAX_ALERTS_PER_REQUEST,
    _MAX_BODY_BYTES,
    NS_INCIDENT,
    create_app,
)

REPO_ROOT = Path(__file__).resolve().parents[2]

_TOKEN = "s3cr3t-bearer-token"
_GH_SECRET = "gh-webhook-hmac-secret"
_TOKEN_ENV = "TEST_AM_TOKEN"
_GH_ENV = "TEST_GH_SECRET"


# -- config + gateway stub -----------------------------------------------------------------


def _make_cfg(**server_overrides: Any) -> AppConfig:
    server: dict[str, Any] = {"url": "http://localhost:8123", **server_overrides}
    return AppConfig.model_validate(
        {
            "targets": {"kubernetes": {"kubeconfig_ro": "/tmp/k.yaml"}},
            "execution": {
                "cmd_timeout_seconds": 60,
                "output_max_chars": 50000,
                "env_allowlist": ["PATH", "HOME"],
            },
            "audit": {"dir": "/tmp/audit"},
            "policy": {"dir": "/tmp/policy"},
            "server": server,
            "models": copy.deepcopy(MODELS),
            "budgets": budgets(),
        }
    )


def _stub_gateway() -> AsyncMock:
    gw = AsyncMock()
    gw.create_thread = AsyncMock(return_value="ignored-thread-id")
    gw.run = AsyncMock(return_value=None)
    return gw


def _client(app: Any, peer: tuple[str, int] = ("127.0.0.1", 40000)) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=app, client=peer)
    return httpx.AsyncClient(transport=transport, base_url="http://webhooks")


async def _drain(app: Any) -> None:
    """Run any fire-and-forget background run tasks to completion before asserting."""
    tasks = list(app.state.background_tasks)
    if tasks:
        await asyncio.gather(*tasks)


# -- payload fixtures ----------------------------------------------------------------------


def _am_payload(
    *,
    fingerprint: str = "a1b2c3d4e5f60718",
    status: str = "firing",
    alertname: str = "KubePodCrashLooping",
    severity: str = "critical",
) -> dict[str, Any]:
    """A realistic Alertmanager v4 webhook body (single alert)."""
    labels = {"alertname": alertname, "severity": severity, "namespace": "web", "pod": "api-0"}
    return {
        "version": "4",
        "groupKey": '{}:{alertname="' + alertname + '"}',
        "truncatedAlerts": 0,
        "status": status,
        "receiver": "opendevops",
        "groupLabels": {"alertname": alertname},
        "commonLabels": {"alertname": alertname, "severity": severity, "namespace": "web"},
        "commonAnnotations": {"summary": "A pod is crash looping"},
        "externalURL": "http://alertmanager.example.com",
        "alerts": [
            {
                "status": status,
                "labels": labels,
                "annotations": {
                    "summary": "Pod api-0 is crash looping",
                    "description": "container api restarted 7 times in 5m",
                },
                "startsAt": "2026-07-18T12:00:00.000Z",
                "endsAt": "0001-01-01T00:00:00Z",
                "generatorURL": "http://prometheus.example.com/graph",
                "fingerprint": fingerprint,
            }
        ],
    }


def _gh_payload(
    *,
    action: str = "completed",
    conclusion: str = "failure",
    repo: str = "acme/webapp",
    run_id: int = 987654321,
) -> dict[str, Any]:
    """A realistic GitHub ``workflow_run`` webhook body."""
    return {
        "action": action,
        "workflow_run": {
            "id": run_id,
            "name": "CI",
            "head_branch": "main",
            "head_sha": "deadbeefcafebabe",
            "status": "completed",
            "conclusion": conclusion,
            "html_url": f"https://github.com/{repo}/actions/runs/{run_id}",
            "run_number": 42,
        },
        "workflow": {"name": "CI"},
        "repository": {"full_name": repo, "name": "webapp"},
        "sender": {"login": "octocat"},
    }


def _gh_sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _am_multi(n: int, *, fingerprint_prefix: str = "fp") -> dict[str, Any]:
    """An Alertmanager body carrying ``n`` alerts, each with a unique fingerprint."""
    base = _am_payload()
    template = base["alerts"][0]
    base["alerts"] = [
        {**copy.deepcopy(template), "fingerprint": f"{fingerprint_prefix}{i:05d}"}
        for i in range(n)
    ]
    return base


def _counter(metrics_text: str, route: str, outcome: str) -> float:
    """Extract ``webhook_requests_total{outcome,route}`` from /metrics text (0.0 if absent).

    Prometheus exposition sorts labels alphabetically, so the rendered order is ``outcome`` then
    ``route``.
    """
    pattern = (
        r"opendevops_webhook_requests_total\{outcome=\""
        + re.escape(outcome)
        + r"\",route=\""
        + re.escape(route)
        + r"\"\} ([0-9.eE+-]+)"
    )
    match = re.search(pattern, metrics_text)
    return float(match.group(1)) if match else 0.0


# -- healthz / metrics ---------------------------------------------------------------------


async def test_healthz_ok_no_auth() -> None:
    app = create_app(_make_cfg(), _stub_gateway())
    async with _client(app) as client:
        resp = await client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


async def test_metrics_exposition_lists_counters_after_traffic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(_TOKEN_ENV, _TOKEN)
    app = create_app(_make_cfg(alertmanager_token_env=_TOKEN_ENV), _stub_gateway())
    async with _client(app) as client:
        accepted = await client.post(
            "/webhooks/alertmanager", headers=_bearer(_TOKEN), json=_am_payload()
        )
        assert accepted.status_code == 202
        await _drain(app)
        metrics = await client.get("/metrics")
    assert metrics.status_code == 200
    body = metrics.text
    assert 'opendevops_webhook_requests_total{outcome="accepted",route="alertmanager"}' in body
    assert 'opendevops_runs_started_total{interface="webhook"}' in body


# -- alertmanager: auth --------------------------------------------------------------------


async def test_alertmanager_missing_bearer_401(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_TOKEN_ENV, _TOKEN)
    app = create_app(_make_cfg(alertmanager_token_env=_TOKEN_ENV), _stub_gateway())
    async with _client(app) as client:
        resp = await client.post("/webhooks/alertmanager", json=_am_payload())
    assert resp.status_code == 401


async def test_alertmanager_wrong_bearer_401(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_TOKEN_ENV, _TOKEN)
    gw = _stub_gateway()
    app = create_app(_make_cfg(alertmanager_token_env=_TOKEN_ENV), gw)
    async with _client(app) as client:
        resp = await client.post(
            "/webhooks/alertmanager", headers=_bearer("wrong"), json=_am_payload()
        )
    assert resp.status_code == 401
    gw.run.assert_not_awaited()


async def test_alertmanager_secret_env_unset_503(monkeypatch: pytest.MonkeyPatch) -> None:
    """The token env NAME is configured but the variable is unset -> fail closed (503)."""
    monkeypatch.delenv(_TOKEN_ENV, raising=False)
    app = create_app(_make_cfg(alertmanager_token_env=_TOKEN_ENV), _stub_gateway())
    async with _client(app) as client:
        resp = await client.post(
            "/webhooks/alertmanager", headers=_bearer(_TOKEN), json=_am_payload()
        )
    assert resp.status_code == 503


async def test_alertmanager_no_token_configured_503() -> None:
    """No token env name configured at all -> fail closed (503), never 'auth disabled'."""
    app = create_app(_make_cfg(alertmanager_token_env=None), _stub_gateway())
    async with _client(app) as client:
        resp = await client.post(
            "/webhooks/alertmanager", headers=_bearer(_TOKEN), json=_am_payload()
        )
    assert resp.status_code == 503


async def test_alertmanager_bearer_uses_constant_time_compare(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(_TOKEN_ENV, _TOKEN)
    calls: list[tuple[Any, Any]] = []
    real = hmac.compare_digest

    def _spy(a: Any, b: Any) -> bool:
        calls.append((a, b))
        return real(a, b)

    monkeypatch.setattr("hmac.compare_digest", _spy)
    app = create_app(_make_cfg(alertmanager_token_env=_TOKEN_ENV), _stub_gateway())
    async with _client(app) as client:
        resp = await client.post(
            "/webhooks/alertmanager", headers=_bearer(_TOKEN), json=_am_payload()
        )
        await _drain(app)
    assert resp.status_code == 202
    assert calls, "bearer check must go through hmac.compare_digest (constant time)"


# -- alertmanager: source allowlist --------------------------------------------------------


async def test_alertmanager_source_allowlist_rejects_outside_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(_TOKEN_ENV, _TOKEN)
    gw = _stub_gateway()
    app = create_app(
        _make_cfg(alertmanager_token_env=_TOKEN_ENV, source_allowlist=["10.0.0.9"]), gw
    )
    async with _client(app, peer=("203.0.113.7", 5555)) as client:
        resp = await client.post(
            "/webhooks/alertmanager", headers=_bearer(_TOKEN), json=_am_payload()
        )
    assert resp.status_code == 403
    gw.run.assert_not_awaited()


async def test_alertmanager_source_allowlist_admits_listed_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(_TOKEN_ENV, _TOKEN)
    app = create_app(
        _make_cfg(alertmanager_token_env=_TOKEN_ENV, source_allowlist=["10.0.0.9"]),
        _stub_gateway(),
    )
    async with _client(app, peer=("10.0.0.9", 5555)) as client:
        resp = await client.post(
            "/webhooks/alertmanager", headers=_bearer(_TOKEN), json=_am_payload()
        )
        await _drain(app)
    assert resp.status_code == 202


# -- alertmanager: run start, deterministic thread, dedup ----------------------------------


async def test_alertmanager_accepts_and_starts_incident_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(_TOKEN_ENV, _TOKEN)
    gw = _stub_gateway()
    app = create_app(_make_cfg(alertmanager_token_env=_TOKEN_ENV), gw)
    fingerprint = "a1b2c3d4e5f60718"
    expected_thread = str(uuid.uuid5(NS_INCIDENT, fingerprint))

    async with _client(app) as client:
        resp = await client.post(
            "/webhooks/alertmanager", headers=_bearer(_TOKEN), json=_am_payload()
        )
        await _drain(app)

    assert resp.status_code == 202
    incident = resp.json()["incidents"][0]
    assert incident["thread_id"] == expected_thread
    assert incident["deduped"] is False

    # Deterministic thread id flows through both gateway calls.
    gw.create_thread.assert_awaited_once_with(thread_id=expected_thread)
    gw.run.assert_awaited_once()
    call = gw.run.await_args
    assert call.args[0] == expected_thread
    assert call.kwargs["profile"] == "incident"
    assert call.kwargs["principal"] == "alertmanager"
    assert call.kwargs["interface"] == "webhook"
    assert call.kwargs["environment"] == "staging"


async def test_alertmanager_dedup_same_fingerprint_starts_one_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(_TOKEN_ENV, _TOKEN)
    gw = _stub_gateway()
    app = create_app(_make_cfg(alertmanager_token_env=_TOKEN_ENV), gw)

    async with _client(app) as client:
        first = await client.post(
            "/webhooks/alertmanager", headers=_bearer(_TOKEN), json=_am_payload()
        )
        second = await client.post(
            "/webhooks/alertmanager", headers=_bearer(_TOKEN), json=_am_payload()
        )
        await _drain(app)

    assert first.json()["incidents"][0]["deduped"] is False
    assert second.status_code == 202
    assert second.json()["incidents"][0]["deduped"] is True
    gw.run.assert_awaited_once()


async def test_alertmanager_environment_from_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_TOKEN_ENV, _TOKEN)
    gw = _stub_gateway()
    app = create_app(
        _make_cfg(alertmanager_token_env=_TOKEN_ENV, webhook_environment="prod"), gw
    )
    async with _client(app) as client:
        await client.post("/webhooks/alertmanager", headers=_bearer(_TOKEN), json=_am_payload())
        await _drain(app)
    assert gw.run.await_args.kwargs["environment"] == "prod"


# -- github: HMAC + workflow_run handling --------------------------------------------------


async def test_github_valid_signature_starts_ci_run(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_GH_ENV, _GH_SECRET)
    gw = _stub_gateway()
    app = create_app(_make_cfg(github_webhook_secret_env=_GH_ENV), gw)
    payload = _gh_payload()
    raw = json.dumps(payload).encode()
    headers = {
        "X-Hub-Signature-256": _gh_sign(_GH_SECRET, raw),
        "X-GitHub-Event": "workflow_run",
        "Content-Type": "application/json",
    }
    expected_thread = str(uuid.uuid5(NS_INCIDENT, "gh:acme/webapp:987654321"))

    async with _client(app) as client:
        resp = await client.post("/webhooks/github", headers=headers, content=raw)
        await _drain(app)

    assert resp.status_code == 202
    assert resp.json()["thread_id"] == expected_thread
    gw.create_thread.assert_awaited_once_with(thread_id=expected_thread)
    gw.run.assert_awaited_once()
    assert gw.run.await_args.args[0] == expected_thread
    assert gw.run.await_args.kwargs["principal"] == "github"
    assert gw.run.await_args.kwargs["interface"] == "webhook"


async def test_github_tampered_body_rejected_401(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_GH_ENV, _GH_SECRET)
    gw = _stub_gateway()
    app = create_app(_make_cfg(github_webhook_secret_env=_GH_ENV), gw)
    raw = json.dumps(_gh_payload()).encode()
    sig = _gh_sign(_GH_SECRET, raw)  # signature over the ORIGINAL body
    tampered = raw + b" "
    headers = {"X-Hub-Signature-256": sig, "X-GitHub-Event": "workflow_run"}

    async with _client(app) as client:
        resp = await client.post("/webhooks/github", headers=headers, content=tampered)
    assert resp.status_code == 401
    gw.run.assert_not_awaited()


async def test_github_missing_signature_header_401(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_GH_ENV, _GH_SECRET)
    app = create_app(_make_cfg(github_webhook_secret_env=_GH_ENV), _stub_gateway())
    raw = json.dumps(_gh_payload()).encode()
    async with _client(app) as client:
        resp = await client.post(
            "/webhooks/github", headers={"X-GitHub-Event": "workflow_run"}, content=raw
        )
    assert resp.status_code == 401


async def test_github_secret_env_unset_503(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(_GH_ENV, raising=False)
    app = create_app(_make_cfg(github_webhook_secret_env=_GH_ENV), _stub_gateway())
    raw = json.dumps(_gh_payload()).encode()
    headers = {"X-Hub-Signature-256": _gh_sign(_GH_SECRET, raw), "X-GitHub-Event": "workflow_run"}
    async with _client(app) as client:
        resp = await client.post("/webhooks/github", headers=headers, content=raw)
    assert resp.status_code == 503


async def test_github_non_workflow_run_event_ignored_204(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(_GH_ENV, _GH_SECRET)
    gw = _stub_gateway()
    app = create_app(_make_cfg(github_webhook_secret_env=_GH_ENV), gw)
    raw = json.dumps({"zen": "Keep it simple", "hook_id": 1}).encode()
    headers = {"X-Hub-Signature-256": _gh_sign(_GH_SECRET, raw), "X-GitHub-Event": "ping"}
    async with _client(app) as client:
        resp = await client.post("/webhooks/github", headers=headers, content=raw)
    assert resp.status_code == 204
    gw.run.assert_not_awaited()


async def test_github_workflow_run_success_ignored_204(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(_GH_ENV, _GH_SECRET)
    gw = _stub_gateway()
    app = create_app(_make_cfg(github_webhook_secret_env=_GH_ENV), gw)
    raw = json.dumps(_gh_payload(conclusion="success")).encode()
    headers = {"X-Hub-Signature-256": _gh_sign(_GH_SECRET, raw), "X-GitHub-Event": "workflow_run"}
    async with _client(app) as client:
        resp = await client.post("/webhooks/github", headers=headers, content=raw)
    assert resp.status_code == 204
    gw.run.assert_not_awaited()


# -- run-complete callback -----------------------------------------------------------------


async def test_run_complete_204_and_counter(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_TOKEN_ENV, _TOKEN)
    app = create_app(_make_cfg(alertmanager_token_env=_TOKEN_ENV), _stub_gateway())
    async with _client(app) as client:
        resp = await client.post(
            "/webhooks/run-complete",
            headers=_bearer(_TOKEN),
            json={"thread_id": "t-1", "run_id": "r-1", "status": "success"},
        )
        metrics = await client.get("/metrics")
    assert resp.status_code == 204
    assert (
        'opendevops_webhook_requests_total{outcome="accepted",route="run-complete"}'
        in metrics.text
    )


async def test_run_complete_requires_bearer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_TOKEN_ENV, _TOKEN)
    app = create_app(_make_cfg(alertmanager_token_env=_TOKEN_ENV), _stub_gateway())
    async with _client(app) as client:
        resp = await client.post("/webhooks/run-complete", json={"thread_id": "t-1"})
    assert resp.status_code == 401


# -- I1: non-ASCII auth headers must fail-closed 401, never 500, and be counted --------------
#
# ``hmac.compare_digest`` on *str* operands raises ``TypeError`` when either holds a non-ASCII
# character. An unauthenticated attacker could weaponise that into a reliable 500 that also escapes
# the auth-outcome metric. httpx refuses to encode a non-ASCII *str* header, so the malicious value
# is injected as raw *bytes* (Starlette latin-1-decodes it back into a non-ASCII str, exactly as a
# real socket would).

# utf-8 checkmark -> a non-ASCII token after Starlette's latin-1 header decode
_NON_ASCII_BEARER = b"Bearer \xe2\x9c\x93"
_NON_ASCII_SIG = b"sha256=\xc3\xa9"  # non-ASCII X-Hub-Signature-256 value


async def test_alertmanager_non_ascii_bearer_401_not_500(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_TOKEN_ENV, _TOKEN)
    gw = _stub_gateway()
    app = create_app(_make_cfg(alertmanager_token_env=_TOKEN_ENV), gw)
    async with _client(app) as client:
        resp = await client.post(
            "/webhooks/alertmanager",
            headers={"Authorization": _NON_ASCII_BEARER},
            json=_am_payload(),
        )
        metrics = await client.get("/metrics")
    assert resp.status_code == 401  # NOT 500
    gw.run.assert_not_awaited()
    assert _counter(metrics.text, "alertmanager", "unauthorized") >= 1  # blind spot closed


async def test_run_complete_non_ascii_bearer_401_not_500(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_TOKEN_ENV, _TOKEN)
    app = create_app(_make_cfg(alertmanager_token_env=_TOKEN_ENV), _stub_gateway())
    async with _client(app) as client:
        resp = await client.post(
            "/webhooks/run-complete",
            headers={"Authorization": _NON_ASCII_BEARER},
            json={"thread_id": "t-1"},
        )
        metrics = await client.get("/metrics")
    assert resp.status_code == 401  # NOT 500
    assert _counter(metrics.text, "run-complete", "unauthorized") >= 1


async def test_github_non_ascii_signature_401_not_500(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_GH_ENV, _GH_SECRET)
    gw = _stub_gateway()
    app = create_app(_make_cfg(github_webhook_secret_env=_GH_ENV), gw)
    raw = json.dumps(_gh_payload()).encode()
    headers = {"X-Hub-Signature-256": _NON_ASCII_SIG, "X-GitHub-Event": "workflow_run"}
    async with _client(app) as client:
        resp = await client.post("/webhooks/github", headers=headers, content=raw)
        metrics = await client.get("/metrics")
    assert resp.status_code == 401  # NOT 500
    gw.run.assert_not_awaited()
    assert _counter(metrics.text, "github", "unauthorized") >= 1


# -- M1/M2: malformed-but-authenticated payloads are ignored, never 500 ----------------------


async def test_alertmanager_labels_as_list_ignored_not_500(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(_TOKEN_ENV, _TOKEN)
    gw = _stub_gateway()
    app = create_app(_make_cfg(alertmanager_token_env=_TOKEN_ENV), gw)
    payload = _am_payload()
    payload["alerts"][0]["labels"] = ["not", "a", "dict"]  # malformed labels
    async with _client(app) as client:
        resp = await client.post(
            "/webhooks/alertmanager", headers=_bearer(_TOKEN), json=payload
        )
        await _drain(app)
        metrics = await client.get("/metrics")
    assert resp.status_code == 202  # NOT 500
    assert resp.json()["incidents"] == []  # alert ignored, no incident opened
    gw.run.assert_not_awaited()
    assert _counter(metrics.text, "alertmanager", "ignored") >= 1


async def test_github_workflow_run_as_string_204_not_500(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(_GH_ENV, _GH_SECRET)
    gw = _stub_gateway()
    app = create_app(_make_cfg(github_webhook_secret_env=_GH_ENV), gw)
    payload = _gh_payload()
    payload["workflow_run"] = "boom"  # malformed: not an object
    raw = json.dumps(payload).encode()
    headers = {"X-Hub-Signature-256": _gh_sign(_GH_SECRET, raw), "X-GitHub-Event": "workflow_run"}
    async with _client(app) as client:
        resp = await client.post("/webhooks/github", headers=headers, content=raw)
    assert resp.status_code == 204  # NOT 500
    gw.run.assert_not_awaited()


async def test_github_repository_as_string_204_not_500(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(_GH_ENV, _GH_SECRET)
    gw = _stub_gateway()
    app = create_app(_make_cfg(github_webhook_secret_env=_GH_ENV), gw)
    payload = _gh_payload()
    payload["repository"] = "boom"  # malformed: not an object
    raw = json.dumps(payload).encode()
    headers = {"X-Hub-Signature-256": _gh_sign(_GH_SECRET, raw), "X-GitHub-Event": "workflow_run"}
    async with _client(app) as client:
        resp = await client.post("/webhooks/github", headers=headers, content=raw)
    assert resp.status_code == 204  # NOT 500
    gw.run.assert_not_awaited()


async def test_github_missing_repository_204_no_run(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_GH_ENV, _GH_SECRET)
    gw = _stub_gateway()
    app = create_app(_make_cfg(github_webhook_secret_env=_GH_ENV), gw)
    payload = _gh_payload()
    del payload["repository"]  # a failure event that omits the identifying repo
    raw = json.dumps(payload).encode()
    headers = {"X-Hub-Signature-256": _gh_sign(_GH_SECRET, raw), "X-GitHub-Event": "workflow_run"}
    async with _client(app) as client:
        resp = await client.post("/webhooks/github", headers=headers, content=raw)
        await _drain(app)
    assert resp.status_code == 204  # never start a "gh:unknown:None" run
    gw.run.assert_not_awaited()
    gw.create_thread.assert_not_awaited()


# -- M3: fan-out cap + body-size guard (defense-in-depth) -------------------------------------


async def test_alertmanager_fanout_capped_and_dropped_counted(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv(_TOKEN_ENV, _TOKEN)
    gw = _stub_gateway()
    app = create_app(_make_cfg(alertmanager_token_env=_TOKEN_ENV), gw)
    over = 5
    payload = _am_multi(_MAX_ALERTS_PER_REQUEST + over)
    with caplog.at_level(logging.WARNING):
        async with _client(app) as client:
            resp = await client.post(
                "/webhooks/alertmanager", headers=_bearer(_TOKEN), json=payload
            )
            await _drain(app)
            metrics = await client.get("/metrics")
    assert resp.status_code == 202
    # Exactly the cap number of runs started; the excess is dropped, not processed.
    assert gw.run.await_count == _MAX_ALERTS_PER_REQUEST
    assert len(resp.json()["incidents"]) == _MAX_ALERTS_PER_REQUEST
    # Dropped alerts are counted (not silently truncated) ...
    assert _counter(metrics.text, "alertmanager", "dropped") == float(over)
    # ... and logged.
    assert any("capped" in rec.message for rec in caplog.records)


async def test_alertmanager_oversized_body_413(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_TOKEN_ENV, _TOKEN)
    gw = _stub_gateway()
    app = create_app(_make_cfg(alertmanager_token_env=_TOKEN_ENV), gw)
    oversized = b"x" * (_MAX_BODY_BYTES + 1)
    async with _client(app) as client:
        resp = await client.post(
            "/webhooks/alertmanager", headers=_bearer(_TOKEN), content=oversized
        )
    assert resp.status_code == 413
    gw.run.assert_not_awaited()


async def test_github_oversized_body_413(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_GH_ENV, _GH_SECRET)
    gw = _stub_gateway()
    app = create_app(_make_cfg(github_webhook_secret_env=_GH_ENV), gw)
    oversized = b"x" * (_MAX_BODY_BYTES + 1)
    headers = {
        "X-Hub-Signature-256": _gh_sign(_GH_SECRET, oversized),
        "X-GitHub-Event": "workflow_run",
    }
    async with _client(app) as client:
        resp = await client.post("/webhooks/github", headers=headers, content=oversized)
    assert resp.status_code == 413
    gw.run.assert_not_awaited()


# -- default app (langgraph.json http.app) -------------------------------------------------


def test_module_app_builds_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """``webapp.app`` lazily builds a FastAPI app from $OPENDEVOPS_CONFIG + a ServerGateway."""
    from fastapi import FastAPI

    monkeypatch.setattr(webapp, "_DEFAULT_APP", None)
    monkeypatch.setenv("OPENDEVOPS_CONFIG", str(REPO_ROOT / "config" / "config.yaml"))
    assert isinstance(webapp.app, FastAPI)


def _capture_gateway_url(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Monkeypatch ``ServerGateway`` (as ``webapp._build_default_app`` imports it) to capture the
    ``url`` override + the untouched ``cfg.server.url``, without building a real SDK client."""
    from fastapi import FastAPI

    captured: dict[str, Any] = {}

    class _FakeGateway:
        def __init__(self, cfg: Any, *, url: str | None = None, **_kw: Any) -> None:
            captured["cfg_url"] = cfg.server.url
            captured["url"] = url

    monkeypatch.setattr(webapp, "_DEFAULT_APP", None)
    monkeypatch.setattr("opendevops.gateway.ServerGateway", _FakeGateway)
    monkeypatch.setenv("OPENDEVOPS_CONFIG", str(REPO_ROOT / "config" / "config.yaml"))
    assert isinstance(webapp.app, FastAPI)
    return captured


def test_module_app_gateway_targets_loopback_not_caddy(monkeypatch: pytest.MonkeyPatch) -> None:
    """I-1: the in-container app builds its ServerGateway against the LOOPBACK server port (:8000),
    NOT the external Caddy URL (:8123) in ``cfg.server.url`` — so a webhook-fired run reaches the
    local API directly (bypassing Caddy + its bearer) instead of a port nothing listens on."""
    monkeypatch.delenv("OPENDEVOPS_SELF_URL", raising=False)
    captured = _capture_gateway_url(monkeypatch)
    assert captured["cfg_url"] == "http://localhost:8123"  # external URL left untouched
    assert captured["url"] == "http://localhost:8000"  # gateway redirected to the loopback
    assert "8123" not in captured["url"]


def test_module_app_gateway_self_url_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    """$OPENDEVOPS_SELF_URL overrides the in-container gateway target (compose sets it)."""
    monkeypatch.setenv("OPENDEVOPS_SELF_URL", "http://localhost:9999")
    captured = _capture_gateway_url(monkeypatch)
    assert captured["url"] == "http://localhost:9999"
    assert captured["cfg_url"] == "http://localhost:8123"  # still untouched
