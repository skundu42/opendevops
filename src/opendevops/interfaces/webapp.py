"""FastAPI webapp mounted into the LangGraph Server via ``langgraph.json`` ``http.app``.

Turns infrastructure events into agent runs, and exposes operational endpoints:

* ``POST /webhooks/alertmanager`` — an Alertmanager v4 webhook. Static-bearer authenticated
  (``Authorization: Bearer <token>``, constant-time compared) plus an optional source-IP
  allowlist; per alert it opens (or reuses) a *deterministic* incident thread
  ``uuid5(NS_INCIDENT, fingerprint)`` and fires an RCA run, deduping repeat fingerprints. Responds
  ``202`` fast; the run proceeds in the background.
* ``POST /webhooks/github`` — a GitHub webhook, native ``X-Hub-Signature-256`` HMAC verified over
  the raw body. A ``workflow_run`` that ``completed`` with ``conclusion="failure"`` starts a CI
  diagnosis run on thread ``uuid5(NS_INCIDENT, f"gh:{repo}:{run_id}")``; every other event is a
  ``204`` no-op.
* ``POST /webhooks/run-complete`` — the ``client.runs.create(webhook=...)`` callback; bearer
  authenticated with the same Alertmanager token, logs + counts the completion, ``204``.
* ``GET /healthz`` — unauthenticated liveness, ``200 {"status": "ok"}``.
* ``GET /metrics`` — Prometheus exposition off a per-app :class:`CollectorRegistry`.
* ``GET /dashboard`` — OIDC/RBAC operations control plane backed by live gateway state, persisted
  audit chains, and the capability-grant ledger. Browser sessions are opaque and server-side;
  static-token login is a local-development mode.

Firewall: this module depends ONLY on the :class:`~opendevops.gateway.base.AgentGateway`
protocol — it never imports ``langgraph_sdk``. All route logic runs against the injected gateway,
so tests drive :func:`create_app` with an ``AsyncMock`` stub. The module-level ``app`` (what
``langgraph.json`` imports) lazily builds a :class:`~opendevops.gateway.server.ServerGateway`
from ``$OPENDEVOPS_CONFIG``, pointed at the LOCAL server on its loopback port
(``$OPENDEVOPS_SELF_URL``, default ``http://localhost:8000``) — NOT ``cfg.server.url`` (the
external Caddy URL): this app runs inside the server container and reaches the API directly.

Security posture (fail-closed): a route whose secret env var is unset returns ``503`` — never
"auth disabled". Token/secret *values* are never logged; only env-var *names* live in config.
Bearer + HMAC comparisons are constant-time (:func:`hmac.compare_digest`) over the UTF-8 *bytes*
of each operand (see :func:`_ct_equal`), so an attacker-controlled non-ASCII header can never turn
an auth check into an unauthenticated 500. Untrusted payloads are parsed defensively: a malformed
authenticated body is ignored/4xx (never 500), per-request alert fan-out is capped, and an
oversized body is rejected with 413.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from typing import TYPE_CHECKING, Any

from fastapi import FastAPI, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Counter, generate_latest

from opendevops.interfaces.dashboard import register_dashboard
from opendevops.observability.live import LiveTelemetry
from opendevops.observability.otel import (
    configure_opentelemetry,
    observe_operation,
    span,
)

if TYPE_CHECKING:
    from opendevops.config import AppConfig
    from opendevops.gateway.base import AgentGateway
    from opendevops.interfaces.slack_app import SlackNotifier

logger = logging.getLogger(__name__)

# Stable namespace for deterministic incident thread ids: ``uuid5(NS_INCIDENT, key)``. The same
# alert fingerprint (or ``gh:<repo>:<run_id>``) always maps to the same UUID, so a repeat event
# reuses its incident thread instead of forking a new one. Derived once, pinned as a literal:
#   uuid5(uuid.NAMESPACE_URL, "https://opendevops.gnosis.io/ns/incident")
NS_INCIDENT = uuid.UUID("08173034-6b5b-58b2-b1ef-0c48953098c8")

# How long a fingerprint is remembered for in-process dedup. Well under an incident's lifetime but
# long enough to collapse Alertmanager's repeat-sends (``repeat_interval`` is typically minutes).
_DEDUP_TTL_S = 900.0

# Principals stamped onto webhook-initiated runs (audit ``principal.user``).
_PRINCIPAL_ALERTMANAGER = "alertmanager"
_PRINCIPAL_GITHUB = "github"

# Webhook runs always resolve the "incident" budget profile and originate from interface "webhook".
_INCIDENT_PROFILE = "incident"
_WEBHOOK_INTERFACE = "webhook"

# Metric outcome labels (the union the counter records for a webhook route).
_ACCEPTED = "accepted"
_DEDUPED = "deduped"
_UNAUTHORIZED = "unauthorized"
_IGNORED = "ignored"
_ERROR = "error"
_DROPPED = "dropped"

# Defense-in-depth parsing caps (Caddy + the daily budget are the real defenses; these keep a
# single malformed/hostile request from fanning out or buffering without bound):
#   * cap the alerts processed per Alertmanager request — excess is dropped LOUDLY (logged +
#     counted ``dropped``), never silently truncated;
#   * reject a webhook body larger than this many bytes with 413.
_MAX_ALERTS_PER_REQUEST = 50
_MAX_BODY_BYTES = 1 * 1024 * 1024  # 1 MiB


class _TTLSet:
    """A tiny time-bounded seen-set for fingerprint dedup (single process, single worker).

    ``see(key, now)`` returns ``True`` the first time a key is observed within the TTL window and
    ``False`` for a repeat. Expired keys are swept lazily on each call, so the set stays bounded by
    the live fingerprint set without a background task.

    Multi-worker caveat: LangGraph Server may run this app across several worker processes, each
    with its OWN ``_TTLSet``. A duplicate alert landing on a *different* worker will not be deduped
    here — the deterministic ``uuid5`` thread id + ``if_exists="do_nothing"`` keeps thread creation
    idempotent, but the RCA run could start twice. Exactly-once cross-worker dedup needs a shared
    store (Redis); that is a future hardening item, out of scope for this in-memory set.
    """

    def __init__(self, ttl_s: float) -> None:
        self._ttl = ttl_s
        self._seen: dict[str, float] = {}

    def see(self, key: str, now: float) -> bool:
        self._evict(now)
        if key in self._seen:
            return False
        self._seen[key] = now
        return True

    def _evict(self, now: float) -> None:
        cutoff = now - self._ttl
        stale = [k for k, ts in self._seen.items() if ts < cutoff]
        for k in stale:
            del self._seen[k]


class _Metrics:
    """The app's Prometheus counters on a dedicated registry (per-app, so tests stay re-entrant)."""

    def __init__(self) -> None:
        self.registry = CollectorRegistry()
        self.webhook_requests = Counter(
            "opendevops_webhook_requests_total",
            "Webhook requests handled, by route and outcome.",
            ["route", "outcome"],
            registry=self.registry,
        )
        self.runs_started = Counter(
            "opendevops_runs_started_total",
            "Agent runs started by the webhook app, by originating interface.",
            ["interface"],
            registry=self.registry,
        )

    def request(self, route: str, outcome: str, count: int = 1) -> None:
        self.webhook_requests.labels(route=route, outcome=outcome).inc(count)
        for _ in range(count):
            observe_operation(
                "webhook",
                0,
                outcome,
                {"opendevops.webhook.route": route},
            )

    def run_started(self, interface: str) -> None:
        self.runs_started.labels(interface=interface).inc()


class WebhookError(Exception):
    """A short-circuit inside a webhook handler carrying the HTTP status + metric outcome.

    Raising this (instead of returning) keeps auth/validation guards flat and guarantees the
    metric is counted exactly once at the single catch site. ``detail`` is a safe, secret-free
    string.
    """

    def __init__(self, status_code: int, outcome: str, detail: str) -> None:
        self.status_code = status_code
        self.outcome = outcome
        self.detail = detail
        super().__init__(detail)


def _resolve_secret(env_name: str | None) -> str | None:
    """Read the *value* of the env var named ``env_name`` (config holds names, never values).

    Returns ``None`` when no name is configured OR the named var is unset/empty — the caller then
    fails **closed** (503). Never logs the value.
    """
    if not env_name:
        return None
    value = os.environ.get(env_name)
    return value or None


def _ct_equal(provided: str, expected: str) -> bool:
    """Constant-time string equality that is **total** on content — it never raises.

    ``hmac.compare_digest`` on *str* operands raises ``TypeError`` the moment either side holds a
    non-ASCII character. Both auth compares below feed it attacker-controlled header strings, so a
    single ``Authorization: Bearer <non-ASCII>`` or ``X-Hub-Signature-256: sha256=<non-ASCII>``
    would otherwise crash the handler with a ``TypeError`` — an *unauthenticated* 500 generator, and
    (worse) one that escapes before the metric is counted. Comparing the UTF-8 *bytes* sidesteps
    that: any header value Starlette hands us is latin-1 decoded, so ``.encode("utf-8")`` is total,
    and ``compare_digest`` on bytes keeps the constant-time semantics (equal-length compare is
    constant time; a length mismatch short-circuits, exactly as the str path did). A non-encodable
    operand (belt-and-suspenders) is a mismatch, not an error.
    """
    try:
        return hmac.compare_digest(
            provided.encode("utf-8", "strict"), expected.encode("utf-8", "strict")
        )
    except (UnicodeError, TypeError):
        return False


def _bearer_token(request: Request) -> str | None:
    """Extract the token from an ``Authorization: Bearer <token>`` header, or ``None``."""
    header = request.headers.get("authorization")
    if not header:
        return None
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    return token


def _require_bearer(request: Request, expected_env: str | None) -> None:
    """Fail closed (503) if the token env is unset; else 401 unless the bearer matches.

    The bearer comparison is constant-time (:func:`hmac.compare_digest`).
    """
    expected = _resolve_secret(expected_env)
    if expected is None:
        raise WebhookError(503, _ERROR, "authentication is not configured")
    provided = _bearer_token(request)
    if provided is None or not _ct_equal(provided, expected):
        raise WebhookError(401, _UNAUTHORIZED, "invalid or missing bearer token")


def _check_source_allowlist(request: Request, allowlist: list[str]) -> None:
    """Reject the direct peer IP when an allowlist is set and it is not on it (403).

    Proxy headers (``X-Forwarded-For``) are deliberately ignored: Caddy fronts this app on a
    trusted network, so the direct peer is authoritative and a spoofable header must not widen it.
    """
    if not allowlist:
        return
    peer = request.client.host if request.client is not None else None
    if peer not in allowlist:
        raise WebhookError(403, _UNAUTHORIZED, "source address not permitted")


def _verify_github_signature(secret: str, body: bytes, header: str | None) -> bool:
    """Constant-time verify GitHub's ``X-Hub-Signature-256: sha256=<hex>`` over the raw body."""
    if not header:
        return False
    expected = "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return _ct_equal(expected, header)


def create_app(
    cfg: AppConfig, gateway: AgentGateway, notifier: SlackNotifier | None = None
) -> FastAPI:
    """Build the webhook FastAPI app over ``cfg`` and an injected :class:`AgentGateway`.

    All route logic runs against ``gateway`` (the protocol), so a test drives this factory with an
    ``AsyncMock`` stub; production wires a :class:`ServerGateway`. Per-app state (dedup set, metric
    registry, background-run tasks) lives on ``app.state`` so nothing leaks across app instances.

    ``notifier`` (optional; default ``None`` — every existing caller/test is unchanged) is an
    optional :class:`~opendevops.interfaces.slack_app.SlackNotifier`. When present, the
    ``run-complete`` route posts a completed run's final answer back to Slack IFF the run's thread
    is a registered Slack destination — so a server-mode run that originated in a Slack thread is
    answered there. An unregistered thread (a webhook/CLI run) is never posted.
    """
    app = FastAPI(title="opendevops webhooks", docs_url=None, redoc_url=None)
    app.state.cfg = cfg
    app.state.gateway = gateway
    app.state.notifier = notifier
    app.state.metrics = _Metrics()
    app.state.dedup = _TTLSet(_DEDUP_TTL_S)
    app.state.live_telemetry = LiveTelemetry()
    configure_opentelemetry()
    # Strong refs to in-flight background runs so the event loop does not GC a pending task; each
    # removes itself on completion (add_done_callback below).
    app.state.background_tasks = set()
    register_dashboard(app, cfg, gateway=gateway, live_telemetry=app.state.live_telemetry)

    def _spawn_run(
        thread_id: str, user_input: str, *, principal: str, interface: str
    ) -> None:
        """Fire-and-forget an incident run: idempotently ensure the thread, then run it.

        Runs entirely in the background so the webhook responds ``202`` immediately. Failures are
        logged, never surfaced (the webhook already returned) — and never with secret content.
        """

        async def _runner() -> None:
            started = time.perf_counter()
            await app.state.live_telemetry.queued(thread_id, principal, interface)
            run_id: str | None = None
            operation_status = "error"
            try:
                with span(
                    "opendevops.webhook_run",
                    {
                        "thread.id": thread_id,
                        "opendevops.interface": interface,
                        "opendevops.environment": cfg.server.webhook_environment,
                    },
                ):
                    await gateway.create_thread(thread_id=thread_id)
                    await app.state.live_telemetry.running(thread_id)
                    result = await gateway.run(
                        thread_id,
                        user_input,
                        profile=_INCIDENT_PROFILE,
                        principal=principal,
                        interface=interface,
                        environment=cfg.server.webhook_environment,
                    )
                    run_id = result.run_id
                    operation_status = "interrupted" if result.interrupted else "ok"
            except Exception as exc:  # noqa: BLE001 - background failures are projected, not leaked
                logger.exception("background webhook run failed for thread %s", thread_id)
                await app.state.live_telemetry.completed(
                    thread_id, run_id, error=type(exc).__name__
                )
            else:
                await app.state.live_telemetry.completed(thread_id, run_id)
            finally:
                observe_operation(
                    "gateway",
                    (time.perf_counter() - started) * 1000,
                    operation_status,
                    {"opendevops.interface": interface},
                )

        task = asyncio.create_task(_runner())
        app.state.background_tasks.add(task)
        task.add_done_callback(app.state.background_tasks.discard)
        app.state.metrics.run_started(interface)

    @app.post("/webhooks/alertmanager")
    async def alertmanager(request: Request) -> Response:
        metrics: _Metrics = app.state.metrics
        try:
            _require_bearer(request, cfg.server.alertmanager_token_env)
            _check_source_allowlist(request, cfg.server.source_allowlist)
            payload = await _read_json(request)
        except WebhookError as exc:
            metrics.request("alertmanager", exc.outcome)
            return _error_response(exc)

        alerts = payload.get("alerts")
        if not isinstance(alerts, list):
            metrics.request("alertmanager", _IGNORED)
            return Response(status_code=204)

        # Defense-in-depth fan-out cap: process at most _MAX_ALERTS_PER_REQUEST, and drop the excess
        # LOUDLY (log + a ``dropped`` counter) rather than silently truncating.
        if len(alerts) > _MAX_ALERTS_PER_REQUEST:
            dropped = len(alerts) - _MAX_ALERTS_PER_REQUEST
            logger.warning(
                "alertmanager fan-out capped at %d: %d received, %d dropped (defense-in-depth)",
                _MAX_ALERTS_PER_REQUEST,
                len(alerts),
                dropped,
            )
            metrics.request("alertmanager", _DROPPED, dropped)
            alerts = alerts[:_MAX_ALERTS_PER_REQUEST]

        now = asyncio.get_event_loop().time()
        incidents: list[dict[str, Any]] = []
        for alert in alerts:
            if not isinstance(alert, dict):
                metrics.request("alertmanager", _IGNORED)
                continue
            fingerprint = alert.get("fingerprint")
            if not fingerprint or not isinstance(fingerprint, str):
                metrics.request("alertmanager", _IGNORED)
                continue
            # A malformed-but-authenticated alert (labels/annotations present but not an object)
            # must never crash the handler — ignore it, never start a run, never 500.
            labels = alert.get("labels")
            annotations = alert.get("annotations")
            if (labels is not None and not isinstance(labels, dict)) or (
                annotations is not None and not isinstance(annotations, dict)
            ):
                metrics.request("alertmanager", _IGNORED)
                continue
            thread_id = str(uuid.uuid5(NS_INCIDENT, fingerprint))
            is_new = app.state.dedup.see(fingerprint, now)
            if is_new:
                _spawn_run(
                    thread_id,
                    _alert_prompt(alert, payload),
                    principal=_PRINCIPAL_ALERTMANAGER,
                    interface=_WEBHOOK_INTERFACE,
                )
                metrics.request("alertmanager", _ACCEPTED)
            else:
                metrics.request("alertmanager", _DEDUPED)
            incidents.append(
                {"fingerprint": fingerprint, "thread_id": thread_id, "deduped": not is_new}
            )
        return _json_response(202, {"incidents": incidents})

    @app.post("/webhooks/github")
    async def github(request: Request) -> Response:
        metrics: _Metrics = app.state.metrics
        secret = _resolve_secret(cfg.server.github_webhook_secret_env)
        if secret is None:
            metrics.request("github", _ERROR)
            return _json_response(503, {"detail": "webhook secret is not configured"})

        # The HMAC is computed over the raw body, so the body must be read before auth; size-guard
        # it first (413) so an oversized body cannot be buffered without bound.
        try:
            raw = await _read_body(request)
        except WebhookError as exc:
            metrics.request("github", exc.outcome)
            return _error_response(exc)
        signature = request.headers.get("x-hub-signature-256")
        if not _verify_github_signature(secret, raw, signature):
            metrics.request("github", _UNAUTHORIZED)
            return _json_response(401, {"detail": "invalid or missing signature"})

        event = request.headers.get("x-github-event")
        payload = _loads_or_none(raw)
        if event != "workflow_run" or not isinstance(payload, dict):
            metrics.request("github", _IGNORED)
            return Response(status_code=204)

        # A malformed-but-authenticated payload (workflow_run/repository not an object) must never
        # crash the handler nor start a run — ignore (204).
        workflow_run = payload.get("workflow_run")
        if not isinstance(workflow_run, dict):
            metrics.request("github", _IGNORED)
            return Response(status_code=204)
        if payload.get("action") != "completed" or workflow_run.get("conclusion") != "failure":
            metrics.request("github", _IGNORED)
            return Response(status_code=204)

        repository = payload.get("repository")
        repo = repository.get("full_name") if isinstance(repository, dict) else None
        run_id = workflow_run.get("id")
        # Never start a run for a payload missing the identifying fields — otherwise a malformed
        # event would open a bogus ``gh:unknown:None`` incident thread.
        if not repo or run_id is None:
            metrics.request("github", _IGNORED)
            return Response(status_code=204)
        key = f"gh:{repo}:{run_id}"
        thread_id = str(uuid.uuid5(NS_INCIDENT, key))
        now = asyncio.get_event_loop().time()
        is_new = app.state.dedup.see(key, now)
        if is_new:
            _spawn_run(
                thread_id,
                _github_prompt(repo, workflow_run),
                principal=_PRINCIPAL_GITHUB,
                interface=_WEBHOOK_INTERFACE,
            )
            metrics.request("github", _ACCEPTED)
        else:
            metrics.request("github", _DEDUPED)
        return _json_response(202, {"thread_id": thread_id, "deduped": not is_new})

    @app.post("/webhooks/run-complete")
    async def run_complete(request: Request) -> Response:
        metrics: _Metrics = app.state.metrics
        try:
            _require_bearer(request, cfg.server.alertmanager_token_env)
            payload = await _read_json(request)
        except WebhookError as exc:
            metrics.request("run-complete", exc.outcome)
            return _error_response(exc)

        # Log + count the completion. The values here are run metadata (ids, status), not secrets.
        logger.info(
            "run-complete callback: thread=%s status=%s",
            payload.get("thread_id"),
            payload.get("status"),
        )
        metrics.request("run-complete", _ACCEPTED)
        # Slack seam: post the final answer to Slack for a completed run whose thread originated
        # in a Slack thread. Additive + fail-safe: only when a notifier is wired AND the thread is a
        # registered Slack destination; a posting failure is logged, never surfaced (already 204).
        await _notify_slack(app.state.notifier, payload)
        return Response(status_code=204)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/metrics")
    async def metrics_endpoint() -> Response:
        data = generate_latest(app.state.metrics.registry)
        return Response(content=data, media_type=CONTENT_TYPE_LATEST)

    return app


async def _notify_slack(notifier: SlackNotifier | None, payload: dict[str, Any]) -> None:
    """Post a completed run's final answer to Slack, gated on a registered Slack destination.

    No-op unless a notifier is wired AND ``payload.thread_id`` is a registered Slack destination
    (an unregistered thread — a webhook/CLI run — is never posted). A malformed payload or a Slack
    API failure is swallowed (logged): the run-complete callback already returns 204.
    """
    if notifier is None:
        return
    thread_id = payload.get("thread_id")
    if not isinstance(thread_id, str) or not thread_id:
        return
    if notifier.destination_for(thread_id) is None:
        return
    try:
        await notifier.post_final(thread_id, _final_answer_text(payload))
    except Exception:  # noqa: BLE001 - a Slack post failure must not fail the 204 callback
        logger.exception("posting the final answer to Slack failed for thread %s", thread_id)


def _final_answer_text(payload: dict[str, Any]) -> str:
    """The run's final answer text from a run-complete payload, defensively.

    Prefers an explicit ``final_text``; falls back to the last assistant text in an ``output`` /
    ``values`` messages list (the LangGraph Server run snapshot); else a generic completion note.
    """
    explicit = payload.get("final_text")
    if isinstance(explicit, str) and explicit.strip():
        return explicit
    output = payload.get("output") or payload.get("values")
    if isinstance(output, dict):
        messages = output.get("messages")
        if isinstance(messages, list):
            for message in reversed(messages):
                if isinstance(message, dict) and message.get("type") == "ai":
                    content = message.get("content")
                    if isinstance(content, str) and content.strip():
                        return content
    return "Run completed."


async def _read_body(request: Request) -> bytes:
    """Read the raw body, rejecting an oversized one with 413 (counted ``error``).

    Defense-in-depth behind Caddy: a declared ``Content-Length`` over the cap is rejected before
    the body is read at all; the post-read length check catches a lying/absent header. Simple by
    design — Caddy and the daily budget are the real bulkheads.
    """
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > _MAX_BODY_BYTES:
                raise WebhookError(413, _ERROR, "request body too large")
        except ValueError:
            pass  # malformed Content-Length — fall through to the post-read guard
    raw = await request.body()
    if len(raw) > _MAX_BODY_BYTES:
        raise WebhookError(413, _ERROR, "request body too large")
    return raw


async def _read_json(request: Request) -> dict[str, Any]:
    """Parse a JSON object body or raise a :class:`WebhookError` (400, counted ``error``)."""
    raw = await _read_body(request)
    payload = _loads_or_none(raw)
    if not isinstance(payload, dict):
        raise WebhookError(400, _ERROR, "request body must be a JSON object")
    return payload


def _loads_or_none(raw: bytes) -> Any:
    try:
        return json.loads(raw)
    except ValueError:  # JSONDecodeError is a ValueError subclass
        return None


def _error_response(exc: WebhookError) -> Response:
    return _json_response(exc.status_code, {"detail": exc.detail})


def _json_response(status_code: int, body: dict[str, Any]) -> Response:
    return Response(
        content=json.dumps(body), status_code=status_code, media_type="application/json"
    )


def _as_dict(value: Any) -> dict[str, Any]:
    """Coerce a JSON value to a dict — anything that is not already a dict becomes ``{}``.

    Belt-and-suspenders so prompt building can never raise on a malformed (but authenticated)
    payload, even though the route already ignores alerts with non-object labels/annotations.
    """
    return value if isinstance(value, dict) else {}


def _alert_prompt(alert: dict[str, Any], payload: dict[str, Any]) -> str:
    """A concise RCA task string from an Alertmanager alert (labels/annotations, no secrets)."""
    labels = _as_dict(alert.get("labels")) or _as_dict(payload.get("commonLabels"))
    annotations = _as_dict(alert.get("annotations")) or _as_dict(payload.get("commonAnnotations"))
    name = labels.get("alertname", "unknown")
    severity = labels.get("severity", "unknown")
    summary = annotations.get("summary") or annotations.get("description") or ""
    status = alert.get("status") or payload.get("status") or "firing"
    return (
        f"Alertmanager alert {name!r} (severity={severity}, status={status}) fired. "
        f"Summary: {summary}. Labels: {json.dumps(labels, sort_keys=True)}. "
        "Perform a root-cause analysis and propose remediation."
    )


def _github_prompt(repo: str, workflow_run: dict[str, Any]) -> str:
    """A CI-diagnosis task string from a failed GitHub ``workflow_run``."""
    name = workflow_run.get("name", "workflow")
    branch = workflow_run.get("head_branch", "unknown")
    url = workflow_run.get("html_url", "")
    return (
        f"GitHub Actions workflow {name!r} failed on {repo}@{branch}. "
        f"Run: {url}. Diagnose the CI failure and propose a fix."
    )


# --------------------------------------------------------------------------------------
# module-level ``app`` for langgraph.json (``http.app``): lazily built from config + ServerGateway
# --------------------------------------------------------------------------------------

_DEFAULT_APP: FastAPI | None = None

# The webhook app runs INSIDE the ``langgraph-server`` container, so its gateway must reach the
# LOCAL server API directly on the loopback port — NOT ``cfg.server.url`` (the external Caddy URL,
# :8123, a DIFFERENT container). ``$OPENDEVOPS_SELF_URL`` overrides the gateway target for this
# in-process path only; its default is the server's in-container listen port. Hitting the server
# directly bypasses Caddy and its bearer, so no api_key is needed here (see docs/DEPLOY.md).
_SELF_URL_ENV = "OPENDEVOPS_SELF_URL"
_DEFAULT_SELF_URL = "http://localhost:8000"


def _build_default_app() -> FastAPI:
    """Build the production app: config from ``$OPENDEVOPS_CONFIG``, a ``ServerGateway`` client.

    Kept out of import time (see :func:`__getattr__`) so importing this module never touches the
    filesystem config or constructs an SDK client — tests build :func:`create_app` with a stub.

    The gateway targets ``$OPENDEVOPS_SELF_URL`` (default ``http://localhost:8000``) — the local
    server's loopback port — NOT ``cfg.server.url`` (the external Caddy URL). Every OTHER dependency
    on ``cfg`` (webhook secrets, environment, allowlist) is unchanged; only the gateway's target URL
    is redirected so in-container webhook runs reach the local API directly (bypassing Caddy).
    """
    from opendevops.agent import _load_server_config
    from opendevops.gateway import ServerGateway

    cfg = _load_server_config()
    self_url = os.environ.get(_SELF_URL_ENV) or _DEFAULT_SELF_URL
    gateway = ServerGateway(cfg, url=self_url)
    return create_app(cfg, gateway)


def __getattr__(name: str) -> Any:
    """PEP 562 lazy export: ``webapp.app`` builds the default app once, on first access.

    ``langgraph.json`` resolves ``./src/opendevops/interfaces/webapp.py:app`` at server startup;
    guarding the build behind attribute access means merely importing this module (as the tests do)
    never requires an on-disk config or a reachable server.
    """
    if name == "app":
        global _DEFAULT_APP
        if _DEFAULT_APP is None:
            _DEFAULT_APP = _build_default_app()
        return _DEFAULT_APP
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
