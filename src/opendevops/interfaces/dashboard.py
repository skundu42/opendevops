"""Authenticated operations dashboard for the service-mode agent.

The dashboard is intentionally read-only. It derives its end-to-end view from the same per-run
audit chains used for verification, so the UI does not introduce a second observability truth:
run lifecycle, policy decisions, executions, escalations, costs, principals, and integrity all
come from persisted :class:`~opendevops.audit.schema.AuditEvent` records.

Browser authentication is separate from the LangGraph API bearer. A configured login token is
constant-time compared and exchanged for a short-lived HMAC-authenticated HttpOnly cookie. The
raw token never enters browser storage or a response body. Missing configuration fails closed.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import time
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response

from opendevops.audit.schema import AuditEvent, EventType
from opendevops.audit.verify import verify_run_file

if TYPE_CHECKING:
    from opendevops.config import AppConfig

_ASSET_DIR = Path(__file__).with_name("dashboard_assets")
_ASSETS = {
    "dashboard.css": "text/css; charset=utf-8",
    "dashboard.js": "application/javascript; charset=utf-8",
    "login.js": "application/javascript; charset=utf-8",
    "logo.png": "image/png",
}
_COOKIE_NAME = "opendevops_dashboard_session"
_SESSION_CONTEXT = "opendevops-dashboard-v1"
_MAX_LOGIN_BODY = 4096
_MAX_AUDIT_FILES = 200
_MAX_AUDIT_FILE_BYTES = 16 * 1024 * 1024
_RECENT_RUNS = 24

_CSP = (
    "default-src 'self'; "
    "base-uri 'none'; "
    "connect-src 'self'; "
    "font-src 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    "img-src 'self' data:; "
    "object-src 'none'; "
    "script-src 'self'; "
    "style-src 'self'"
)


def _security_headers(*, cache: str = "no-store") -> dict[str, str]:
    return {
        "Cache-Control": cache,
        "Content-Security-Policy": _CSP,
        "Cross-Origin-Opener-Policy": "same-origin",
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
    }


def _secret(cfg: AppConfig) -> str | None:
    name = cfg.server.dashboard_token_env
    if not name:
        return None
    return os.environ.get(name) or None


def _constant_time_equal(provided: str, expected: str) -> bool:
    try:
        return hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))
    except (TypeError, UnicodeError):
        return False


def _session_signature(secret: str, expires_at: int) -> str:
    message = f"{_SESSION_CONTEXT}:{expires_at}".encode()
    return hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()


def _new_session(secret: str, ttl_s: int) -> str:
    expires_at = int(time.time()) + ttl_s
    return f"{expires_at}.{_session_signature(secret, expires_at)}"


def _valid_session(request: Request, cfg: AppConfig) -> bool:
    secret = _secret(cfg)
    value = request.cookies.get(_COOKIE_NAME)
    if secret is None or value is None:
        return False
    expires_raw, separator, signature = value.partition(".")
    if not separator:
        return False
    try:
        expires_at = int(expires_raw)
    except ValueError:
        return False
    now = int(time.time())
    # The upper bound prevents an attacker with an old valid cookie from extending it by editing
    # the timestamp; the HMAC already prevents forgery, and this additionally pins config changes.
    if expires_at <= now or expires_at > now + cfg.server.dashboard_session_ttl_s:
        return False
    return _constant_time_equal(signature, _session_signature(secret, expires_at))


def _html(name: str, *, error: str = "") -> HTMLResponse:
    template = (_ASSET_DIR / name).read_text(encoding="utf-8")
    body = template.replace("{{AUTH_ERROR}}", error)
    return HTMLResponse(body, headers=_security_headers())


def _auth_required(request: Request, cfg: AppConfig) -> Response | None:
    if _valid_session(request, cfg):
        return None
    if request.url.path.startswith("/dashboard/api/"):
        return JSONResponse(
            {"detail": "dashboard authentication required"},
            status_code=401,
            headers=_security_headers(),
        )
    return RedirectResponse("/dashboard/login", status_code=303, headers=_security_headers())


def register_dashboard(app: FastAPI, cfg: AppConfig) -> None:
    """Register login, asset, UI, and snapshot routes on the existing FastAPI application."""

    @app.get("/dashboard/assets/{asset_name}")
    async def dashboard_asset(asset_name: str) -> Response:
        media_type = _ASSETS.get(asset_name)
        if media_type is None:
            return Response(status_code=404, headers=_security_headers())
        return FileResponse(
            _ASSET_DIR / asset_name,
            media_type=media_type,
            headers=_security_headers(cache="public, max-age=3600"),
        )

    @app.get("/dashboard/login")
    async def dashboard_login(request: Request) -> Response:
        if _valid_session(request, cfg):
            return RedirectResponse("/dashboard", status_code=303, headers=_security_headers())
        return _html("login.html")

    @app.post("/dashboard/login")
    async def dashboard_login_submit(request: Request) -> Response:
        expected = _secret(cfg)
        if expected is None:
            error_response = _html(
                "login.html",
                error="Dashboard authentication is not configured. Set the configured token.",
            )
            error_response.status_code = 503
            return error_response
        raw = await request.body()
        if len(raw) > _MAX_LOGIN_BODY:
            oversized_response = _html(
                "login.html", error="The submitted credential is invalid."
            )
            oversized_response.status_code = 413
            return oversized_response
        try:
            token = parse_qs(raw.decode("utf-8"), keep_blank_values=True).get("token", [""])[0]
        except UnicodeError:
            token = ""
        if not _constant_time_equal(token, expected):
            invalid_response = _html(
                "login.html", error="The submitted credential is invalid."
            )
            invalid_response.status_code = 401
            return invalid_response

        success_response = RedirectResponse(
            "/dashboard", status_code=303, headers=_security_headers()
        )
        success_response.set_cookie(
            _COOKIE_NAME,
            _new_session(expected, cfg.server.dashboard_session_ttl_s),
            max_age=cfg.server.dashboard_session_ttl_s,
            httponly=True,
            secure=cfg.server.dashboard_cookie_secure,
            samesite="strict",
            path="/dashboard",
        )
        return success_response

    @app.post("/dashboard/logout")
    async def dashboard_logout() -> Response:
        response = RedirectResponse(
            "/dashboard/login", status_code=303, headers=_security_headers()
        )
        response.delete_cookie(_COOKIE_NAME, path="/dashboard")
        return response

    @app.get("/dashboard")
    async def dashboard(request: Request) -> Response:
        denied = _auth_required(request, cfg)
        return denied if denied is not None else _html("index.html")

    @app.get("/dashboard/api/snapshot")
    async def dashboard_snapshot(request: Request) -> Response:
        denied = _auth_required(request, cfg)
        if denied is not None:
            return denied
        snapshot = await asyncio.to_thread(build_dashboard_snapshot, cfg)
        return JSONResponse(snapshot, headers=_security_headers())


def _parse_events(path: Path) -> tuple[list[AuditEvent], str | None]:
    try:
        if path.stat().st_size > _MAX_AUDIT_FILE_BYTES:
            return [], "audit file exceeds dashboard safety limit"
        events = [
            AuditEvent.model_validate_json(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except (OSError, ValueError) as exc:
        return [], f"{type(exc).__name__}: audit chain could not be parsed"
    return events, None


def _as_float(value: Any) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _counted(value: int, singular: str) -> str:
    suffix = "" if value == 1 else "s"
    return f"{value} {singular}{suffix}"


def _status(events: list[AuditEvent]) -> str:
    completed = next(
        (event for event in reversed(events) if event.event_type is EventType.run_completed), None
    )
    if completed is not None:
        return str((completed.summary or {}).get("status") or "completed")
    last_escalation = max(
        (index for index, event in enumerate(events) if event.event_type is EventType.escalation),
        default=-1,
    )
    last_resolution = max(
        (index for index, event in enumerate(events) if event.event_type is EventType.resolution),
        default=-1,
    )
    return "awaiting_approval" if last_escalation > last_resolution else "running"


def _run_record(path: Path) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    events, parse_error = _parse_events(path)
    if not events:
        if parse_error is None:
            return None, []
        return (
            {
                "run_id": path.stem,
                "status": "corrupt",
                "integrity": "failed",
                "error": parse_error,
                "updated_at": None,
                "started_at": None,
                "principal": "unknown",
                "interface": "unknown",
                "environment": "unknown",
                "model": None,
                "policy_version": None,
                "cost_usd": 0.0,
                "duration_ms": 0,
                "decisions": 0,
                "executions": 0,
                "denials": 0,
                "escalations": 0,
                "events": 0,
            },
            [],
        )

    seed = events[0]
    completed = next(
        (event for event in reversed(events) if event.event_type is EventType.run_completed), None
    )
    summary = completed.summary if completed is not None and completed.summary else {}
    started_at = _parse_ts(seed.ts)
    updated_at = _parse_ts(events[-1].ts)
    duration_ms = (
        max(0, int((updated_at - started_at).total_seconds() * 1000))
        if started_at is not None and updated_at is not None
        else 0
    )
    decisions = [event for event in events if event.event_type is EventType.decision]
    executions = [event for event in events if event.event_type is EventType.execution]
    denials = sum(
        1
        for event in decisions
        if event.decision is not None and event.decision.effect == "deny"
    )
    escalations = sum(1 for event in events if event.event_type is EventType.escalation)
    integrity = verify_run_file(path, require_complete=False)
    record = {
        "run_id": seed.run_id,
        "thread_id": seed.thread_id,
        "status": _status(events),
        "integrity": "verified" if integrity.ok else "failed",
        "error": parse_error or integrity.reason,
        "updated_at": events[-1].ts,
        "started_at": seed.ts,
        "principal": seed.principal.user,
        "interface": seed.principal.interface,
        "environment": seed.environment,
        "model": seed.model,
        "policy_version": seed.policy_version,
        "cost_usd": _as_float(summary.get("cost_authoritative", summary.get("cost_state"))),
        "duration_ms": duration_ms,
        "decisions": len(decisions),
        "executions": len(executions),
        "denials": denials,
        "escalations": escalations,
        "events": len(events),
    }
    timeline = [
        {
            "event_id": event.event_id,
            "run_id": event.run_id,
            "ts": event.ts,
            "type": event.event_type.value,
            "tool": event.tool,
            "effect": event.decision.effect if event.decision is not None else None,
            "rule_id": event.decision.rule_id if event.decision is not None else None,
            "exit_code": event.execution.exit_code if event.execution is not None else None,
        }
        for event in events[-16:]
    ]
    return record, timeline


def _integration_snapshot(cfg: AppConfig) -> list[dict[str, Any]]:
    return [
        {
            "name": "Kubernetes",
            "state": "configured" if cfg.targets.kubernetes.allowed_contexts else "blocked",
            "detail": (
                f"{_counted(len(cfg.targets.kubernetes.allowed_contexts), 'context')} allowlisted"
            ),
        },
        {
            "name": "GitHub",
            "state": "configured" if cfg.targets.github.token_env else "not_configured",
            "detail": (
                "read credential configured"
                if cfg.targets.github.token_env
                else "read credential required"
            ),
        },
        {
            "name": "AWS",
            "state": "configured" if cfg.targets.aws.credential_env else "not_configured",
            "detail": _counted(len(cfg.targets.aws.credential_env), "credential variable"),
        },
        {
            "name": "Google Cloud",
            "state": "configured" if cfg.targets.gcloud.credential_env else "not_configured",
            "detail": _counted(len(cfg.targets.gcloud.credential_env), "credential variable"),
        },
        {
            "name": "Azure",
            "state": "configured" if cfg.targets.azure.credential_env else "not_configured",
            "detail": _counted(len(cfg.targets.azure.credential_env), "credential variable"),
        },
        {
            "name": "SSH",
            "state": "configured" if cfg.targets.ssh.key_env else "not_configured",
            "detail": f"{_counted(len(cfg.targets.ssh.hosts), 'host')} allowlisted",
        },
        {
            "name": "Alertmanager",
            "state": (
                "configured" if cfg.server.alertmanager_token_env else "not_configured"
            ),
            "detail": "bearer-authenticated webhook",
        },
        {
            "name": "GitHub webhooks",
            "state": (
                "configured" if cfg.server.github_webhook_secret_env else "not_configured"
            ),
            "detail": "HMAC-SHA256 authenticated",
        },
        {
            "name": "Slack",
            "state": (
                "configured"
                if cfg.slack.bot_token_env and cfg.slack.app_token_env
                else "not_configured"
            ),
            "detail": (
                "Socket Mode credentials configured"
                if cfg.slack.bot_token_env and cfg.slack.app_token_env
                else "Socket Mode credentials required"
            ),
        },
        {
            "name": "Scheduler",
            "state": "configured" if cfg.scheduler.jobs_file else "not_configured",
            "detail": "validated job schedule",
        },
    ]


def build_dashboard_snapshot(cfg: AppConfig) -> dict[str, Any]:
    """Build a bounded, secret-free snapshot from persisted audit chains and typed config."""
    audit_dir = Path(cfg.audit.dir)
    try:
        paths = sorted(
            audit_dir.glob("*.jsonl"), key=lambda path: path.stat().st_mtime, reverse=True
        )[:_MAX_AUDIT_FILES]
    except OSError:
        paths = []

    records: list[dict[str, Any]] = []
    latest_timeline: list[dict[str, Any]] = []
    for path in paths:
        record, timeline = _run_record(path)
        if record is None:
            continue
        records.append(record)
        if not latest_timeline and timeline:
            latest_timeline = timeline

    records.sort(key=lambda run: run.get("updated_at") or "", reverse=True)
    now = datetime.now(UTC)
    today = now.date().isoformat()
    today_records = [
        run for run in records if str(run.get("started_at") or "").startswith(today)
    ]
    completed_today = [
        run
        for run in today_records
        if run["status"] not in {"running", "awaiting_approval", "corrupt"}
    ]
    successful_today = sum(1 for run in completed_today if run["status"] == "completed")
    status_counts = Counter(str(run["status"]) for run in records)
    interface_counts = Counter(str(run["interface"]) for run in records)
    environment_counts = Counter(str(run["environment"]) for run in records)

    daily: dict[str, dict[str, Any]] = defaultdict(lambda: {"runs": 0, "cost_usd": 0.0})
    start_day = (now - timedelta(days=6)).date()
    for offset in range(7):
        day = (start_day + timedelta(days=offset)).isoformat()
        daily[day]  # seed zero-value days for a stable chart
    for run in records:
        day = str(run.get("started_at") or "")[:10]
        if day in daily:
            daily[day]["runs"] += 1
            daily[day]["cost_usd"] += run["cost_usd"]

    policy = {
        "decisions": sum(int(run["decisions"]) for run in records),
        "executions": sum(int(run["executions"]) for run in records),
        "denials": sum(int(run["denials"]) for run in records),
        "escalations": sum(int(run["escalations"]) for run in records),
    }
    latest = records[0] if records else None
    return {
        "generated_at": now.isoformat().replace("+00:00", "Z"),
        "overview": {
            "runs_today": len(today_records),
            "active_runs": status_counts["running"] + status_counts["awaiting_approval"],
            "success_rate": (
                round(successful_today / len(completed_today) * 100, 1)
                if completed_today
                else None
            ),
            "cost_today_usd": round(sum(run["cost_usd"] for run in today_records), 6),
            "daily_budget_usd": cfg.budgets.daily.global_usd,
            "audit_verified": sum(1 for run in records if run["integrity"] == "verified"),
            "audit_failed": sum(1 for run in records if run["integrity"] == "failed"),
        },
        "policy": policy,
        "status_counts": dict(status_counts),
        "interface_counts": dict(interface_counts),
        "environment_counts": dict(environment_counts),
        "daily": [
            {
                "date": day,
                "runs": values["runs"],
                "cost_usd": round(values["cost_usd"], 6),
            }
            for day, values in sorted(daily.items())
        ],
        "runs": records[:_RECENT_RUNS],
        "latest_timeline": latest_timeline,
        "runtime": {
            "executor_mode": cfg.executor.mode,
            "model": latest.get("model") if latest else cfg.models.resolve("main"),
            "policy_version": latest.get("policy_version") if latest else None,
        },
        "integrations": _integration_snapshot(cfg),
    }
