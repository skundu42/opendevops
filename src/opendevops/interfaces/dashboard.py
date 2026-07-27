"""OIDC/RBAC operations dashboard over live control-plane and verified audit telemetry."""

from __future__ import annotations

import asyncio
import hashlib
import html
import json
import logging
import re
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import parse_qs

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sse_starlette.sse import EventSourceResponse

from opendevops.audit.schema import AuditEvent, EventType
from opendevops.audit.verify import verify_run_file
from opendevops.control_plane import (
    CapabilityGrantRequest,
    ChangeControlError,
    ChangeControlService,
)
from opendevops.gateway.base import (
    AssistantText,
    EscalationEvent,
    GatewayError,
    RunEnd,
    ToolCall,
    ToolResult,
)
from opendevops.interfaces.dashboard_auth import (
    DashboardAuth,
    DashboardAuthError,
    DashboardSession,
    build_session_store,
    require_permission,
    validate_csrf,
)
from opendevops.interfaces.dashboard_chat import DashboardChatError, DashboardChatStore

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from opendevops.config import AppConfig
    from opendevops.gateway.base import AgentGateway
    from opendevops.observability.live import LiveTelemetry

_ASSET_DIR = Path(__file__).with_name("dashboard_assets")
_GENERATED_ASSET_DIR = _ASSET_DIR / "generated"
_ASSETS = {
    "dashboard.css": "text/css; charset=utf-8",
    "dashboard.js": "application/javascript; charset=utf-8",
    "login.js": "application/javascript; charset=utf-8",
    "logo.png": "image/png",
}
_COOKIE_NAME = "opendevops_dashboard_session"
_MAX_LOGIN_BODY = 4096
_MAX_API_BODY = 32 * 1024
_MAX_AUDIT_FILES = 200
_MAX_AUDIT_FILE_BYTES = 16 * 1024 * 1024
_RECENT_RUNS = 24
_MAX_CHAT_RESPONSE_CHARS = 100_000

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


def _html(
    name: str,
    *,
    error: str = "",
    session: DashboardSession | None = None,
    auth_mode: str = "static",
    chat_enabled: bool = True,
    chat_max_message_chars: int = 8000,
) -> HTMLResponse:
    template = (_ASSET_DIR / name).read_text(encoding="utf-8")
    replacements = {
        "{{AUTH_ERROR}}": html.escape(error),
        "{{CSRF_TOKEN}}": html.escape(session.csrf_token if session else ""),
        "{{IDENTITY_NAME}}": html.escape(
            (session.display_name or session.email or session.subject) if session else ""
        ),
        "{{IDENTITY_ROLES}}": html.escape(", ".join(session.roles) if session else ""),
        "{{STATIC_FORM_CLASS}}": "" if auth_mode == "static" else "is-hidden",
        "{{OIDC_FORM_CLASS}}": "" if auth_mode == "oidc" else "is-hidden",
        "{{CHAT_ENABLED}}": "true" if chat_enabled else "false",
        "{{CHAT_SECTION_CLASS}}": "" if chat_enabled else "is-hidden",
        "{{CHAT_MAX_MESSAGE_CHARS}}": str(chat_max_message_chars),
    }
    body = template
    for marker, value in replacements.items():
        body = body.replace(marker, value)
    return HTMLResponse(body, headers=_security_headers())


class ApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decisions: list[dict[str, Any]] = Field(min_length=1, max_length=10)


class SessionRevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    issuer: str = Field(min_length=1, max_length=500)
    subject: str = Field(min_length=1, max_length=500)


class ChatThreadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    environment: Literal["staging", "prod"] = "staging"


class ChatMessageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message: str = Field(min_length=1, max_length=24_000)


async def _json_model(request: Request, model: type[BaseModel]) -> BaseModel:
    raw = await request.body()
    if len(raw) > _MAX_API_BODY:
        raise DashboardAuthError("request body is too large")
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise DashboardAuthError("request body must be valid JSON") from exc
    try:
        return model.model_validate(payload)
    except ValidationError as exc:
        raise DashboardAuthError("request body does not match the API schema") from exc


def _error(detail: str, status: int) -> JSONResponse:
    return JSONResponse({"detail": detail}, status_code=status, headers=_security_headers())


def _bounded_chat_text(value: str, limit: int = _MAX_CHAT_RESPONSE_CHARS) -> str:
    if len(value) <= limit:
        return value
    return f"{value[:limit].rstrip()}\n\n[Response truncated by dashboard transcript limit.]"


def _chat_error(exc: DashboardChatError) -> JSONResponse:
    detail = str(exc)
    return _error(detail, 404 if detail == "chat thread not found" else 409)


def _set_session_cookie(response: Response, token: str, cfg: AppConfig) -> None:
    response.set_cookie(
        _COOKIE_NAME,
        token,
        max_age=cfg.server.dashboard_session_ttl_s,
        httponly=True,
        secure=cfg.server.dashboard_cookie_secure,
        samesite="strict",
        path="/dashboard",
    )


async def _live_snapshot(gateway: AgentGateway, live_telemetry: LiveTelemetry) -> dict[str, Any]:
    local = await live_telemetry.snapshot()
    getter = getattr(gateway, "live_snapshot", None)
    gateway_state: dict[str, Any] = {}
    if getter is not None:
        try:
            observed = await getter()
            gateway_state = observed if isinstance(observed, dict) else {}
        except Exception:  # noqa: BLE001 - dashboard telemetry degrades independently
            gateway_state = {"source": "unavailable"}
    active = {
        (str(item.get("thread_id") or ""), str(item.get("run_id") or "")): item
        for item in [*local.get("active_runs", []), *gateway_state.get("active_runs", [])]
    }
    return {
        **local,
        **gateway_state,
        "active_runs": list(active.values()),
        "pending_approvals": gateway_state.get("pending_approvals", []),
        "queue_depth": local.get("queue_depth", 0),
        "worker_active": local.get("worker_active", 0),
    }


def register_dashboard(
    app: FastAPI,
    cfg: AppConfig,
    *,
    gateway: AgentGateway,
    live_telemetry: LiveTelemetry,
) -> None:
    """Register OIDC/RBAC UI, chat, live SSE, run control, and configuration routes."""
    missing_browser_assets = [
        name for name in ("dashboard.js", "login.js") if not (_GENERATED_ASSET_DIR / name).is_file()
    ]
    if missing_browser_assets:
        raise RuntimeError(
            "compiled dashboard assets are missing; run `npm ci && npm run frontend:build`"
        )
    auth = DashboardAuth(cfg=cfg, store=build_session_store(cfg))
    from opendevops.storage import ControlDatabase, resolve_store_config

    control_db = ControlDatabase(
        resolve_store_config(
            backend=cfg.control_plane.backend,
            database=cfg.control_plane.database,
            database_url_env=cfg.control_plane.database_url_env,
        )
    )
    change_control = ChangeControlService(cfg.control_plane, database=control_db)
    chat_store = DashboardChatStore(
        control_db,
        retention_days=cfg.server.dashboard_chat_retention_days,
    )
    app.state.dashboard_auth = auth
    app.state.change_control = change_control
    app.state.dashboard_chat = chat_store

    async def _session(request: Request) -> DashboardSession | None:
        return await auth.current(request.cookies.get(_COOKIE_NAME))

    async def _api_session(
        request: Request, permission: str = "dashboard.read"
    ) -> tuple[DashboardSession | None, Response | None]:
        session = await _session(request)
        if session is None:
            return None, _error("dashboard authentication required", 401)
        try:
            require_permission(session, permission)
        except DashboardAuthError as exc:
            return None, _error(str(exc), 403)
        return session, None

    @app.get("/dashboard/assets/{asset_name}")
    async def dashboard_asset(asset_name: str) -> Response:
        media_type = _ASSETS.get(asset_name)
        if media_type is None:
            return Response(status_code=404, headers=_security_headers())
        asset_dir = _GENERATED_ASSET_DIR if asset_name.endswith(".js") else _ASSET_DIR
        return FileResponse(
            asset_dir / asset_name,
            media_type=media_type,
            headers=_security_headers(cache="public, max-age=3600"),
        )

    @app.get("/dashboard/login")
    async def dashboard_login(request: Request) -> Response:
        if await _session(request):
            return RedirectResponse("/dashboard", status_code=303, headers=_security_headers())
        return _html("login.html", auth_mode=cfg.server.dashboard_auth_mode)

    @app.post("/dashboard/login")
    async def dashboard_login_submit(request: Request) -> Response:
        if cfg.server.dashboard_auth_mode != "static":
            return _error("static-token login is disabled", 404)
        raw = await request.body()
        if len(raw) > _MAX_LOGIN_BODY:
            oversized_response = _html("login.html", error="The submitted credential is invalid.")
            oversized_response.status_code = 413
            return oversized_response
        try:
            token = parse_qs(raw.decode("utf-8"), keep_blank_values=True).get("token", [""])[0]
        except UnicodeError:
            token = ""
        try:
            session_token, session = await auth.static_login(token)
        except DashboardAuthError as exc:
            status = 503 if "not configured" in str(exc) else 401
            invalid_response = _html(
                "login.html", error=str(exc), auth_mode=cfg.server.dashboard_auth_mode
            )
            invalid_response.status_code = status
            return invalid_response
        change_control.record_action("auth.login", session.identity, {"mode": "static"})
        success_response = RedirectResponse(
            "/dashboard", status_code=303, headers=_security_headers()
        )
        _set_session_cookie(success_response, session_token, cfg)
        return success_response

    @app.get("/dashboard/oidc/login")
    async def dashboard_oidc_login() -> Response:
        try:
            return RedirectResponse(
                await auth.begin_oidc(), status_code=302, headers=_security_headers()
            )
        except (DashboardAuthError, httpx.HTTPError) as exc:
            logger.warning(
                "OIDC authorization could not be started (%s)", type(exc).__name__
            )
            return _html(
                "login.html",
                error="OIDC login is temporarily unavailable.",
                auth_mode=cfg.server.dashboard_auth_mode,
            )

    @app.get("/dashboard/oidc/callback")
    async def dashboard_oidc_callback(request: Request) -> Response:
        if request.query_params.get("error"):
            return _html(
                "login.html",
                error="The identity provider refused the login.",
                auth_mode=cfg.server.dashboard_auth_mode,
            )
        try:
            session_token, session = await auth.complete_oidc(
                state=request.query_params.get("state"),
                code=request.query_params.get("code"),
            )
        except Exception as exc:  # noqa: BLE001 - fail closed without leaking provider tokens
            logger.warning("OIDC callback validation failed (%s)", type(exc).__name__)
            return _html(
                "login.html",
                error="OIDC login failed. Please try again or contact an administrator.",
                auth_mode=cfg.server.dashboard_auth_mode,
            )
        change_control.record_action("auth.login", session.identity, {"mode": "oidc"})
        response = RedirectResponse("/dashboard", status_code=303, headers=_security_headers())
        _set_session_cookie(response, session_token, cfg)
        return response

    @app.post("/dashboard/logout")
    async def dashboard_logout(request: Request) -> Response:
        session = await _session(request)
        token = request.cookies.get(_COOKIE_NAME)
        if session is not None:
            try:
                validate_csrf(session, request.headers.get("x-csrf-token"))
            except DashboardAuthError as exc:
                return _error(str(exc), 403)
            change_control.record_action("auth.logout", session.identity)
        if token:
            await auth.store.delete(token)
        response = RedirectResponse(
            "/dashboard/login", status_code=303, headers=_security_headers()
        )
        response.delete_cookie(_COOKIE_NAME, path="/dashboard")
        return response

    @app.get("/dashboard")
    async def dashboard(request: Request) -> Response:
        session = await _session(request)
        if session is None:
            return RedirectResponse(
                "/dashboard/login", status_code=303, headers=_security_headers()
            )
        return _html(
            "index.html",
            session=session,
            auth_mode=cfg.server.dashboard_auth_mode,
            chat_enabled=cfg.server.dashboard_chat_enabled,
            chat_max_message_chars=cfg.server.dashboard_chat_max_message_chars,
        )

    @app.get("/dashboard/api/chat/threads")
    async def dashboard_chat_threads(request: Request) -> Response:
        if not cfg.server.dashboard_chat_enabled:
            return _error("dashboard chat is disabled", 404)
        session, denied = await _api_session(request, "chat.use")
        if denied is not None:
            return denied
        assert session is not None
        return JSONResponse(
            {
                "items": [
                    item.model_dump(mode="json")
                    for item in chat_store.list_threads(session.identity)
                ]
            },
            headers=_security_headers(),
        )

    @app.post("/dashboard/api/chat/threads")
    async def dashboard_create_chat_thread(request: Request) -> Response:
        if not cfg.server.dashboard_chat_enabled:
            return _error("dashboard chat is disabled", 404)
        session, denied = await _api_session(request, "chat.use")
        if denied is not None:
            return denied
        assert session is not None
        try:
            validate_csrf(session, request.headers.get("x-csrf-token"))
            body = await _json_model(request, ChatThreadRequest)
            assert isinstance(body, ChatThreadRequest)
            thread_id = await gateway.create_thread()
            thread = chat_store.create(thread_id, session.identity, body.environment)
        except DashboardAuthError as exc:
            return _error(str(exc), 403)
        except DashboardChatError as exc:
            return _chat_error(exc)
        except GatewayError:
            logger.exception("Dashboard chat thread allocation failed")
            return _error("agent gateway is temporarily unavailable", 503)
        change_control.record_action(
            "chat.thread_created",
            session.identity,
            {"thread_id": thread_id, "environment": body.environment},
        )
        return JSONResponse(
            thread.model_dump(mode="json"),
            status_code=201,
            headers=_security_headers(),
        )

    @app.get("/dashboard/api/chat/threads/{thread_id}")
    async def dashboard_chat_thread(thread_id: str, request: Request) -> Response:
        if not cfg.server.dashboard_chat_enabled:
            return _error("dashboard chat is disabled", 404)
        session, denied = await _api_session(request, "chat.use")
        if denied is not None:
            return denied
        assert session is not None
        try:
            thread = chat_store.get(thread_id, session.identity)
            messages = chat_store.messages(thread_id, session.identity)
        except DashboardChatError as exc:
            return _chat_error(exc)
        return JSONResponse(
            {
                "thread": thread.model_dump(mode="json"),
                "messages": [item.model_dump(mode="json") for item in messages],
            },
            headers=_security_headers(),
        )

    @app.post("/dashboard/api/chat/threads/{thread_id}/messages")
    async def dashboard_chat_message(thread_id: str, request: Request) -> Response:
        if not cfg.server.dashboard_chat_enabled:
            return _error("dashboard chat is disabled", 404)
        session, denied = await _api_session(request, "chat.use")
        if denied is not None:
            return denied
        assert session is not None
        try:
            validate_csrf(session, request.headers.get("x-csrf-token"))
            body = await _json_model(request, ChatMessageRequest)
            assert isinstance(body, ChatMessageRequest)
            message = body.message.strip()
            if not message:
                raise DashboardAuthError("message must not be blank")
            if len(message) > cfg.server.dashboard_chat_max_message_chars:
                raise DashboardAuthError("message exceeds the configured dashboard limit")
            thread = chat_store.begin_turn(thread_id, session.identity, message)
        except DashboardAuthError as exc:
            return _error(str(exc), 400 if "message" in str(exc) else 403)
        except DashboardChatError as exc:
            return _chat_error(exc)

        await live_telemetry.queued(thread_id, session.principal, "http")
        change_control.record_action(
            "chat.message_submitted",
            session.identity,
            {"thread_id": thread_id, "environment": thread.environment},
        )

        async def _chat_events() -> Any:
            terminal = False
            run_id: str | None = None
            latest_assistant_text = ""
            try:
                await live_telemetry.running(thread_id)
                async for event in gateway.stream(
                    thread_id,
                    message,
                    profile="default",
                    principal=session.principal,
                    interface="http",
                    environment=thread.environment,
                ):
                    if await request.is_disconnected():
                        raise asyncio.CancelledError
                    if isinstance(event, AssistantText):
                        latest_assistant_text = _bounded_chat_text(event.text)
                        yield {
                            "event": "assistant",
                            "data": json.dumps(
                                {"text": latest_assistant_text},
                                separators=(",", ":"),
                            ),
                        }
                    elif isinstance(event, ToolCall):
                        tool_name = _bounded_chat_text(event.name, 120)
                        yield {
                            "event": "activity",
                            "data": json.dumps(
                                {
                                    "kind": "tool",
                                    "text": f"Invoking {tool_name}",
                                },
                                separators=(",", ":"),
                            ),
                        }
                    elif isinstance(event, ToolResult):
                        if event.denied:
                            rule = _bounded_chat_text(event.rule_id or "policy", 120)
                            detail = f"Policy denied the request · {rule}"
                            chat_store.append(
                                thread_id,
                                role="activity",
                                kind="policy_denial",
                                content=detail,
                            )
                        else:
                            detail = "Tool completed"
                        yield {
                            "event": "activity",
                            "data": json.dumps(
                                {
                                    "kind": "policy_denial" if event.denied else "tool_result",
                                    "text": detail,
                                },
                                separators=(",", ":"),
                            ),
                        }
                    elif isinstance(event, EscalationEvent):
                        run_id = event.escalation.run_id
                        yield {
                            "event": "approval",
                            "data": json.dumps(
                                {
                                    "run_id": run_id,
                                    "text": (
                                        "Independent approval is required before execution "
                                        "can continue."
                                    ),
                                },
                                separators=(",", ":"),
                            ),
                        }
                    elif isinstance(event, RunEnd):
                        result = event.result
                        run_id = result.run_id
                        final_text = _bounded_chat_text(
                            result.final_text or latest_assistant_text
                        )
                        if final_text:
                            chat_store.append(
                                thread_id,
                                role="assistant",
                                kind="message",
                                content=final_text,
                                run_id=run_id,
                            )
                        elif result.error:
                            chat_store.append(
                                thread_id,
                                role="system",
                                kind="run_error",
                                content="The agent run ended before it produced a response.",
                                run_id=run_id,
                            )
                        awaiting_approval = result.interrupted is not None
                        if awaiting_approval:
                            chat_store.append(
                                thread_id,
                                role="activity",
                                kind="approval_required",
                                content=(
                                    "Waiting for an independent approver in Live control."
                                ),
                                run_id=run_id,
                            )
                        chat_store.finish_turn(
                            thread_id,
                            awaiting_approval=awaiting_approval,
                            run_id=run_id,
                        )
                        await live_telemetry.completed(
                            thread_id,
                            run_id,
                            "agent run failed" if result.error else None,
                        )
                        status = (
                            "awaiting_approval"
                            if awaiting_approval
                            else "error"
                            if result.error
                            else "completed"
                        )
                        change_control.record_action(
                            "chat.run_finished",
                            session.identity,
                            {
                                "thread_id": thread_id,
                                "run_id": run_id,
                                "status": status,
                            },
                        )
                        yield {
                            "event": "done",
                            "data": json.dumps(
                                {
                                    "run_id": run_id,
                                    "status": status,
                                    "final_text": final_text,
                                    "cost_usd": result.cost_usd_authoritative,
                                },
                                separators=(",", ":"),
                            ),
                        }
                        terminal = True
                        return
            except asyncio.CancelledError:
                await gateway.cancel(thread_id)
                chat_store.cancel(thread_id)
                await live_telemetry.cancelled(thread_id)
                change_control.record_action(
                    "chat.run_cancelled",
                    session.identity,
                    {"thread_id": thread_id, "run_id": run_id},
                )
                terminal = True
                raise
            except Exception as exc:  # noqa: BLE001 - stream fails closed without internals
                logger.exception("Dashboard chat run failed (%s)", type(exc).__name__)
                chat_store.append(
                    thread_id,
                    role="system",
                    kind="run_error",
                    content="The agent run failed. Retry the turn or inspect the run ledger.",
                    run_id=run_id,
                )
                chat_store.finish_turn(
                    thread_id,
                    awaiting_approval=False,
                    run_id=run_id,
                )
                await live_telemetry.completed(thread_id, run_id, "agent run failed")
                change_control.record_action(
                    "chat.run_finished",
                    session.identity,
                    {"thread_id": thread_id, "run_id": run_id, "status": "error"},
                )
                yield {
                    "event": "error",
                    "data": json.dumps(
                        {"detail": "The agent run failed. Please retry."},
                        separators=(",", ":"),
                    ),
                }
                terminal = True
            finally:
                if not terminal:
                    try:
                        await gateway.cancel(thread_id)
                    finally:
                        chat_store.cancel(thread_id)
                        await live_telemetry.cancelled(thread_id)

        return EventSourceResponse(
            _chat_events(),
            ping=15,
            headers={**_security_headers(), "X-Accel-Buffering": "no"},
        )

    @app.post("/dashboard/api/chat/threads/{thread_id}/cancel")
    async def dashboard_cancel_chat(thread_id: str, request: Request) -> Response:
        if not cfg.server.dashboard_chat_enabled:
            return _error("dashboard chat is disabled", 404)
        session, denied = await _api_session(request, "chat.use")
        if denied is not None:
            return denied
        assert session is not None
        try:
            validate_csrf(session, request.headers.get("x-csrf-token"))
            thread = chat_store.get(thread_id, session.identity)
            await gateway.cancel(thread_id)
            chat_store.cancel(thread_id, session.identity)
        except DashboardAuthError as exc:
            return _error(str(exc), 403)
        except DashboardChatError as exc:
            return _chat_error(exc)
        await live_telemetry.cancelled(thread_id)
        change_control.record_action(
            "chat.run_cancelled",
            session.identity,
            {"thread_id": thread.thread_id, "run_id": thread.last_run_id},
        )
        return JSONResponse({"status": "cancelled"}, headers=_security_headers())

    @app.get("/dashboard/api/snapshot")
    async def dashboard_snapshot(request: Request) -> Response:
        session, denied = await _api_session(request)
        if denied is not None:
            return denied
        assert session is not None
        snapshot = await asyncio.to_thread(build_dashboard_snapshot, cfg)
        live = await _live_snapshot(gateway, live_telemetry)
        snapshot["live"] = live
        snapshot["slis"]["queue_latency_ms"] = live.get("queue_latency_ms")
        snapshot["identity"] = {
            "issuer": session.issuer,
            "subject": session.subject,
            "display_name": session.display_name,
            "roles": session.roles,
            "csrf_token": session.csrf_token,
        }
        snapshot["control_plane"] = {
            "revision": change_control.revision(),
            "proposals": [
                item.model_dump(mode="json") for item in change_control.list(limit=50)
            ],
        }
        change_control.record_action("dashboard.snapshot", session.identity)
        return JSONResponse(snapshot, headers=_security_headers())

    @app.get("/dashboard/api/events")
    async def dashboard_events(request: Request) -> Response:
        session, denied = await _api_session(request)
        if denied is not None:
            return denied
        assert session is not None
        change_control.record_action("dashboard.stream_connected", session.identity)

        async def _events() -> Any:
            last_audit_digest = ""
            while True:
                if await request.is_disconnected():
                    return
                live = await _live_snapshot(gateway, live_telemetry)
                yield {"event": "live", "data": json.dumps(live, separators=(",", ":"))}
                snapshot = await asyncio.to_thread(build_dashboard_snapshot, cfg)
                snapshot["slis"]["queue_latency_ms"] = live.get("queue_latency_ms")
                snapshot["control_plane"] = {
                    "revision": change_control.revision(),
                    "proposals": [
                        item.model_dump(mode="json")
                        for item in change_control.list(limit=50)
                    ],
                }
                digest = hashlib.sha256(
                    json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest()
                if digest != last_audit_digest:
                    last_audit_digest = digest
                    yield {
                        "event": "snapshot",
                        "data": json.dumps(snapshot, separators=(",", ":")),
                    }
                await asyncio.sleep(2)

        return EventSourceResponse(
            _events(),
            ping=15,
            headers={**_security_headers(), "X-Accel-Buffering": "no"},
        )

    @app.get("/dashboard/api/runs/{run_id}")
    async def dashboard_run_detail(run_id: str, request: Request) -> Response:
        session, denied = await _api_session(request)
        if denied is not None:
            return denied
        detail = build_run_detail(cfg, run_id)
        if detail is None:
            return _error("run not found", 404)
        assert session is not None
        change_control.record_action("dashboard.run_detail", session.identity, {"run_id": run_id})
        return JSONResponse(detail, headers=_security_headers())

    @app.post("/dashboard/api/runs/{run_id}/cancel")
    async def dashboard_cancel_run(run_id: str, request: Request) -> Response:
        session, denied = await _api_session(request, "run.cancel")
        if denied is not None:
            return denied
        assert session is not None
        try:
            validate_csrf(session, request.headers.get("x-csrf-token"))
        except DashboardAuthError as exc:
            return _error(str(exc), 403)
        detail = build_run_detail(cfg, run_id)
        if detail is None or not detail.get("thread_id"):
            return _error("run or correlated thread not found", 404)
        await gateway.cancel(str(detail["thread_id"]))
        await live_telemetry.cancelled(str(detail["thread_id"]))
        change_control.record_action(
            "run.cancelled",
            session.identity,
            {"run_id": run_id, "thread_id": detail["thread_id"]},
        )
        return JSONResponse({"status": "cancelled"}, headers=_security_headers())

    @app.post("/dashboard/api/approvals/{thread_id}")
    async def dashboard_resolve_approval(thread_id: str, request: Request) -> Response:
        session, denied = await _api_session(request, "approval.resolve")
        if denied is not None:
            return denied
        assert session is not None
        try:
            validate_csrf(session, request.headers.get("x-csrf-token"))
            body = await _json_model(request, ApprovalRequest)
            assert isinstance(body, ApprovalRequest)
            result = await gateway.resume_interrupt(
                thread_id, body.decisions, approver=session.principal
            )
        except (DashboardAuthError, ChangeControlError, GatewayError) as exc:
            return _error(str(exc), 403)
        change_control.record_action(
            "approval.resolved",
            session.identity,
            {"thread_id": thread_id, "run_id": result.run_id},
        )
        if chat_store.get_internal(thread_id) is not None:
            final_text = _bounded_chat_text(result.final_text)
            if final_text:
                chat_store.append(
                    thread_id,
                    role="assistant",
                    kind="message",
                    content=final_text,
                    run_id=result.run_id,
                )
            elif result.error:
                chat_store.append(
                    thread_id,
                    role="system",
                    kind="run_error",
                    content="The resumed agent run ended before it produced a response.",
                    run_id=result.run_id,
                )
            if result.interrupted is not None:
                chat_store.append(
                    thread_id,
                    role="activity",
                    kind="approval_required",
                    content=(
                        "Another independent approval is required before execution can continue."
                    ),
                    run_id=result.run_id,
                )
            chat_store.finish_turn(
                thread_id,
                awaiting_approval=result.interrupted is not None,
                run_id=result.run_id,
            )
        return JSONResponse(
            {
                "run_id": result.run_id,
                "status": "awaiting_approval" if result.interrupted else "completed",
            },
            headers=_security_headers(),
        )

    @app.get("/dashboard/api/config/proposals")
    async def dashboard_list_proposals(request: Request) -> Response:
        _, denied = await _api_session(request)
        if denied is not None:
            return denied
        return JSONResponse(
            {
                "revision": change_control.revision(),
                "items": [item.model_dump(mode="json") for item in change_control.list()],
            },
            headers=_security_headers(),
        )

    @app.post("/dashboard/api/config/proposals")
    async def dashboard_propose_config(request: Request) -> Response:
        session, denied = await _api_session(request, "config.propose")
        if denied is not None:
            return denied
        assert session is not None
        try:
            validate_csrf(session, request.headers.get("x-csrf-token"))
            body = await _json_model(request, CapabilityGrantRequest)
            assert isinstance(body, CapabilityGrantRequest)
            proposal = change_control.propose(body, session.identity)
        except DashboardAuthError as exc:
            return _error(str(exc), 403)
        except ChangeControlError as exc:
            return _error(str(exc), 400)
        return JSONResponse(
            proposal.model_dump(mode="json"), status_code=201, headers=_security_headers()
        )

    @app.post("/dashboard/api/config/proposals/{proposal_id}/approve")
    async def dashboard_approve_config(proposal_id: str, request: Request) -> Response:
        session, denied = await _api_session(request, "config.approve")
        if denied is not None:
            return denied
        assert session is not None
        try:
            validate_csrf(session, request.headers.get("x-csrf-token"))
            proposal = change_control.approve(proposal_id, session.identity)
        except (DashboardAuthError, ChangeControlError) as exc:
            return _error(str(exc), 409)
        return JSONResponse(proposal.model_dump(mode="json"), headers=_security_headers())

    @app.post("/dashboard/api/config/proposals/{proposal_id}/activate")
    async def dashboard_activate_config(proposal_id: str, request: Request) -> Response:
        session, denied = await _api_session(request, "config.activate")
        if denied is not None:
            return denied
        assert session is not None
        try:
            validate_csrf(session, request.headers.get("x-csrf-token"))
            proposal = change_control.activate(proposal_id, session.identity)
        except (DashboardAuthError, ChangeControlError) as exc:
            return _error(str(exc), 409)
        return JSONResponse(proposal.model_dump(mode="json"), headers=_security_headers())

    @app.post("/dashboard/api/config/proposals/{proposal_id}/revoke")
    async def dashboard_revoke_config(proposal_id: str, request: Request) -> Response:
        session, denied = await _api_session(request, "config.revoke")
        if denied is not None:
            return denied
        assert session is not None
        try:
            validate_csrf(session, request.headers.get("x-csrf-token"))
            proposal = change_control.revoke(proposal_id, session.identity)
        except (DashboardAuthError, ChangeControlError) as exc:
            return _error(str(exc), 409)
        return JSONResponse(proposal.model_dump(mode="json"), headers=_security_headers())

    @app.post("/dashboard/api/sessions/revoke")
    async def dashboard_revoke_sessions(request: Request) -> Response:
        session, denied = await _api_session(request, "session.revoke")
        if denied is not None:
            return denied
        assert session is not None
        try:
            validate_csrf(session, request.headers.get("x-csrf-token"))
            body = await _json_model(request, SessionRevokeRequest)
            assert isinstance(body, SessionRevokeRequest)
        except DashboardAuthError as exc:
            return _error(str(exc), 400)
        count = await auth.store.revoke_identity(body.issuer, body.subject)
        change_control.record_action(
            "session.revoked",
            session.identity,
            {"issuer": body.issuer, "subject": body.subject, "count": count},
        )
        return JSONResponse({"revoked": count}, headers=_security_headers())


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
                "policy_latency_ms": None,
                "decisions": 0,
                "executions": 0,
                "execution_errors": 0,
                "model_calls": 0,
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
    model_calls = [event for event in events if event.event_type is EventType.model_call]
    policy_durations = [
        _as_float((event.summary or {}).get("duration_ms"))
        for event in decisions
        if (event.summary or {}).get("duration_ms") is not None
    ]
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
        "policy_latency_ms": (
            round(sum(policy_durations) / len(policy_durations), 3)
            if policy_durations
            else None
        ),
        "decisions": len(decisions),
        "executions": len(executions),
        "model_calls": len(model_calls),
        "execution_errors": sum(
            1
            for event in executions
            if event.execution is not None and event.execution.exit_code != 0
        ),
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


def build_run_detail(cfg: AppConfig, run_id: str) -> dict[str, Any] | None:
    """Return a bounded, secret-free run detail projection with correlation identifiers."""
    if re.fullmatch(r"[A-Za-z0-9_-]{1,128}", run_id) is None:
        return None
    audit_dir = Path(cfg.audit.dir).resolve()
    path = (audit_dir / f"{run_id}.jsonl").resolve()
    if path.parent != audit_dir or not path.is_file():
        return None
    record, _ = _run_record(path)
    events, parse_error = _parse_events(path)
    if record is None:
        return None
    detail_events = [
        {
            "event_id": event.event_id,
            "type": event.event_type.value,
            "ts": event.ts,
            "trace_id": event.trace_id,
            "tool_call_id": event.tool_call_id,
            "tool": event.tool,
            "decision": (
                {
                    "effect": event.decision.effect,
                    "rule_id": event.decision.rule_id,
                    "reason": event.decision.reason,
                    "channel": event.decision.channel,
                }
                if event.decision is not None
                else None
            ),
            "execution": (
                {
                    "exit_code": event.execution.exit_code,
                    "duration_ms": event.execution.duration_ms,
                    "truncated": event.execution.truncated,
                }
                if event.execution is not None
                else None
            ),
            "approver": event.approver,
            "summary": (
                {
                    key: value
                    for key, value in (event.summary or {}).items()
                    if key
                    in {
                        "status",
                        "kind",
                        "rule_id",
                        "type",
                        "channel",
                        "cost_state",
                        "cost_authoritative",
                        "usage",
                        "budget_stop",
                        "model_call_id",
                        "duration_ms",
                        "cost_before",
                        "cost_delta",
                        "cost_after",
                        "error_type",
                    }
                }
                or None
            ),
        }
        for event in events
    ]
    return {
        **record,
        "trace_id": events[0].trace_id if events else None,
        "audit_error": parse_error,
        "events": detail_events,
    }


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
    latest_updated = _parse_ts(str(latest.get("updated_at") or "")) if latest else None
    audit_lag_seconds = (
        max(0.0, (now - latest_updated).total_seconds()) if latest_updated else None
    )
    completed_count = len(completed_today)
    total_executions = sum(int(run["executions"]) for run in records)
    executor_errors = sum(int(run["execution_errors"]) for run in records)
    policy_samples = [
        (float(run["policy_latency_ms"]), int(run["decisions"]))
        for run in records
        if run.get("policy_latency_ms") is not None and int(run["decisions"]) > 0
    ]
    policy_sample_count = sum(count for _, count in policy_samples)
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
        "slis": {
            "run_success_percent": (
                round(successful_today / completed_count * 100, 2)
                if completed_count
                else None
            ),
            "queue_latency_ms": None,
            "policy_latency_ms": (
                round(
                    sum(latency * count for latency, count in policy_samples)
                    / policy_sample_count,
                    3,
                )
                if policy_sample_count
                else None
            ),
            "executor_error_percent": (
                None
                if total_executions == 0
                else round(executor_errors / total_executions * 100, 2)
            ),
            "audit_lag_seconds": (
                round(audit_lag_seconds, 3) if audit_lag_seconds is not None else None
            ),
            "budget_utilization_percent": (
                round(
                    sum(run["cost_usd"] for run in today_records)
                    / cfg.budgets.daily.global_usd
                    * 100,
                    2,
                )
                if cfg.budgets.daily.global_usd > 0
                else None
            ),
        },
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
