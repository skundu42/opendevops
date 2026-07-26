"""``ServerGateway`` — drive a graph running inside a self-hosted LangGraph Server.

This is the ONLY module in the codebase allowed to import ``langgraph_sdk`` — our compatibility
firewall. Every other module speaks the transport-neutral :class:`~opendevops.gateway.base`
protocol, so if server licensing ever fails review this seam is where a FastAPI-embedded fallback
would re-implement the same HTTP surface without touching a single interface.

The graph runs in the Server process; :class:`ServerGateway` runs on a *different* host and speaks
to it over HTTP (``get_client(url=..., api_key=...)``). It implements the full ``AgentGateway``
protocol against the SDK — ``threads.create`` / ``runs.wait`` / ``runs.stream`` / ``runs.cancel``
and the ``command={"resume": ...}`` resume — translating the server's ``updates`` / ``values`` wire
frames into the SAME :class:`RunEvent` dataclasses the CLI already renders (via the shared
:mod:`opendevops.gateway.translate` helpers ``LocalGateway`` uses).

Accounting / audit divergence (decided deliberately)
----------------------------------------------------
In service mode the graph — and therefore ``PolicyMiddleware`` + the budget middlewares + every
audit write + the daily-counter charge — runs in the Server process. The gateway-side
``get_usage_metadata_callback()`` that makes ``LocalGateway``'s authoritative ledger work is
contextvar-based and **cannot see** those server-side model calls. So this gateway ships:

* ``cost_usd_state`` — read from the final run state (``run_cost_usd``), the main-model spend the
  in-graph ``CostCapMiddleware`` accumulated and the ``DailyBudgetMiddleware`` already charged to
  the (server-side) daily counter;
* ``cost_usd_authoritative == cost_usd_state``, with ``usage["authoritative_unavailable"] = True``.
  There is no independent gateway ledger here and — critically — the gateway does **not** re-charge
  the daily counter (the server already did), so nothing is double-counted. The weekly LangSmith
  cross-check (LangSmith-computed cost vs gateway-accounted cost, >5% divergence alerts)
  is the compensating control that catches price-table staleness / summarizer undercount.

Audit book-ends land server-side, in the same per-run chain file as the in-graph events, written by
:class:`~opendevops.agent.RunLifecycleMiddleware` (enabled on the server build via
``build_agent(..., run_lifecycle=True)``). The gateway writes NO audit here — it only reads final
state. The run's correlation id (``run_id``) is minted gateway-side and threaded through ``context``
so the middleware keys the chain file on it; a resume reuses the same ``run_id`` (see
:meth:`resume_interrupt`) so the resumed segment appends to the same chain.

SDK probe evidence (installed langgraph-sdk 0.4.2 + a live in-memory ``langgraph dev`` 0.11.1):
* ``client.threads.create(*, thread_id=<uuid>, if_exists=...)`` → ``{"thread_id", ...}``; a
  non-UUID ``thread_id`` is rejected (``422 Invalid thread ID: must be a UUID``), so we let the
  server mint the id.
* ``client.runs.wait(thread_id, assistant_id, *, input, command, config, context, on_run_created)``
  → the final state values ``dict`` (``{"messages": [...], "run_cost_usd": ...}``); on a suspend it
  returns ``{"messages": [...], "__interrupt__": [{"value": <payload>, "id": ...}]}`` (does NOT
  raise); on a graph error it raises an SDK error.
* ``client.runs.stream(..., stream_mode=["updates","values"])`` → ``StreamPart(event, data, id)``:
  a ``metadata`` frame first, then interleaved ``values`` (full state, messages as ``model_dump``
  dicts) and ``updates`` (``{node: {"messages": [...]}}``); ``__interrupt__`` rides the final
  ``values`` frame on a suspend.
* ``on_run_created`` fires in both ``wait`` and ``stream`` with ``{"run_id", "thread_id"}`` — the
  SERVER run id we need for ``runs.cancel(thread_id, run_id)``.
* Resume: ``command={"resume": {"decisions": [...]}}`` — the value delivered to ``interrupt()`` is
  exactly ``{"decisions": [...]}``, matching what ``PolicyMiddleware`` expects; the approver is
  injected into each decision exactly as ``LocalGateway`` does.
"""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from langgraph_sdk import get_client

from opendevops.audit.schema import new_event_id
from opendevops.gateway.base import (
    Escalation,
    EscalationEvent,
    GatewayConfigError,
    GatewayError,
    GatewayRunError,
    RunEnd,
    RunResult,
    enforce_approval_separation,
)
from opendevops.gateway.translate import extract_interrupt, final_text, translate_updates

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from opendevops.config import AppConfig, ResolvedProfile
    from opendevops.gateway.base import RunEvent

logger = logging.getLogger(__name__)

# The graph id registered in ``langgraph.json`` (``"graphs": {"devops": ...}``); the SDK's
# ``assistant_id`` accepts a graph name directly.
_DEFAULT_ASSISTANT = "devops"

# The server run stream modes: ``updates`` drives per-node event translation, ``values`` carries the
# final state (accounting + ``__interrupt__``). NOT ``messages`` — same rationale as LocalGateway.
_STREAM_MODE: list[str] = ["updates", "values"]


def _new_run_id() -> str:
    """A time-sortable ULID run/correlation id (minted gateway-side, threaded through context)."""
    return new_event_id()


@dataclass
class _Suspended:
    """Captured when a server run SUSPENDS, so a resume reuses the same run_id (chain locality)."""

    run_id: str
    ctx: dict[str, Any]
    prof: ResolvedProfile


class ServerGateway:
    """:class:`~opendevops.gateway.base.AgentGateway` over a self-hosted LangGraph Server.

    Args:
        cfg: the validated application config; ``cfg.server.url`` must be set (else
            :class:`GatewayConfigError`) unless ``url`` is passed explicitly.
        client: an optional pre-built ``langgraph_sdk`` async client — the test seam (tests inject a
            fake wire-shaped client); production passes ``None`` and the client is built from
            ``cfg.server`` via :func:`langgraph_sdk.get_client`.
        assistant_id: the graph id to drive (defaults to ``"devops"``, matching ``langgraph.json``).
        url: an explicit base URL that OVERRIDES ``cfg.server.url`` for this gateway only. The
            external-client path leaves this ``None`` and reaches the server through Caddy on
            ``cfg.server.url`` (the published :8123). The webhook app, which runs INSIDE the server
            container, passes the loopback server port (``http://localhost:8000``) so its runs hit
            the local API directly — bypassing Caddy and its bearer — while every other consumer of
            ``cfg.server.url`` is untouched. ``api_key`` resolution is unchanged: with the loopback
            path's ``api_key_env`` var unset, no bearer is sent, which is correct here.
    """

    def __init__(
        self,
        cfg: AppConfig,
        *,
        client: Any = None,
        assistant_id: str = _DEFAULT_ASSISTANT,
        url: str | None = None,
    ) -> None:
        resolved_url = url if url is not None else cfg.server.url
        if not resolved_url:
            raise GatewayConfigError(
                "server.url is not configured — set config.yaml `server: {url: ...}` before "
                "constructing a ServerGateway (service mode is opt-in)"
            )
        self._cfg = cfg
        self._url = resolved_url
        self._assistant_id = assistant_id
        self._client = client if client is not None else self._build_client(cfg, resolved_url)
        # thread_id -> the SERVER run id (from on_run_created), so cancel targets the right run.
        self._server_runs: dict[str, str] = {}
        # thread_id -> the in-flight local wait task (so cancel can interrupt our side promptly).
        self._tasks: dict[str, asyncio.Task[Any]] = {}
        # thread_id -> suspended-run context, so a resume continues the SAME run's chain.
        self._suspended: dict[str, _Suspended] = {}

    @staticmethod
    def _build_client(cfg: AppConfig, url: str) -> Any:
        """Build the ``langgraph_sdk`` async client for ``url`` (auth: explicit-by-config).

        ``url`` is the already-resolved base URL (``cfg.server.url`` or the constructor's override).
        The API key is read from the env var *named* by ``cfg.server.api_key_env`` (never stored in
        config). Passing ``api_key`` explicitly — even ``None`` — suppresses the SDK's ambient
        ``LANGGRAPH_API_KEY`` / ``LANGSMITH_API_KEY`` auto-load, so a key is sent only when config
        opts in (probed: ``get_client(api_key=None)`` = "don't load API key from environment").
        """
        api_key = os.environ.get(cfg.server.api_key_env) if cfg.server.api_key_env else None
        return get_client(url=url, api_key=api_key)

    # -- public surface -------------------------------------------------------------------

    async def create_thread(self, thread_id: str | None = None) -> str:
        """Allocate a server thread and return its id, or reuse a caller-chosen UUID idempotently.

        ``thread_id=None`` lets the server mint the id (a UUID). An explicit ``thread_id`` — the
        webhook app's deterministic ``uuid5(NS_INCIDENT, fingerprint)`` incident thread — is passed
        with ``if_exists="do_nothing"`` so a repeat alert reuses the existing thread instead of
        erroring (the SDK rejects a non-UUID id with 422, which a uuid5 never is). The returned id
        equals the one the server echoes.
        """
        if thread_id is not None:
            thread = await self._client.threads.create(
                thread_id=thread_id, if_exists="do_nothing"
            )
        else:
            thread = await self._client.threads.create()
        return str(thread["thread_id"])

    async def run(
        self,
        thread_id: str,
        user_input: str,
        *,
        profile: str = "default",
        principal: str,
        interface: str,
        environment: str,
    ) -> RunResult:
        """Run one turn to completion (``runs.wait``) and return its :class:`RunResult`."""
        run_id = _new_run_id()
        prof = self._cfg.budgets.profile(profile)
        ctx = self._context_payload(run_id, principal, interface, environment, profile)
        return await self._drive_wait(run_id, thread_id, ctx, prof, self._input(user_input), None)

    async def resume_interrupt(
        self,
        thread_id: str,
        decisions: list[dict[str, Any]],
        *,
        approver: str,
    ) -> RunResult:
        """Resume a suspended (escalated) run on ``thread_id`` with the approver's decisions.

        Reuses the suspended run's ``run_id`` / ``ctx`` / ``prof`` so the resumed segment's audit
        events (written server-side) append to the SAME per-run chain file the first segment seeded.
        """
        susp = self._require_suspended(thread_id)
        enforce_approval_separation(
            requester=str(susp.ctx.get("principal") or "unknown"),
            approver=approver,
            environment=str(susp.ctx.get("environment") or ""),
            decisions=decisions,
            required=self._cfg.control_plane.production_requires_independent_approval,
        )
        susp = self._pop_suspended(thread_id)
        command = self._resume_command(decisions, approver)
        return await self._drive_wait(susp.run_id, thread_id, susp.ctx, susp.prof, None, command)

    async def stream(
        self,
        thread_id: str,
        user_input: str,
        *,
        profile: str = "default",
        principal: str,
        interface: str,
        environment: str,
    ) -> AsyncIterator[RunEvent]:
        """Run one turn (``runs.stream``): yield :class:`RunEvent`\\ s + a final :class:`RunEnd`."""
        run_id = _new_run_id()
        prof = self._cfg.budgets.profile(profile)
        ctx = self._context_payload(run_id, principal, interface, environment, profile)
        async for event in self._drive_stream(
            run_id, thread_id, ctx, prof, self._input(user_input), None
        ):
            yield event

    async def stream_resume(
        self,
        thread_id: str,
        decisions: list[dict[str, Any]],
        *,
        approver: str,
    ) -> AsyncIterator[RunEvent]:
        """Streaming variant of :meth:`resume_interrupt` (the CLI renders the resumed turn)."""
        susp = self._require_suspended(thread_id)
        enforce_approval_separation(
            requester=str(susp.ctx.get("principal") or "unknown"),
            approver=approver,
            environment=str(susp.ctx.get("environment") or ""),
            decisions=decisions,
            required=self._cfg.control_plane.production_requires_independent_approval,
        )
        susp = self._pop_suspended(thread_id)
        command = self._resume_command(decisions, approver)
        async for event in self._drive_stream(
            susp.run_id, thread_id, susp.ctx, susp.prof, None, command
        ):
            yield event

    async def cancel(self, thread_id: str) -> None:
        """Cancel ``thread_id``'s in-flight run — locally and on the server (both idempotent)."""
        task = self._tasks.get(thread_id)
        if task is not None and not task.done():
            task.cancel()
        await self._safe_server_cancel(thread_id)

    async def aclose(self) -> None:
        """Close the underlying SDK HTTP client (best-effort; idempotent)."""
        try:
            await self._client.aclose()
        except Exception:  # noqa: BLE001 - a close failure must never surface to a caller
            logger.debug("server client close failed", exc_info=True)

    # -- segment drivers ------------------------------------------------------------------

    async def _drive_wait(
        self,
        run_id: str,
        thread_id: str,
        ctx: dict[str, Any],
        prof: ResolvedProfile,
        input_: dict[str, Any] | None,
        command: dict[str, Any] | None,
    ) -> RunResult:
        """Await one segment via ``runs.wait`` under a wall-clock guard; finalize-or-suspend it."""
        try:
            values = await self._wait(thread_id, ctx, prof, input_, command)
        except TimeoutError:
            # A suspended (escalated) run returns from ``wait`` immediately, so a wall-clock timeout
            # only ever fires on a genuinely-running run — never on an interrupt (the local
            # gateway's rule holds for free here). Cancel the still-running server run and report
            # the wall-clock stop.
            await self._safe_server_cancel(thread_id)
            return self._budget_result(
                run_id, "wall_clock", prof.wall_clock_s, "wall clock exceeded"
            )
        except asyncio.CancelledError:
            await self._safe_server_cancel(thread_id)
            return self._budget_result(run_id, "cancelled", None, "run cancelled")
        except Exception as exc:  # noqa: BLE001 - map an unexpected SDK/network failure to a raise
            raise GatewayRunError(run_id, exc) from exc
        return self._finalize(run_id, thread_id, ctx, prof, values)

    async def _drive_stream(
        self,
        run_id: str,
        thread_id: str,
        ctx: dict[str, Any],
        prof: ResolvedProfile,
        input_: dict[str, Any] | None,
        command: dict[str, Any] | None,
    ) -> AsyncIterator[RunEvent]:
        """Stream a segment; yield events, an EscalationEvent (if suspended), then a RunEnd."""
        final_values: dict[str, Any] = {}
        agen = self._client.runs.stream(
            thread_id,
            self._assistant_id,
            input=input_,
            command=command,
            stream_mode=_STREAM_MODE,
            config=self._run_config(prof),
            context=ctx,
            on_run_created=self._on_run_created(thread_id),
        )
        try:
            async for part in self._guarded_stream(thread_id, agen, prof.wall_clock_s):
                events, values = self._translate_part(part)
                if values is not None:
                    final_values = values
                for event in events:
                    yield event
        except TimeoutError:
            await self._safe_server_cancel(thread_id)
            yield RunEnd(
                result=self._budget_result(
                    run_id, "wall_clock", prof.wall_clock_s, "wall clock exceeded"
                )
            )
            return
        except asyncio.CancelledError:
            await self._safe_server_cancel(thread_id)
            yield RunEnd(result=self._budget_result(run_id, "cancelled", None, "run cancelled"))
            return
        except Exception:  # noqa: BLE001 - the REPL streams exclusively; surface a friendly RunEnd
            logger.exception("server stream failed for run %s", run_id)
            yield RunEnd(result=self._error_result(run_id))
            return

        result = self._finalize(run_id, thread_id, ctx, prof, final_values)
        if result.interrupted is not None:
            yield EscalationEvent(escalation=result.interrupted)
        yield RunEnd(result=result)

    async def _wait(
        self,
        thread_id: str,
        ctx: dict[str, Any],
        prof: ResolvedProfile,
        input_: dict[str, Any] | None,
        command: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Call ``runs.wait`` as a tracked, cancellable task under a wall-clock ``wait_for``."""
        coro = self._client.runs.wait(
            thread_id,
            self._assistant_id,
            input=input_,
            command=command,
            config=self._run_config(prof),
            context=ctx,
            on_run_created=self._on_run_created(thread_id),
        )
        task: asyncio.Task[Any] = asyncio.ensure_future(coro)
        self._tasks[thread_id] = task
        try:
            values = await asyncio.wait_for(task, timeout=prof.wall_clock_s)
        finally:
            self._tasks.pop(thread_id, None)
        return values if isinstance(values, dict) else {}

    async def _guarded_stream(
        self, thread_id: str, agen: AsyncIterator[Any], wall_clock_s: int
    ) -> AsyncIterator[Any]:
        """Wrap the SDK stream so ``cancel`` can interrupt it and a wall clock bounds the turn.

        Each ``__anext__`` step is a tracked, cancellable task (so ``cancel(thread_id)`` raises
        ``CancelledError`` out of the in-flight step) sharing one wall-clock deadline. ``asyncio``
        — not ``wait_for`` — avoids wrapping the iterator's ``StopAsyncIteration`` in a task-cancel.
        Mirrors ``LocalGateway._guarded_stream``.
        """
        loop = asyncio.get_event_loop()
        deadline = loop.time() + wall_clock_s
        iterator = agen.__aiter__()
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise TimeoutError("wall clock exceeded during stream")
            step: asyncio.Task[Any] = asyncio.ensure_future(iterator.__anext__())
            self._tasks[thread_id] = step
            try:
                done, _pending = await asyncio.wait({step}, timeout=remaining)
                if not done:
                    step.cancel()
                    raise TimeoutError("wall clock exceeded during stream")
                try:
                    part = step.result()
                except StopAsyncIteration:
                    return
            finally:
                self._tasks.pop(thread_id, None)
            yield part

    # -- finalization + helpers -----------------------------------------------------------

    def _finalize(
        self,
        run_id: str,
        thread_id: str,
        ctx: dict[str, Any],
        prof: ResolvedProfile,
        values: dict[str, Any],
    ) -> RunResult:
        """Build the RunResult from final state; remember the resume context iff it suspended."""
        result = self._result_from_values(run_id, thread_id, values)
        if result.interrupted is not None:
            self._suspended[thread_id] = _Suspended(run_id=run_id, ctx=ctx, prof=prof)
        return result

    def _result_from_values(
        self, run_id: str, thread_id: str, values: dict[str, Any]
    ) -> RunResult:
        """Translate the final server state to a :class:`RunResult` (accounting divergence applied).

        ``cost_authoritative == cost_state`` and ``usage["authoritative_unavailable"] = True`` — the
        gateway callback cannot see server-side model calls (see the module docstring).
        """
        interrupt_payload = extract_interrupt(values)
        cost_state = float(values.get("run_cost_usd") or 0.0)
        usage: dict[str, Any] = dict(values.get("run_usage") or {})
        # The gateway callback cannot see server-side model calls; authoritative == state here.
        usage["authoritative_unavailable"] = True
        budget_stop = values.get("budget_stop")

        if interrupt_payload is not None:
            return RunResult(
                final_text="",
                run_id=run_id,
                cost_usd_state=cost_state,
                cost_usd_authoritative=cost_state,
                usage=usage,
                budget_stop=budget_stop,
                interrupted=Escalation(
                    payload=interrupt_payload, run_id=run_id, thread_id=thread_id
                ),
            )
        return RunResult(
            final_text=final_text(values),
            run_id=run_id,
            cost_usd_state=cost_state,
            cost_usd_authoritative=cost_state,
            usage=usage,
            budget_stop=budget_stop,
        )

    def _translate_part(self, part: Any) -> tuple[list[RunEvent], dict[str, Any] | None]:
        """Map one SDK ``StreamPart`` to ``(events, values_state)`` — exactly one side is non-empty.

        ``updates`` frames translate to RunEvents (the ``__interrupt__`` pseudo-node is a list, not
        node-dict, so it is skipped); ``values`` frames are the final-state snapshot; ``metadata`` /
        ``messages`` / any other frame carries nothing user-facing.
        """
        event = part.event
        data = part.data
        if event == "updates" and isinstance(data, dict):
            return translate_updates(data), None
        if event == "values" and isinstance(data, dict):
            return [], data
        return [], None

    def _on_run_created(self, thread_id: str) -> Any:
        """A callback that records the SERVER run id for ``thread_id`` (for ``runs.cancel``)."""

        def _record(meta: Any) -> None:
            run_id = meta.get("run_id") if isinstance(meta, dict) else getattr(meta, "run_id", None)
            if run_id:
                self._server_runs[thread_id] = str(run_id)

        return _record

    async def _safe_server_cancel(self, thread_id: str) -> None:
        """Best-effort ``runs.cancel`` of ``thread_id`` server run (a no-op if none is tracked)."""
        server_run_id = self._server_runs.get(thread_id)
        if not server_run_id:
            return
        try:
            await self._client.runs.cancel(thread_id, server_run_id, action="interrupt")
        except Exception:  # noqa: BLE001 - cancellation is best-effort; never surface to a caller
            logger.debug("server run cancel failed for thread %s", thread_id, exc_info=True)

    def _pop_suspended(self, thread_id: str) -> _Suspended:
        susp = self._suspended.pop(thread_id, None)
        if susp is None:
            raise GatewayError(f"no suspended run to resume for thread {thread_id!r}")
        return susp

    def _require_suspended(self, thread_id: str) -> _Suspended:
        susp = self._suspended.get(thread_id)
        if susp is None:
            raise GatewayError(f"no suspended run to resume for thread {thread_id!r}")
        return susp

    async def live_snapshot(self) -> dict[str, Any]:
        """Merge gateway lifecycle state with SDK status for known threads."""
        known_threads = set(self._tasks) | set(self._suspended) | set(self._server_runs)
        active: list[dict[str, Any]] = []
        for thread_id in sorted(known_threads):
            try:
                runs = await self._client.runs.list(thread_id, limit=10, status="running")
            except Exception:  # noqa: BLE001 - telemetry cannot affect execution
                runs = []
            for run in runs:
                data = (
                    dict(run)
                    if isinstance(run, dict)
                    else {
                        key: getattr(run, key, None)
                        for key in ("run_id", "status", "created_at", "updated_at")
                    }
                )
                active.append(
                    {
                        "thread_id": thread_id,
                        "server_run_id": str(data.get("run_id") or ""),
                        "status": str(data.get("status") or "running"),
                        "created_at": data.get("created_at"),
                        "updated_at": data.get("updated_at"),
                    }
                )
        approvals = [
            {
                "thread_id": thread_id,
                "run_id": suspended.run_id,
                "status": "awaiting_approval",
                "requester": str(suspended.ctx.get("principal") or "unknown"),
                "environment": str(suspended.ctx.get("environment") or "unknown"),
            }
            for thread_id, suspended in self._suspended.items()
        ]
        return {
            "active_runs": active,
            "pending_approvals": approvals,
            "queue_depth": None,
            "workers": None,
            "source": "langgraph_sdk",
        }

    @staticmethod
    def _resume_command(decisions: list[dict[str, Any]], approver: str) -> dict[str, Any]:
        """A ``command={"resume": ...}`` with the approver injected into each decision (audited)."""
        injected = [{**d, "approver": approver} for d in decisions]
        return {"resume": {"decisions": injected}}

    def _run_config(self, prof: ResolvedProfile) -> dict[str, Any]:
        """The SDK run config: the profile's recursion limit (thread id is a positional arg)."""
        return {"recursion_limit": prof.recursion_limit}

    @staticmethod
    def _input(user_input: str) -> dict[str, Any]:
        """The graph input for a fresh turn (JSON-wire message shape the server accepts)."""
        return {"messages": [{"role": "user", "content": user_input}]}

    @staticmethod
    def _context_payload(
        run_id: str, principal: str, interface: str, environment: str, profile: str
    ) -> dict[str, Any]:
        """The run-scoped ``context`` payload — the same fields ``LocalGateway`` passes in-graph."""
        return {
            "principal": principal,
            "interface": interface,
            "environment": environment,
            "budget_profile": profile,
            "run_id": run_id,
            "trace_id": uuid.uuid4().hex,
        }

    def _budget_result(
        self, run_id: str, kind: str, limit: int | None, error: str
    ) -> RunResult:
        """A RunResult for a gateway-side stop (wall-clock / cancel); no final state to price.

        Accounting caveat: this reports ``cost 0.0`` because the gateway never received the run's
        final state — but the run really executed on the server, so the SERVER-side daily counter
        still holds the real charge (already debited by the in-graph ``DailyBudgetMiddleware``) and
        the SERVER-side audit chain stays OPEN (``RunLifecycleMiddleware.aafter_agent`` never fired
        for the cancelled run — a crash-shaped hole the tail-truncation-tolerant verifier accepts).
        So a wall-clock/cancel stop under-reports cost gateway-side while the server's ledger and
        chain remain the source of truth; the weekly LangSmith cross-check reconciles the gap.
        """
        trip: dict[str, Any] = {"kind": kind}
        if limit is not None:
            trip["limit"] = limit
        return RunResult(
            final_text="",
            run_id=run_id,
            cost_usd_state=0.0,
            cost_usd_authoritative=0.0,
            usage={"authoritative_unavailable": True},
            budget_stop=trip,
            error=error,
        )

    def _error_result(self, run_id: str) -> RunResult:
        """A friendly RunResult for an unexpected mid-stream SDK/network failure."""
        return RunResult(
            final_text="",
            run_id=run_id,
            cost_usd_state=0.0,
            cost_usd_authoritative=0.0,
            usage={"authoritative_unavailable": True},
            error="unexpected error",
        )
