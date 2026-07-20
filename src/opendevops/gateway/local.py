"""``LocalGateway`` — in-process implementation of the ``AgentGateway`` protocol.

Owns the durable singletons for a process — one :class:`AuditLogger`, one
:class:`SqliteDailyCounter`, one :class:`PriceTable`, and one compiled agent graph built with
those *shared* instances (so the in-graph budget middleware and the gateway's book-keeping
write to the same audit chain and daily ledger). Escalation suspend/resume rides the
``AsyncSqliteSaver`` checkpointer.

Per turn the gateway:

1. mints a ``run_id`` (ULID) and resolves the caller's :class:`AgentContext`;
2. **daily pre-check** — refuses *before any model call* if a daily envelope is already at/over
   cap (still writing ``run_started`` + ``budget_trip`` + ``run_completed`` for auditability);
3. seeds the audit chain and invokes the graph inside a ``get_usage_metadata_callback()`` scope,
   wrapped in a cancellable task guarded by ``asyncio.wait_for(..., profile.wall_clock_s)``;
4. maps wall-clock timeout / ``GraphRecursionError`` / other failures onto ``budget_trip`` +
   ``run_completed`` audit events and a friendly :class:`RunResult` (or a wrapped raise);
5. on success, runs the **authoritative accounting** (below) and closes the chain.

Authoritative accounting — the summarizer-coverage rule
-------------------------------------------------------
The in-graph budget middleware prices and counts only the *main* model's calls (it keys every
call to ``self._model_key``) and adds each per-call amount to the daily counter as it goes. A
summarizer (or any nested model call) is invisible to that middleware but **is** seen by the
usage-metadata callback, which aggregates ``{model_name: usage}`` across every chat-model call
in the turn. So after the run:

* ``state_total`` = ``final_state.run_cost_usd`` (main-model spend the counter already has);
* ``authoritative`` = Σ ``price_table.cost_usd(mapped_key_i, usage_i)`` over the callback
  aggregate (main **+** summarizer + anything else).

If ``authoritative > state_total`` the gateway adds only the **delta** to the daily counter
(both the ``global`` and ``principal:<principal>`` scopes, matching the middleware's two
writes). Adding just the delta — not the whole authoritative figure — avoids double-counting
the per-call amounts the middleware already wrote, while still making the daily ledger complete
(it now includes the summarizer). A callback model name that does not map to a priced row is
log-warned, priced with the main model's row, and counted as one ``usage_missing`` blind spot.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import aiosqlite
from langchain_core.callbacks import (
    UsageMetadataCallbackHandler,
    get_usage_metadata_callback,
)
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
from langgraph.errors import GraphRecursionError
from langgraph.types import Command

from opendevops.agent import agent_git_sha, build_agent
from opendevops.audit.logger import AuditLogger
from opendevops.audit.schema import EventType, new_event_id
from opendevops.budget.daily import DailyCounter, build_daily_counter
from opendevops.context import AgentContext
from opendevops.gateway.base import (
    Escalation,
    EscalationEvent,
    GatewayError,
    GatewayRunError,
    RunEnd,
    RunEvent,
    RunResult,
)
from opendevops.gateway.translate import (
    extract_interrupt,
    final_text,
    translate_updates,
)
from opendevops.models import registry
from opendevops.models.pricing import PriceTable
from opendevops.policy.loader import load_policy

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from opendevops.config import AppConfig, ResolvedProfile

logger = logging.getLogger(__name__)

# The checkpointer sqlite db filename under ``cfg.state.dir`` (the AsyncSqliteSaver). The
# suspend/resume of an escalation is durable across this file.
_CHECKPOINT_FILE = "checkpoints.sqlite3"


@dataclass
class _Suspended:
    """Context captured when a run SUSPENDS on an escalation, so a resume continues the same run.

    ``baseline_cost`` is the cumulative ``run_cost_usd`` at suspend (the resume segment's daily
    top-up delta is measured against it); ``authoritative_so_far`` accumulates the priced
    authoritative spend across segments so the final ``run_completed`` reflects the whole run.
    """

    run_id: str
    ctx: AgentContext
    prof: ResolvedProfile
    baseline_cost: float
    authoritative_so_far: float

# A delta smaller than this is treated as float noise and not charged to the counter.
_DELTA_EPSILON = 1e-9


def _new_run_id() -> str:
    """A time-sortable ULID run id (reuses the audit module's ULID generator)."""
    return new_event_id()


class LocalGateway:
    """In-process :class:`~opendevops.gateway.base.AgentGateway` over the compiled agent graph.

    Args:
        cfg: the validated application config.
        audit: optional shared :class:`AuditLogger` (defaults to one on ``cfg.audit.dir``).
        counter: optional shared :class:`DailyCounter` (defaults to whatever
            :func:`~opendevops.budget.daily.build_daily_counter` selects for ``cfg`` — the
            durable ``SqliteDailyCounter`` on ``cfg.audit.dir`` by default, or the shared
            ``RedisDailyCounter`` when ``budgets.daily.backend == "redis"``).

    The optional injections exist so tests can pass an :class:`InMemoryDailyCounter` and inspect
    the very audit logger the graph wrote to; production constructs ``LocalGateway(cfg)``.
    """

    def __init__(
        self,
        cfg: AppConfig,
        *,
        audit: AuditLogger | None = None,
        counter: DailyCounter | None = None,
    ) -> None:
        self._cfg = cfg
        self._audit = audit if audit is not None else AuditLogger(cfg.audit.dir)
        self._counter: DailyCounter = (
            counter if counter is not None else build_daily_counter(cfg)
        )
        self._price_table = PriceTable.from_config(cfg.models)
        self._model_key = registry.resolve(cfg, "main")
        self._price_key_by_name = self._build_price_key_index()
        self._daily_cfg = cfg.budgets.daily
        # NEVER pass run_lifecycle=True here: LocalGateway writes its OWN run_started/run_completed
        # book-ends (start_run before ainvoke, end_run after), so an in-graph RunLifecycleMiddleware
        # would double the book-ends into the same chain file. That flag is exclusively the server
        # build's (server_graph()), where no gateway shares the graph's process to write them.
        self._agent = build_agent(cfg, audit=self._audit, counter=self._counter)
        self._git_sha = agent_git_sha()
        self._policy_version = load_policy(cfg.policy.dir).policy_version
        # In-flight run tasks by thread_id, so ``cancel`` can interrupt them.
        self._tasks: dict[str, asyncio.Task[Any]] = {}
        # Escalation suspend/resume: the AsyncSqliteSaver (built lazily inside a running loop — its
        # __init__ calls asyncio.get_running_loop) and the per-thread suspended-run context.
        self._saver: AsyncSqliteSaver | None = None
        self._suspended: dict[str, _Suspended] = {}

    # -- public surface -------------------------------------------------------------------

    async def create_thread(self, thread_id: str | None = None) -> str:
        """Allocate an opaque thread id (a fresh uuid4), or return the caller-chosen one.

        In-process threads carry no server-side state to allocate — the id is just the
        checkpointer key — so reuse is trivial: an explicit ``thread_id`` is returned verbatim
        (idempotent by construction), and ``None`` mints a fresh uuid4. Mirrors the additive
        ``thread_id`` kwarg ``ServerGateway.create_thread`` uses for deterministic incident
        threads.
        """
        return thread_id if thread_id is not None else uuid.uuid4().hex

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
        """Run one turn (``ainvoke``) with full accounting and audit book-ends.

        A turn that SUSPENDS on a policy escalation returns a :class:`RunResult` whose
        ``interrupted`` is an :class:`Escalation` (the chain stays open); resume it with
        :meth:`resume_interrupt`.
        """
        run_id = _new_run_id()
        prof = self._cfg.budgets.profile(profile)
        ctx = self._context(run_id, principal, interface, environment, profile)

        refusal = await self._daily_precheck(principal)
        if refusal is not None:
            return self._refuse(run_id, self._audit_header(ctx), refusal)

        self._audit.start_run(run_id, **self._audit_header(ctx))
        await self._ensure_checkpointer()
        return await self._drive(
            run_id, ctx, prof, {"messages": [("user", user_input)]}, thread_id, 0.0, 0.0
        )

    async def resume_interrupt(
        self,
        thread_id: str,
        decisions: list[dict[str, Any]],
        *,
        approver: str,
    ) -> RunResult:
        """Resume a suspended (escalated) run on ``thread_id`` with the approver's decisions."""
        susp = self._pop_suspended(thread_id)
        await self._ensure_checkpointer()
        return await self._drive(
            susp.run_id,
            susp.ctx,
            susp.prof,
            self._resume_command(decisions, approver),
            thread_id,
            susp.baseline_cost,
            susp.authoritative_so_far,
        )

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
        """Run one turn (``astream``, updates+values), yielding events + a final :class:`RunEnd`.

        Uses ``stream_mode=["updates", "values"]`` (NOT ``"messages"``): message-mode forces
        token-level model streaming, which the deterministic fake model cannot produce for a
        tool-call turn — the documented fallback. ``updates`` drives the per-node event
        translation; the last ``values`` frame is the final state used for accounting. A turn that
        suspends on an escalation yields an :class:`EscalationEvent` just before the final
        :class:`RunEnd`.
        """
        run_id = _new_run_id()
        prof = self._cfg.budgets.profile(profile)
        ctx = self._context(run_id, principal, interface, environment, profile)

        refusal = await self._daily_precheck(principal)
        if refusal is not None:
            yield RunEnd(result=self._refuse(run_id, self._audit_header(ctx), refusal))
            return

        self._audit.start_run(run_id, **self._audit_header(ctx))
        await self._ensure_checkpointer()
        completed = False
        try:
            async for event in self._drive_stream(
                run_id, ctx, prof, {"messages": [("user", user_input)]}, thread_id, 0.0, 0.0
            ):
                if isinstance(event, RunEnd):
                    completed = True
                yield event
        except GeneratorExit:
            await self._close_if_abandoned(thread_id, run_id, completed)
            raise

    async def stream_resume(
        self,
        thread_id: str,
        decisions: list[dict[str, Any]],
        *,
        approver: str,
    ) -> AsyncIterator[RunEvent]:
        """Streaming variant of :meth:`resume_interrupt` (the CLI renders the resumed turn).

        Consumer-abandonment disposition — (a) close as ``abandoned``, fail-closed
        ------------------------------------------------------------------------------
        Symmetric with :meth:`stream`: if the CLI abandons the generator mid-resume (e.g. a
        rendering exception ``aclose()``'s it after one event), catch ``GeneratorExit``, cancel any
        in-flight graph task, and CLOSE the audit chain as ``abandoned`` — never leak an open chain.
        Because :meth:`_pop_suspended` removed the suspended record BEFORE the first yield and this
        path does NOT re-register it, a later :meth:`resume_interrupt` on the same thread raises the
        friendly ``GatewayError`` ("no suspended run to resume"): **the pending interrupt in the
        checkpoint is dead**, by design.

        Why not (b) re-register the record so a second resume can retry? A probe
        showed it is unsafe: by the time abandonment is observable the resume's graph has already
        run *past* ``interrupt()`` (the interrupt is consumed, and for an ``approve`` the escalated
        tool has ALREADY executed — the destructive ``kubectl delete`` ran before the consumer saw
        a second event). So there is no pending interrupt left to cleanly retry — a second
        ``Command(resume=...)`` merely re-drives a half-finished graph from an arbitrary checkpoint
        position, and re-presenting an already-executed action to a second approver is an
        authorization/audit hazard. The ``tool_call_id`` execution cache does prevent a literal
        double-exec on replay, but that does not make (b) sound (stale accounting baselines on the
        re-registered record; a second approver "deciding" an action that already happened).
        Fail-closed beats clever: close the chain and record the truth.
        """
        susp = self._pop_suspended(thread_id)
        await self._ensure_checkpointer()
        completed = False
        try:
            async for event in self._drive_stream(
                susp.run_id,
                susp.ctx,
                susp.prof,
                self._resume_command(decisions, approver),
                thread_id,
                susp.baseline_cost,
                susp.authoritative_so_far,
            ):
                if isinstance(event, RunEnd):
                    completed = True
                yield event
        except GeneratorExit:
            await self._close_if_abandoned(thread_id, susp.run_id, completed)
            raise

    async def _close_if_abandoned(self, thread_id: str, run_id: str, completed: bool) -> None:
        """Close ``run_id``'s chain as ``abandoned`` when a stream consumer ``aclose()``'d it.

        Called from the ``GeneratorExit`` finalizer of :meth:`stream` / :meth:`stream_resume`.
        Left unhandled, an abandoned stream leaks an open audit chain (``run_started`` with no
        ``run_completed``) and an orphaned in-flight graph task. Cancel the task and close the chain
        — UNLESS the run already reached its terminal ``RunEnd`` (``completed``; chain already
        closed) or SUSPENDED on an escalation (``thread_id in self._suspended`` — the chain is
        intentionally kept open for resume, and for ``stream_resume`` a re-suspend registers a fresh
        record). Costs are hardcoded ``0.0`` (no final state to price), consistent with both
        streams' abandonment summaries. Never raises — the caller re-raises ``GeneratorExit`` so the
        generator finalizes correctly.
        """
        if completed or thread_id in self._suspended:
            return
        await self.cancel(thread_id)
        self._audit.end_run(
            run_id,
            summary={
                "status": "abandoned",
                "cost_state": 0.0,
                "cost_authoritative": 0.0,
                "usage": {},
            },
        )

    # -- segment drivers (shared by run/resume and stream/stream_resume) ------------------

    async def _drive(
        self,
        run_id: str,
        ctx: AgentContext,
        prof: ResolvedProfile,
        invoke_input: Any,
        thread_id: str,
        baseline_cost: float,
        authoritative_so_far: float,
    ) -> RunResult:
        """Invoke one segment (fresh input or a resume Command) and finalize-or-suspend it."""
        try:
            with get_usage_metadata_callback() as cb:
                config = self._invoke_config(cb, thread_id, prof.recursion_limit)
                coro = self._agent.ainvoke(invoke_input, config=config, context=ctx)
                final_state = await self._guard(thread_id, coro, prof.wall_clock_s)
        except TimeoutError:
            return self._interrupted(
                run_id, "wall_clock", prof.wall_clock_s, cb, "wall clock exceeded"
            )
        except GraphRecursionError:
            return self._interrupted(
                run_id, "recursion", prof.recursion_limit, cb, "recursion limit exceeded"
            )
        except asyncio.CancelledError:
            return self._interrupted(run_id, "cancelled", None, cb, "run cancelled")
        except Exception as exc:  # noqa: BLE001 - close the chain, then re-raise wrapped
            self._audit.end_run(
                run_id,
                summary={
                    "status": "error",
                    "error": str(exc),
                    "cost_state": 0.0,
                    "cost_authoritative": 0.0,
                    "usage": {},
                },
            )
            raise GatewayRunError(run_id, exc) from exc

        return await self._finalize_or_suspend(
            run_id, ctx, prof, thread_id, final_state, cb, baseline_cost, authoritative_so_far
        )

    async def _drive_stream(
        self,
        run_id: str,
        ctx: AgentContext,
        prof: ResolvedProfile,
        invoke_input: Any,
        thread_id: str,
        baseline_cost: float,
        authoritative_so_far: float,
    ) -> AsyncIterator[RunEvent]:
        """Stream one segment; yield events then an EscalationEvent (if suspended) + a RunEnd."""
        final_state: dict[str, Any] = {}
        try:
            with get_usage_metadata_callback() as cb:
                config = self._invoke_config(cb, thread_id, prof.recursion_limit)
                agen = self._agent.astream(
                    invoke_input, config=config, context=ctx, stream_mode=["updates", "values"]
                )
                async for event, state in self._guarded_stream(thread_id, agen, prof.wall_clock_s):
                    if state is not None:
                        final_state = state
                    if event is not None:
                        yield event
        except TimeoutError:
            yield RunEnd(
                result=self._interrupted(
                    run_id, "wall_clock", prof.wall_clock_s, cb, "wall clock exceeded"
                )
            )
            return
        except GraphRecursionError:
            yield RunEnd(
                result=self._interrupted(
                    run_id, "recursion", prof.recursion_limit, cb, "recursion limit exceeded"
                )
            )
            return
        except asyncio.CancelledError:
            yield RunEnd(result=self._interrupted(run_id, "cancelled", None, cb, "run cancelled"))
            return
        except Exception as exc:  # noqa: BLE001 - close the chain, then surface a friendly RunEnd
            # The CLI REPL streams exclusively, so an unexpected error mid-stream (a model / API
            # failure) must NOT escape raw: that would crash the REPL and leave the audit chain
            # open (``run_started`` with no ``run_completed``). Mirror ``_drive``'s catch-all —
            # close the chain with ``status="error"`` — but yield a terminal :class:`RunEnd`
            # carrying a friendly error string instead of raising, so the REPL renders the error
            # and stays alive.
            self._audit.end_run(
                run_id,
                summary={
                    "status": "error",
                    "error": str(exc),
                    "cost_state": 0.0,
                    "cost_authoritative": 0.0,
                    "usage": {},
                },
            )
            yield RunEnd(
                result=RunResult(
                    final_text="",
                    run_id=run_id,
                    cost_usd_state=0.0,
                    cost_usd_authoritative=0.0,
                    usage={},
                    error="unexpected error",
                )
            )
            return

        result = await self._finalize_or_suspend(
            run_id, ctx, prof, thread_id, final_state, cb, baseline_cost, authoritative_so_far
        )
        if result.interrupted is not None:
            yield EscalationEvent(escalation=result.interrupted)
        yield RunEnd(result=result)

    async def cancel(self, thread_id: str) -> None:
        """Cancel ``thread_id``'s in-flight run (idempotent; a no-op if nothing is running)."""
        task = self._tasks.get(thread_id)
        if task is not None and not task.done():
            task.cancel()

    async def daily_total(self, scope: str = "global") -> float:
        """The daily spend accumulated under ``scope`` today (drives the REPL's cost line)."""
        return await self._counter.total(scope)

    async def aclose(self) -> None:
        """Close the checkpointer's aiosqlite connection (best-effort; idempotent).

        The REPL's persistent loop lives for the whole session so this is normally implicit at
        process exit, but closing deterministically avoids leaking the connection's worker thread
        (and the "event loop is closed" noise when a short-lived loop is torn down under it).
        """
        saver = self._saver
        if saver is None:
            return
        self._saver = None
        try:
            await saver.conn.close()
        except Exception:  # noqa: BLE001 - a close failure must never surface to a caller
            logger.debug("checkpointer connection close failed", exc_info=True)

    # -- run execution guards -------------------------------------------------------------

    async def _guard(self, thread_id: str, coro: Any, wall_clock_s: int) -> dict[str, Any]:
        """Run ``coro`` as a tracked, cancellable task under a wall-clock ``wait_for``."""
        task: asyncio.Task[dict[str, Any]] = asyncio.ensure_future(coro)
        self._tasks[thread_id] = task
        try:
            return await asyncio.wait_for(task, timeout=wall_clock_s)
        finally:
            self._tasks.pop(thread_id, None)

    async def _guarded_stream(
        self, thread_id: str, agen: AsyncIterator[tuple[str, Any]], wall_clock_s: int
    ) -> AsyncIterator[tuple[RunEvent | None, dict[str, Any] | None]]:
        """Wrap the graph astream so ``cancel`` can interrupt it and a wall clock bounds it.

        Each ``anext`` step is a tracked, cancellable task (so ``cancel(thread_id)`` raises
        ``CancelledError`` out of the in-flight step) and the whole turn shares one wall-clock
        deadline (a step still running past it raises ``TimeoutError``). ``asyncio.wait`` — not
        ``wait_for`` — avoids wrapping the iterator's ``StopAsyncIteration`` in a task-cancel.
        Yields ``(event, values_state)`` pairs — exactly one of the two is non-``None``.
        """
        loop = asyncio.get_event_loop()
        deadline = loop.time() + wall_clock_s
        iterator = agen.__aiter__()
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise TimeoutError("wall clock exceeded during stream")
            step: asyncio.Task[tuple[str, Any]] = asyncio.ensure_future(iterator.__anext__())
            self._tasks[thread_id] = step
            try:
                done, _pending = await asyncio.wait({step}, timeout=remaining)
                if not done:
                    step.cancel()
                    raise TimeoutError("wall clock exceeded during stream")
                try:
                    mode, chunk = step.result()
                except StopAsyncIteration:
                    return
            finally:
                self._tasks.pop(thread_id, None)
            if mode == "values":
                yield None, chunk
                continue
            for translated in translate_updates(chunk):
                yield translated, None

    # -- checkpointer / resume plumbing ---------------------------------------------------

    async def _ensure_checkpointer(self) -> None:
        """Build the AsyncSqliteSaver once (in-loop) and attach it to the compiled graph.

        ``AsyncSqliteSaver.__init__`` calls ``asyncio.get_running_loop()``, so it cannot be built
        in the sync constructor. It is built lazily on first async use and attached in place
        (``graph.checkpointer = saver``) — which keeps the ``self._agent`` object stable, so an
        interrupt can suspend/resume without the checkpointer being rebuilt per turn.
        """
        if self._saver is not None:
            return
        state_dir = self._cfg.state.dir
        state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        conn = await aiosqlite.connect(str(state_dir / _CHECKPOINT_FILE))
        self._saver = AsyncSqliteSaver(conn)
        self._agent.checkpointer = self._saver

    def _pop_suspended(self, thread_id: str) -> _Suspended:
        susp = self._suspended.pop(thread_id, None)
        if susp is None:
            raise GatewayError(f"no suspended run to resume for thread {thread_id!r}")
        return susp

    @staticmethod
    def _resume_command(decisions: list[dict[str, Any]], approver: str) -> Command[Any]:
        """A ``Command(resume=...)`` with the approver injected into each decision (audit trail)."""
        injected = [{**d, "approver": approver} for d in decisions]
        return Command(resume={"decisions": injected})

    def _context(
        self, run_id: str, principal: str, interface: str, environment: str, profile: str
    ) -> AgentContext:
        return AgentContext(
            principal=principal,
            interface=interface,
            environment=environment,
            budget_profile=profile,
            run_id=run_id,
        )

    # -- accounting + finalization --------------------------------------------------------

    async def _finalize_or_suspend(
        self,
        run_id: str,
        ctx: AgentContext,
        prof: ResolvedProfile,
        thread_id: str,
        final_state: dict[str, Any],
        cb: UsageMetadataCallbackHandler,
        baseline_cost: float,
        authoritative_so_far: float,
    ) -> RunResult:
        """Account this segment, then either SUSPEND (escalation) or close the chain (completed).

        The accounting — pricing the callback aggregate and topping up the daily counter with the
        segment's summarizer delta — is *guarded* (runs outside the driver's try/except, so a
        pricing raise or counter outage must not escape and leave the chain open). ``run_cost_usd``
        is a checkpointed accumulating channel, so ``final_state`` carries the WHOLE run's spend;
        the segment's daily top-up delta is measured against ``baseline_cost`` (the cumulative
        spend at the previous suspend, 0 for a fresh run). If ``__interrupt__`` is present the run
        suspended: keep the chain open, remember the resume context, and return an ``interrupted``
        RunResult. Otherwise write ``run_completed`` with the whole-run figures.
        """
        interrupt_payload = extract_interrupt(final_state)
        state_total = float(final_state.get("run_cost_usd") or 0.0)
        segment_state_delta = state_total - baseline_cost
        seg_authoritative, missing, counter_write_failed = await self._account_segment(
            run_id, ctx.principal, segment_state_delta, cb
        )
        total_authoritative = authoritative_so_far + seg_authoritative

        usage: dict[str, Any] = dict(final_state.get("run_usage") or {})
        if missing:
            usage["usage_missing"] = int(usage.get("usage_missing", 0)) + missing
        if counter_write_failed:
            usage["counter_write_failed"] = True
        budget_stop = final_state.get("budget_stop")

        if interrupt_payload is not None:
            # SUSPEND: the chain stays open; capture the context a resume needs.
            self._suspended[thread_id] = _Suspended(
                run_id=run_id,
                ctx=ctx,
                prof=prof,
                baseline_cost=state_total,
                authoritative_so_far=total_authoritative,
            )
            return RunResult(
                final_text="",
                run_id=run_id,
                cost_usd_state=state_total,
                cost_usd_authoritative=total_authoritative,
                usage=usage,
                budget_stop=budget_stop,
                interrupted=Escalation(
                    payload=interrupt_payload, run_id=run_id, thread_id=thread_id
                ),
            )

        # COMPLETE: close the audit chain with the whole-run figures.
        self._audit.end_run(
            run_id,
            summary={
                "status": "completed",
                "cost_state": state_total,
                "cost_authoritative": total_authoritative,
                "usage": usage,
                "budget_stop": budget_stop,
            },
        )
        return RunResult(
            final_text=final_text(final_state),
            run_id=run_id,
            cost_usd_state=state_total,
            cost_usd_authoritative=total_authoritative,
            usage=usage,
            budget_stop=budget_stop,
        )

    async def _account_segment(
        self,
        run_id: str,
        principal: str,
        segment_state_delta: float,
        cb: UsageMetadataCallbackHandler,
    ) -> tuple[float, int, bool]:
        """Price this segment's callback aggregate + top up the daily counter with its delta.

        Returns ``(segment_authoritative, usage_missing, counter_write_failed)``. Guarded: a
        pricing raise or a counter outage is logged and flagged (``counter_write_failed``) rather
        than raised — the counter is a soft control; the authoritative ledger is what matters. On a
        counter-write failure the already-priced authoritative figure is preserved.
        """
        seg_authoritative = segment_state_delta
        missing = 0
        counter_write_failed = False
        try:
            seg_authoritative, missing = self._price_aggregate(cb)
            delta = seg_authoritative - segment_state_delta
            if delta > _DELTA_EPSILON:
                await self._counter.add("global", delta)
                await self._counter.add(f"principal:{principal}", delta)
        except Exception:  # noqa: BLE001 - accounting must never leave the audit chain unclosed
            logger.exception(
                "finalize accounting failed for run %s; closing the chain with "
                "counter_write_failed flagged",
                run_id,
            )
            counter_write_failed = True
        return seg_authoritative, missing, counter_write_failed

    def _price_aggregate(self, cb: UsageMetadataCallbackHandler) -> tuple[float, int]:
        """Sum USD over the callback aggregate; return ``(authoritative_usd, usage_missing)``.

        Each aggregate key is a reported model name; map it to a priced ``provider:model`` row
        (exact, then bare-suffix). An unmapped name is priced with the main model's row and
        counted as one blind spot (log-warned), never silently dropped.
        """
        total = 0.0
        missing = 0
        for name, usage in self._usage_aggregate(cb).items():
            key = self._resolve_price_key(name)
            if key is None:
                logger.warning(
                    "usage aggregate reports unknown model name %r; pricing with main model %r "
                    "and counting one usage_missing blind spot",
                    name,
                    self._model_key,
                )
                key = self._model_key
                missing += 1
            total += self._price_table.cost_usd(key, usage)
        return total, missing

    def _usage_aggregate(self, cb: UsageMetadataCallbackHandler) -> dict[str, Any]:
        """The ``{model_name: usage}`` aggregate the callback collected (overridable test seam)."""
        return dict(cb.usage_metadata)

    def _resolve_price_key(self, model_name: str) -> str | None:
        """Map a reported model name to a priced ``provider:model`` key, or ``None`` if unknown."""
        if model_name in self._price_table.prices:
            return model_name
        return self._price_key_by_name.get(model_name)

    def _build_price_key_index(self) -> dict[str, str]:
        """Index each priced key by itself and by its bare model suffix (after ``provider:``)."""
        index: dict[str, str] = {}
        for key in self._price_table.prices:
            index[key] = key
            _, _, suffix = key.partition(":")
            if suffix:
                index.setdefault(suffix, key)
        return index

    # -- refusal / interruption paths -----------------------------------------------------

    async def _daily_precheck(self, principal: str) -> dict[str, Any] | None:
        """Return a ``budget_stop`` dict if a daily envelope is already at/over cap, else ``None``.

        Pre-checks both the ``global`` and ``principal:<principal>`` envelopes (global first) so a
        run is refused *before any model call* — the same caps the in-graph
        :class:`DailyBudgetMiddleware` enforces mid-run. A counter outage fails closed (refuse),
        matching the middleware's fail-closed posture.
        """
        principal_scope = f"principal:{principal}"
        try:
            global_spent = await self._counter.total("global")
            principal_spent = await self._counter.total(principal_scope)
        except Exception:  # noqa: BLE001 - counter outage: fail closed like the middleware
            logger.exception("daily counter outage in gateway pre-check; refusing (fail-closed)")
            return {"kind": "counter_outage"}
        if global_spent >= self._daily_cfg.global_usd:
            return {
                "kind": "daily_usd",
                "scope": "global",
                "spent": global_spent,
                "cap": self._daily_cfg.global_usd,
            }
        if principal_spent >= self._daily_cfg.per_principal_usd:
            return {
                "kind": "daily_usd",
                "scope": principal_scope,
                "spent": principal_spent,
                "cap": self._daily_cfg.per_principal_usd,
            }
        return None

    def _refuse(self, run_id: str, header: dict[str, Any], stop: dict[str, Any]) -> RunResult:
        """Write ``run_started`` + ``budget_trip`` + ``run_completed`` for an audited refusal."""
        self._audit.start_run(run_id, **header)
        self._audit.append(run_id, EventType.budget_trip, summary=stop)
        self._audit.end_run(
            run_id,
            summary={
                "status": "refused",
                "cost_state": 0.0,
                "cost_authoritative": 0.0,
                "usage": {},
                "budget_stop": stop,
            },
        )
        return RunResult(
            final_text="",
            run_id=run_id,
            cost_usd_state=0.0,
            cost_usd_authoritative=0.0,
            usage={},
            budget_stop=stop,
            error="daily budget exhausted",
        )

    def _interrupted(
        self,
        run_id: str,
        kind: str,
        limit: int | None,
        cb: UsageMetadataCallbackHandler,
        error: str,
    ) -> RunResult:
        """Close the chain for a wall-clock / recursion / cancel interruption.

        Records a ``budget_trip`` + ``run_completed``, a best-effort *authoritative* cost, and the
        partial token ``usage`` read from the callback aggregate. The daily counter is NOT
        touched here: the in-graph middleware already charged what it saw, and without a final
        state there is no safe delta to compute.

        The pricing/usage read is *guarded* (like :meth:`_account_segment`): a raising price table
        must not mask the timeout/interruption or leave the audit chain open — it degrades to zero
        cost/usage plus a logged exception, and the chain still closes.
        """
        trip: dict[str, Any] = {"kind": kind}
        if limit is not None:
            trip["limit"] = limit
        try:
            authoritative, _ = self._price_aggregate(cb)
            usage = self._usage_detail(cb)
        except Exception:  # noqa: BLE001 - accounting must never leave the audit chain unclosed
            logger.exception(
                "pricing the callback aggregate failed during %s interruption for run %s; "
                "recording zero cost/usage",
                kind,
                run_id,
            )
            authoritative = 0.0
            usage = {}
        self._audit.append(run_id, EventType.budget_trip, summary=trip)
        self._audit.end_run(
            run_id,
            summary={
                "status": kind if kind != "wall_clock" else "cancelled",
                "cost_state": 0.0,
                "cost_authoritative": authoritative,
                "usage": usage,
                "budget_stop": trip,
            },
        )
        return RunResult(
            final_text="",
            run_id=run_id,
            cost_usd_state=0.0,
            cost_usd_authoritative=authoritative,
            usage=usage,
            budget_stop=trip,
            error=error,
        )

    def _usage_detail(self, cb: UsageMetadataCallbackHandler) -> dict[str, Any]:
        """Sum the callback aggregate's token counts into a usage dict (``{}`` if the aggregate is).

        Mirrors the ``run_usage`` token shape used on the completed path, so an interrupted run's
        :class:`RunResult` still carries the partial usage the callback saw.
        """
        aggregate = self._usage_aggregate(cb)
        if not aggregate:
            return {}
        detail = {"input_tokens": 0, "output_tokens": 0, "cache_read": 0, "cache_creation": 0}
        for usage in aggregate.values():
            details = usage.get("input_token_details") or {}
            detail["input_tokens"] += usage.get("input_tokens", 0)
            detail["output_tokens"] += usage.get("output_tokens", 0)
            detail["cache_read"] += details.get("cache_read", 0)
            detail["cache_creation"] += details.get("cache_creation", 0)
        return detail

    # -- helpers --------------------------------------------------------------------------

    def _invoke_config(
        self, cb: UsageMetadataCallbackHandler, thread_id: str, recursion_limit: int
    ) -> dict[str, Any]:
        """The langgraph invoke/stream config: usage callback + recursion limit + thread id."""
        return {
            "callbacks": [cb],
            "recursion_limit": recursion_limit,
            "configurable": {"thread_id": thread_id},
        }

    def _audit_header(self, ctx: AgentContext) -> dict[str, Any]:
        """The run-scoped audit header stamped onto every event of the run's chain."""
        return {
            "principal": {"interface": ctx.interface, "user": ctx.principal},
            "environment": ctx.environment,
            "model": self._model_key,
            "policy_version": self._policy_version,
            "agent_git_sha": self._git_sha,
        }
