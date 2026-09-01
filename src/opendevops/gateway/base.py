"""The ``AgentGateway`` protocol and its typed run/stream value objects.

The gateway is the single seam between an *interface* (the CLI REPL now; a LangGraph Server /
Slack adapter later) and the compiled agent graph. It owns run identity, the audit-chain
book-ends, wall-clock/recursion enforcement, and the authoritative cost ledger, so every
interface gets identical accounting and safety without re-implementing it.

Two surfaces, same arguments and same accounting:

* :meth:`AgentGateway.run` — await one turn to completion, get a :class:`RunResult`.
* :meth:`AgentGateway.stream` — async-iterate :class:`RunEvent`\\ s as the turn unfolds
  (assistant text, tool calls, tool results), terminated by a single :class:`RunEnd` carrying
  the same :class:`RunResult` ``run`` would have returned.

All events are small frozen-ish dataclasses with a ``type`` string discriminator so an
interface can ``match`` on either the class or the tag, and so they serialize cleanly if a
future transport needs to put them on a wire.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, runtime_checkable

from opendevops.tools.scrub import scrub


@dataclass
class RunResult:
    """The terminal outcome of one agent turn.

    * ``final_text`` — the last assistant message text (empty on a refusal/timeout).
    * ``cost_usd_state`` — the in-graph accumulated ``run_cost_usd`` (main-model calls the
      budget middleware priced and counted per-call).
    * ``cost_usd_authoritative`` — the gateway's after-the-fact ledger: the sum over the
      usage-metadata callback aggregate (main model **plus** any summarizer / untracked model
      calls). ``>= cost_usd_state``; the difference is charged to the daily counter as a delta.
    * ``usage`` — merged token counters + blind-spot flags (``usage_missing`` /
      ``counter_write_failed``).
    * ``budget_stop`` — set iff a cap tripped (per-run USD, daily USD, wall-clock, recursion,
      or a counter outage); ``None`` on a clean finish.
    * ``error`` — a short human string iff the turn did not complete normally; ``None`` on success.
    * ``interrupted`` — set iff the turn SUSPENDED on a policy ``escalate`` awaiting human
      review. The run's audit chain is still OPEN: resume it with
      :meth:`AgentGateway.resume_interrupt` (same ``thread_id``) to continue to a final
      :class:`RunResult`. ``None`` on a run that ran to completion.
    """

    final_text: str
    run_id: str
    cost_usd_state: float
    cost_usd_authoritative: float
    usage: dict[str, Any] = field(default_factory=dict)
    budget_stop: dict[str, Any] | None = None
    error: str | None = None
    interrupted: Escalation | None = None


@dataclass
class Escalation:
    """A suspended run awaiting human approval of a policy-escalated tool call.

    * ``payload`` — the review envelope the middleware's ``interrupt()`` raised:
      ``{"action_requests": [{"action", "args"}], "review_configs": [{"rule_id", "reason",
      "allowed_decisions", "timeout_s"}]}``. The interface renders it and collects a decision.
    * ``run_id`` / ``thread_id`` — the open run and its thread; ``resume_interrupt(thread_id, ...)``
      continues the SAME run chain.
    """

    payload: dict[str, Any]
    run_id: str
    thread_id: str
    type: Literal["escalation"] = "escalation"


@dataclass(frozen=True)
class EscalationDetails:
    """Sanitized, bounded fields shared by every escalation interface."""

    tool: str
    argv: list[str]
    rule_id: str
    reason: str
    timeout_s: int | None
    tool_call_id: str


def escalation_details(escalation: Escalation) -> EscalationDetails:
    """Parse the first action/review pair from an interrupt payload, failing closed."""

    requests = escalation.payload.get("action_requests") or []
    request: dict[str, Any] = requests[0] if requests and isinstance(requests[0], dict) else {}
    raw_args = request.get("args")
    args: dict[str, Any] = raw_args if isinstance(raw_args, dict) else {}
    raw_values = args.get("argv")
    raw_argv: list[Any] = raw_values if isinstance(raw_values, list) else []
    reviews = escalation.payload.get("review_configs") or []
    review: dict[str, Any] = reviews[0] if reviews and isinstance(reviews[0], dict) else {}

    def clean(value: Any, limit: int) -> str:
        return scrub(str(value))[0][:limit]

    timeout = review.get("timeout_s")
    return EscalationDetails(
        tool=clean(request.get("action") or "unknown", 128),
        argv=[clean(value, 4096) for value in raw_argv[:128]],
        rule_id=clean(review.get("rule_id") or "unknown", 256),
        reason=clean(review.get("reason") or "", 2000),
        timeout_s=timeout if isinstance(timeout, int) and timeout > 0 else None,
        tool_call_id=clean(
            request.get("tool_call_id") or request.get("id") or escalation.run_id, 256
        ),
    )


@dataclass
class AssistantText:
    """A chunk of assistant-visible text (one per model turn under updates-mode streaming)."""

    text: str
    type: Literal["assistant_text"] = "assistant_text"


@dataclass
class ToolCall:
    """The agent asked to run a tool. ``argv`` is populated for the argv-only ``run_command``."""

    name: str
    argv: list[str] | None = None
    type: Literal["tool_call"] = "tool_call"


@dataclass
class ToolResult:
    """A tool's terminating message. ``denied`` + ``rule_id`` are set for a policy denial."""

    excerpt: str
    denied: bool = False
    rule_id: str | None = None
    type: Literal["tool_result"] = "tool_result"


@dataclass
class EscalationEvent:
    """A streamed signal that the run SUSPENDED on a policy escalation (HITL).

    Emitted immediately before the terminal :class:`RunEnd` of a stream when the turn interrupts:
    the interface renders ``escalation.payload`` (approve/edit/reject), then calls
    :meth:`AgentGateway.resume_interrupt` / :meth:`AgentGateway.stream_resume` on the same thread.
    """

    escalation: Escalation
    type: Literal["escalation_event"] = "escalation_event"


@dataclass
class RunEnd:
    """The stream terminator: carries the same :class:`RunResult` that :meth:`run` returns."""

    result: RunResult
    type: Literal["run_end"] = "run_end"


# The discriminated union an interface renders. `RunEnd` is always the last event of a stream; an
# `EscalationEvent`, when present, is the second-to-last (the turn suspended for human review).
RunEvent = AssistantText | ToolCall | ToolResult | EscalationEvent | RunEnd


class GatewayError(RuntimeError):
    """Base for gateway-raised errors."""


class GatewayConfigError(GatewayError):
    """The gateway could not be constructed from config (invalid config or an unusable target)."""


class ApprovalSeparationError(GatewayError):
    """A production requester attempted to authorize their own mutation."""


def enforce_approval_separation(
    *,
    requester: str,
    approver: str,
    environment: str,
    decisions: list[dict[str, Any]],
    required: bool,
) -> None:
    """Reject self-approval/edit for production while still allowing self-rejection."""
    authorizes = any(
        str(item.get("type") or "").lower() in {"approve", "edit"} for item in decisions
    )
    if required and environment == "prod" and authorizes and requester == approver:
        raise ApprovalSeparationError(
            "production changes require an approver different from the requester"
        )


class GatewayRunError(GatewayError):
    """An unexpected (non-budget, non-timeout) failure escaped a run; wraps the original.

    The run's audit chain is still closed with ``status="error"`` before this is raised.
    """

    def __init__(self, run_id: str, cause: BaseException) -> None:
        self.run_id = run_id
        self.cause = cause
        super().__init__(f"run {run_id!r} failed: {cause}")


@runtime_checkable
class AgentGateway(Protocol):
    """The interface every front-end drives. All methods are async; ``stream`` is an async gen."""

    async def create_thread(self, thread_id: str | None = None) -> str:
        """Allocate a conversation/thread id, or reuse a caller-chosen one idempotently.

        With ``thread_id=None`` (the default) a fresh opaque id is minted (a uuid locally; a
        server-minted thread in service mode). With an explicit ``thread_id`` the caller pins the
        id — used by the webhook app to derive a *deterministic* incident thread
        (``uuid5(NS_INCIDENT, fingerprint)``) so the same alert reuses the same thread: the
        allocation is idempotent (``ServerGateway`` passes ``if_exists="do_nothing"``), and the
        returned id equals the one requested.
        """
        ...

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
        """Run one turn to completion and return its :class:`RunResult`."""
        ...

    def stream(
        self,
        thread_id: str,
        user_input: str,
        *,
        profile: str = "default",
        principal: str,
        interface: str,
        environment: str,
    ) -> AsyncIterator[RunEvent]:
        """Run one turn, yielding :class:`RunEvent`\\ s and a final :class:`RunEnd`."""
        ...

    async def cancel(self, thread_id: str) -> None:
        """Cancel the in-flight run for ``thread_id`` (Ctrl-C in the REPL), if any."""
        ...

    async def resume_interrupt(
        self,
        thread_id: str,
        decisions: list[dict[str, Any]],
        *,
        approver: str,
    ) -> RunResult:
        """Resume a suspended (escalated) run on ``thread_id`` with the approver's ``decisions``.

        Injects ``approver`` into each decision and continues the SAME run (its audit chain stays
        open across the suspend). ``decisions`` is the deepagents-shaped list
        ``[{"type": "approve"|"edit"|"reject", "args"?, "message"?}]``. Returns the terminal
        :class:`RunResult` (which may itself be ``interrupted`` again on a further escalation).
        """
        ...

    def stream_resume(
        self,
        thread_id: str,
        decisions: list[dict[str, Any]],
        *,
        approver: str,
    ) -> AsyncIterator[RunEvent]:
        """Streaming variant of :meth:`resume_interrupt` (the CLI renders the resumed turn)."""
        ...
