"""Slack chat-ops adapter over the :class:`AgentGateway` (P4, T19).

An engineer talks to the agent in a Slack thread; a reply in the same Slack thread resumes the
SAME agent thread; a policy escalation renders as approve / edit / reject Block Kit buttons and the
approver is recorded in the audit trail. Transport is slack-bolt 1.30.0 **Socket Mode**
(``AsyncSocketModeHandler`` — no public URL required).

Driving model — STREAM-IN-PROCESS (mirrors the CLI REPL)
--------------------------------------------------------
The adapter holds a gateway (a :class:`~opendevops.gateway.local.LocalGateway` in the shipped
``start`` path) and drives ``gateway.stream(...)`` for a new message, rendering assistant text and
escalation buttons directly into the Slack thread — exactly the shape of ``cli._drive_turn`` /
``cli._consume_stream``. This is the simplest correct + testable choice: no round-trip through the
LangGraph Server webhook queue, the whole run/resume/escalation loop lives in one process, and
every branch is exercised by unit tests with an ``AsyncMock`` gateway + a stub Slack client. A
button click resolves the CLICKING user to an approver principal and calls
``gateway.resume_interrupt(...)`` (the
non-streaming resume — the CLI's ``stream_resume`` streams the resumed turn, but a Slack button is a
discrete interaction, so we render the single terminal :class:`RunResult` it returns: either a fresh
escalation or the final answer).

The webapp ``run-complete`` seam (:func:`opendevops.interfaces.webapp.create_app`'s ``notifier``)
is the ADDITIVE complement for a *server-mode* deployment where runs execute inside the LangGraph
Server rather than this process: :class:`SlackThreadNotifier` reads the same in-memory
:class:`SlackThreadRegistry` the adapter populates and posts the final answer when a completed run's
thread is a registered Slack destination. Both paths share the registry and the Block Kit builders.

Testability — thin Bolt wiring
------------------------------
Socket Mode needs a live websocket, so ALL logic lives in plain functions / adapter methods that
tests call directly; the ``AsyncApp`` listener bodies (:func:`build_bolt_app`) are thin shims that
``ack`` fast and delegate to those methods in a background task. slack-bolt is imported LAZILY in
:func:`build_bolt_app` / :func:`start` — its async surface pulls in ``aiohttp`` (an optional
``slack_sdk`` transport dep), so importing this module (as every test does) never requires it.

slack-bolt 1.30.0 probe (source read under site-packages, aiohttp not installed):
* ``slack_bolt.async_app.AsyncApp(*, token=..., signing_secret=..., ...)`` — keyword-only ctor;
  decorators ``@app.event("app_mention")`` / ``@app.event("message")`` / ``@app.action(<str|re>)``
  / ``@app.view(<callback_id>)`` register async listeners; listener args are kwargs-injected
  (``ack``, ``body``, ``event``, ``action``, ``view``, ``client``, ``logger``).
* ``slack_bolt.adapter.socket_mode.async_handler.AsyncSocketModeHandler(app, app_token)`` — its
  default aiohttp-based client; ``await handler.start_async()`` connects then sleeps forever.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol, cast, runtime_checkable

from opendevops.gateway import (
    AssistantText,
    EscalationEvent,
    RunEnd,
    ToolResult,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from opendevops.config import AppConfig, Principal
    from opendevops.gateway import AgentGateway, Escalation, RunEvent, RunResult

logger = logging.getLogger(__name__)

# Stable namespace for the deterministic Slack -> agent thread mapping (``uuid5(NS_SLACK, key)``).
# The same Slack thread (``channel:thread_ts``) always maps to the same agent thread, so a reply in
# that thread resumes the SAME run chain. Derived once, pinned as a literal (mirrors
# ``webapp.NS_INCIDENT``):  uuid5(uuid.NAMESPACE_URL, "https://opendevops.gnosis.io/ns/slack")
NS_SLACK = uuid.UUID("49732ea7-79ed-5495-a176-77c5f28a7f7e")

# The originating-interface tag stamped onto every Slack run (audit ``principal.interface``); the
# T14 ``context.Interface`` literal already includes "slack".
INTERFACE_SLACK = "slack"

# Block Kit ``action_id``s for the escalation buttons. The action listener matches this family; the
# trailing decision type drives :func:`decision_from_action`.
ACTION_APPROVE = "opendevops:escalation:approve"
ACTION_EDIT = "opendevops:escalation:edit"
ACTION_REJECT = "opendevops:escalation:reject"
_ACTION_PREFIX = "opendevops:escalation:"

# The edit modal's callback id + the input block/action ids the submission handler reads.
VIEW_EDIT_CALLBACK_ID = "opendevops:escalation_edit"
EDIT_INPUT_BLOCK = "argv_block"
EDIT_INPUT_ACTION = "argv_input"


# --------------------------------------------------------------------------------------
# Pure, deterministic helpers (tests call these directly)
# --------------------------------------------------------------------------------------


def slack_thread_id(channel: str, thread_ts: str) -> str:
    """The deterministic agent thread id for a Slack thread: ``uuid5(NS_SLACK, "chan:ts")``.

    Deterministic so a reply in the same Slack thread maps to the same agent thread (and thus the
    same open run chain, resumable on escalation).
    """
    return str(uuid.uuid5(NS_SLACK, f"{channel}:{thread_ts}"))


def resolve_principal(slack_user_id: str, cfg: AppConfig) -> Principal | None:
    """Map a Slack user id to its configured :class:`Principal`, or ``None`` if unmapped.

    FAIL CLOSED: an unknown user resolves to ``None`` and the caller REFUSES to run (posts a "not
    authorized" message) — never a default principal, never an unauthenticated run.
    """
    return cfg.principals.get(slack_user_id)


def encode_action_value(thread_id: str, tool_call_id: str) -> str:
    """Encode the agent ``thread_id`` + ``tool_call_id`` into a Block Kit button ``value`` (JSON).

    The action handler decodes this to route a click to the right run chain: ``thread_id`` selects
    the suspended run to resume; ``tool_call_id`` correlates the click to the specific escalation.
    """
    return json.dumps({"thread_id": thread_id, "tool_call_id": tool_call_id})


def decode_action_value(value: str) -> dict[str, str]:
    """Decode a button ``value`` back to ``{"thread_id", "tool_call_id"}`` (``{}`` if malformed)."""
    try:
        data = json.loads(value)
    except (ValueError, TypeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): str(v) for k, v in data.items()}


def decision_from_action(
    action_id: str, value: str, edited_argv: list[str] | None = None
) -> dict[str, Any]:
    """Map a Block Kit button click to the resume decision ``resume_interrupt`` expects.

    Returns the deepagents-shaped decision ``{"type": "approve"|"edit"|"reject", ...}``:
    ``approve`` → ``{"type": "approve"}``; ``edit`` → ``{"type": "edit", "args": {"argv": [...]}}``
    (from the modal-collected ``edited_argv``); ``reject`` → ``{"type": "reject", "message": ...}``.
    An unrecognised ``action_id`` fails closed to a reject.
    """
    kind = action_id[len(_ACTION_PREFIX) :] if action_id.startswith(_ACTION_PREFIX) else action_id
    if kind == "approve":
        return {"type": "approve"}
    if kind == "edit":
        return {"type": "edit", "args": {"argv": list(edited_argv or [])}}
    return {"type": "reject", "message": "rejected via Slack"}


def _escalation_argv(escalation: Escalation) -> list[str]:
    """The escalated command's argv from the interrupt payload (``[]`` if absent/malformed)."""
    requests = escalation.payload.get("action_requests") or []
    if requests and isinstance(requests[0], dict):
        args = requests[0].get("args")
        if isinstance(args, dict) and isinstance(args.get("argv"), list):
            return [str(a) for a in args["argv"]]
    return []


def _escalation_review(escalation: Escalation) -> tuple[str, str]:
    """``(rule_id, reason)`` from the interrupt payload's first review config."""
    reviews = escalation.payload.get("review_configs") or []
    if reviews and isinstance(reviews[0], dict):
        return str(reviews[0].get("rule_id", "?")), str(reviews[0].get("reason", ""))
    return "?", ""


def _escalation_tool_call_id(escalation: Escalation) -> str:
    """A stable per-escalation correlation id for the buttons.

    The P2 interrupt payload (``policy.middleware``) does not carry the ``tool_call_id`` in its
    ``action_requests`` entry, so we honour one if a future payload adds it and otherwise fall back
    to the escalation's ``run_id`` — a stable id unique to this run/escalation, which is all the
    button needs (resume is routed by ``thread_id``; the correlation id is belt-and-suspenders).
    """
    requests = escalation.payload.get("action_requests") or []
    if requests and isinstance(requests[0], dict):
        tcid = requests[0].get("tool_call_id") or requests[0].get("id")
        if tcid:
            return str(tcid)
    return escalation.run_id


# --------------------------------------------------------------------------------------
# Block Kit builders (pure — return lists of block dicts)
# --------------------------------------------------------------------------------------


def render_escalation_blocks(escalation: Escalation) -> list[dict[str, Any]]:
    """A red-ish approval card: argv + rule + reason + approve / edit / reject buttons.

    Each button's ``value`` carries the agent ``thread_id`` + ``tool_call_id`` (via
    :func:`encode_action_value`) so the action handler resumes the right run.
    """
    argv, (rule, reason) = _escalation_argv(escalation), _escalation_review(escalation)
    value = encode_action_value(escalation.thread_id, _escalation_tool_call_id(escalation))
    command = " ".join(argv) if argv else "(no command)"
    body = f"*Command:* `{command}`\n*Rule:* `{rule}`"
    if reason:
        body += f"\n*Reason:* {reason}"
    return [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": ":warning: Approval required", "emoji": True},
        },
        {"type": "section", "text": {"type": "mrkdwn", "text": body}},
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Approve"},
                    "style": "primary",
                    "action_id": ACTION_APPROVE,
                    "value": value,
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Edit"},
                    "action_id": ACTION_EDIT,
                    "value": value,
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Reject"},
                    "style": "danger",
                    "action_id": ACTION_REJECT,
                    "value": value,
                },
            ],
        },
    ]


def render_final_blocks(text: str) -> list[dict[str, Any]]:
    """Render an assistant answer (a streamed chunk or a run's final text) as a section block."""
    return [{"type": "section", "text": {"type": "mrkdwn", "text": text or "_(no output)_"}}]


def render_denied(reason: str) -> list[dict[str, Any]]:
    """A denial / refusal card (unauthorized user, policy denial) — reason in a section block."""
    return [{"type": "section", "text": {"type": "mrkdwn", "text": f":no_entry: {reason}"}}]


def render_edit_modal(value: str, argv: list[str]) -> dict[str, Any]:
    """A modal collecting an edited argv; ``value`` rides in ``private_metadata`` for the resume."""
    return {
        "type": "modal",
        "callback_id": VIEW_EDIT_CALLBACK_ID,
        "private_metadata": value,
        "title": {"type": "plain_text", "text": "Edit command"},
        "submit": {"type": "plain_text", "text": "Run"},
        "close": {"type": "plain_text", "text": "Cancel"},
        "blocks": [
            {
                "type": "input",
                "block_id": EDIT_INPUT_BLOCK,
                "label": {"type": "plain_text", "text": "Edited command (argv)"},
                "element": {
                    "type": "plain_text_input",
                    "action_id": EDIT_INPUT_ACTION,
                    "initial_value": " ".join(argv),
                },
            }
        ],
    }


def edited_argv_from_view(view: dict[str, Any]) -> list[str]:
    """The whitespace-split edited argv from a submitted edit-modal view (``[]`` if empty)."""
    state = view.get("state") or {}
    values = state.get("values") or {}
    block = values.get(EDIT_INPUT_BLOCK) or {}
    element = block.get(EDIT_INPUT_ACTION) or {}
    raw = element.get("value") or ""
    return str(raw).split()


# --------------------------------------------------------------------------------------
# Thread -> Slack destination registry (shared by the adapter and the run-complete seam)
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class SlackDestination:
    """Where to post updates for an agent thread: a Slack ``channel`` + root ``thread_ts``."""

    channel: str
    thread_ts: str


class SlackThreadRegistry:
    """In-memory agent-thread-id -> :class:`SlackDestination` map the adapter populates.

    Single-process, single-worker (like ``webapp._TTLSet``): the Socket-Mode adapter and, in the
    same process, the webhook app's run-complete notifier share one instance so a completed run can
    be posted back to its originating Slack thread.
    """

    def __init__(self) -> None:
        self._by_thread: dict[str, SlackDestination] = {}

    def register(self, thread_id: str, channel: str, thread_ts: str) -> None:
        self._by_thread[thread_id] = SlackDestination(channel=channel, thread_ts=thread_ts)

    def destination_for(self, thread_id: str) -> SlackDestination | None:
        return self._by_thread.get(thread_id)


# --------------------------------------------------------------------------------------
# The run-complete -> Slack notifier seam (server-mode complement)
# --------------------------------------------------------------------------------------


@runtime_checkable
class SlackNotifier(Protocol):
    """Posts a completed run's final answer back to its Slack thread (webapp ``run-complete`` seam).

    ``destination_for`` lets the route gate on registration (post only for a thread that originated
    in Slack); ``post_final`` posts the text. Kept minimal so a test can drive it with a stub.
    """

    def destination_for(self, thread_id: str) -> Any | None:
        """The registered Slack destination for ``thread_id``, or ``None`` if none is registered."""
        ...

    async def post_final(self, thread_id: str, text: str) -> None:
        """Post ``text`` as the final answer to ``thread_id``'s Slack thread."""
        ...


class SlackClient(Protocol):
    """The ``slack_sdk`` ``AsyncWebClient`` slice the adapter uses (so tests pass an AsyncMock)."""

    async def chat_postMessage(self, **kwargs: Any) -> Any: ...  # noqa: N802 - slack_sdk name

    async def views_open(self, **kwargs: Any) -> Any: ...


class SlackThreadNotifier:
    """Concrete :class:`SlackNotifier`: post a final answer via a Slack client + the registry."""

    def __init__(self, client: SlackClient, registry: SlackThreadRegistry) -> None:
        self._client = client
        self._registry = registry

    def destination_for(self, thread_id: str) -> SlackDestination | None:
        return self._registry.destination_for(thread_id)

    async def post_final(self, thread_id: str, text: str) -> None:
        dest = self._registry.destination_for(thread_id)
        if dest is None:
            return
        await self._client.chat_postMessage(
            channel=dest.channel,
            thread_ts=dest.thread_ts,
            text=text or "(run completed)",
            blocks=render_final_blocks(text),
        )


# --------------------------------------------------------------------------------------
# The adapter: gateway-driving logic (directly unit-tested)
# --------------------------------------------------------------------------------------


class SlackAdapter:
    """Drives the gateway for Slack messages + escalation button clicks (stream-in-process).

    All methods are directly awaitable in tests with an ``AsyncMock`` gateway and a stub
    :class:`SlackClient`; the Bolt listener shims (:func:`build_bolt_app`) merely ``ack`` and
    schedule these in a background task.
    """

    def __init__(
        self,
        cfg: AppConfig,
        gateway: AgentGateway,
        client: SlackClient,
        *,
        registry: SlackThreadRegistry | None = None,
    ) -> None:
        self._cfg = cfg
        self._gateway = gateway
        self._client = client
        self.registry = registry if registry is not None else SlackThreadRegistry()
        self._environment = cfg.slack.default_channel_environment

    # -- message handling -----------------------------------------------------------------

    async def handle_message(
        self, *, channel: str, thread_ts: str, user: str, text: str
    ) -> None:
        """Resolve the principal (fail closed), register the thread, drive a streamed turn.

        An UNKNOWN Slack user is refused BEFORE any gateway call: post "not authorized" and return
        (never a default principal, never an unauthenticated run).
        """
        principal = resolve_principal(user, self._cfg)
        thread_id = slack_thread_id(channel, thread_ts)
        if principal is None:
            await self._post_blocks(
                channel, thread_ts, render_denied(f"<@{user}> is not authorized to run the agent.")
            )
            return

        self.registry.register(thread_id, channel, thread_ts)
        # Placeholder so the user sees an immediate ack (Bolt auto-acks the event within 3s; the
        # run proceeds in the background from the shim).
        placeholder = render_final_blocks(":hourglass_flowing_sand: on it…")
        await self._post_blocks(channel, thread_ts, placeholder)
        stream = self._gateway.stream(
            thread_id,
            text,
            profile=principal.profile,
            principal=principal.principal,
            interface=INTERFACE_SLACK,
            environment=self._environment,
        )
        await self._consume_stream(stream, channel, thread_ts)

    async def _consume_stream(
        self, stream: AsyncIterator[RunEvent], channel: str, thread_ts: str
    ) -> RunResult | None:
        """Render every event of one streamed turn to the thread; return its terminal RunResult.

        Assistant text posts as a section block, an escalation posts the approve/edit/reject card
        (and the run stays suspended until a button is clicked), a policy denial posts a denial
        card. The final answer is the last assistant text — already posted — so nothing extra is
        posted on a clean finish (mirrors the CLI, which never re-prints ``final_text``).
        """
        result: RunResult | None = None
        async for event in stream:
            if isinstance(event, RunEnd):
                result = event.result
            elif isinstance(event, EscalationEvent):
                await self._post_blocks(
                    channel, thread_ts, render_escalation_blocks(event.escalation)
                )
            elif isinstance(event, AssistantText):
                if event.text.strip():
                    await self._post_blocks(channel, thread_ts, render_final_blocks(event.text))
            elif isinstance(event, ToolResult) and event.denied:
                rule = f" [{event.rule_id}]" if event.rule_id else ""
                await self._post_blocks(
                    channel, thread_ts, render_denied(f"denied by policy{rule}")
                )
        return result

    # -- escalation button handling -------------------------------------------------------

    async def handle_action(
        self,
        *,
        action_id: str,
        value: str,
        user: str,
        channel: str,
        thread_ts: str,
        trigger_id: str | None = None,
    ) -> None:
        """Resume the suspended run for an approve / reject click (edit opens a modal instead).

        The CLICKING user is resolved to an approver principal — fail closed if unknown (post "not
        authorized", never resume). ``resume_interrupt`` injects the approver, so the audit
        ``resolution`` event records the RESOLVED principal, not the raw Slack id.

        Two fail-closed gates precede any resume:

        * (M-2) a malformed/undecodable ``value`` yields an empty ``thread_id`` — we cannot identify
          the suspended run, so refuse rather than call ``resume_interrupt("", …)`` (which the
          gateway raises on, unhandled in the fire-and-forget task).
        * (M-1) the click is BOUND to the thread the card was rendered in: the escalation card is
          posted IN the run's Slack thread, so a legitimate in-thread click's own
          ``(channel, thread_ts)`` hashes to the same agent ``thread_id`` the button carries. A
          ``value`` whose ``thread_id`` was forged/derived for a DIFFERENT thread (one the clicker
          may not even see) will not match — refuse without resuming. This binds every
          approve/edit/reject to its own thread, closing the forged-value gap.
        """
        approver = resolve_principal(user, self._cfg)
        payload = decode_action_value(value)
        thread_id = payload.get("thread_id", "")
        if approver is None:
            await self._post_blocks(
                channel, thread_ts, render_denied(f"<@{user}> is not authorized to approve.")
            )
            return

        if not thread_id:  # M-2: undecodable / empty button value — cannot route a resume.
            await self._post_blocks(
                channel, thread_ts, render_denied("could not identify the escalation to resolve.")
            )
            return

        expected = slack_thread_id(channel, thread_ts)  # M-1: bind the click to its own thread.
        if thread_id != expected:
            logger.warning(
                "escalation click thread_id %r != click thread %r (user %r); refusing",
                thread_id,
                expected,
                user,
            )
            await self._post_blocks(
                channel, thread_ts, render_denied("this approval is not valid for this thread.")
            )
            return

        if action_id == ACTION_EDIT:
            await self._open_edit_modal(trigger_id, value)
            return

        decision = decision_from_action(action_id, value)
        result = await self._gateway.resume_interrupt(
            thread_id, [decision], approver=approver.principal
        )
        await self._render_result(result, channel, thread_ts)

    async def handle_view_submission(self, *, view: dict[str, Any], user: str) -> None:
        """Resume with the modal-collected edited argv (the edit path's second half).

        The destination is recovered from the registry via the ``thread_id`` carried in the view's
        ``private_metadata`` (a modal submission has no channel of its own). That registry lookup IS
        this path's authz binding (M-1): a modal has no click channel to check against, so the
        submission is bound by requiring its ``thread_id`` to resolve to a REGISTERED Slack
        destination — an empty (M-2) or unregistered/forged ``thread_id`` fails closed here (logged,
        no ``resume_interrupt``, no gateway call). The ``thread_id`` itself was already thread-bound
        when the edit button that opened this modal passed :meth:`handle_action`'s M-1 gate.
        """
        approver = resolve_principal(user, self._cfg)
        payload = decode_action_value(view.get("private_metadata", ""))
        thread_id = payload.get("thread_id", "")
        dest = self.registry.destination_for(thread_id)
        if dest is None:  # M-1/M-2: empty or unregistered/forged thread_id — refuse, no resume.
            logger.warning("edit submission for unregistered thread %r; ignoring", thread_id)
            return
        if approver is None:
            await self._post_blocks(
                dest.channel,
                dest.thread_ts,
                render_denied(f"<@{user}> is not authorized to approve."),
            )
            return
        decision = decision_from_action(ACTION_EDIT, "", edited_argv=edited_argv_from_view(view))
        result = await self._gateway.resume_interrupt(
            thread_id, [decision], approver=approver.principal
        )
        await self._render_result(result, dest.channel, dest.thread_ts)

    async def _render_result(
        self, result: RunResult, channel: str, thread_ts: str
    ) -> None:
        """Render a resumed run's terminal RunResult: a re-escalation card or the final answer."""
        if result.interrupted is not None:
            await self._post_blocks(
                channel, thread_ts, render_escalation_blocks(result.interrupted)
            )
        elif result.final_text:
            await self._post_blocks(channel, thread_ts, render_final_blocks(result.final_text))

    async def _open_edit_modal(self, trigger_id: str | None, value: str) -> None:
        """Open the edit modal for the escalated command (the collected argv resumes later)."""
        if not trigger_id:
            logger.warning("edit action without a trigger_id; cannot open modal")
            return
        await self._client.views_open(trigger_id=trigger_id, view=render_edit_modal(value, []))

    # -- slack post helper ----------------------------------------------------------------

    async def _post_blocks(
        self, channel: str, thread_ts: str, blocks: list[dict[str, Any]]
    ) -> None:
        """Post ``blocks`` into the Slack thread (a failed post is logged, never raised)."""
        text = _fallback_text(blocks)
        try:
            await self._client.chat_postMessage(
                channel=channel, thread_ts=thread_ts, blocks=blocks, text=text
            )
        except Exception:  # noqa: BLE001 - a Slack API hiccup must not crash the run/loop
            logger.exception("failed to post to Slack channel %s thread %s", channel, thread_ts)


def _fallback_text(blocks: list[dict[str, Any]]) -> str:
    """A plain-text fallback (for notifications / a11y) from the first text-bearing block."""
    for block in blocks:
        text = block.get("text")
        if isinstance(text, dict) and text.get("text"):
            return str(text["text"])
    return "opendevops"


# --------------------------------------------------------------------------------------
# Bolt wiring (thin shims) + startup (lazy slack-bolt import; needs a live websocket)
# --------------------------------------------------------------------------------------


def _require_env(env_name: str | None, what: str) -> str:
    """Read the *value* of the env var named ``env_name``; raise a clear startup error if unset.

    Mirrors the fail-closed, opt-in posture of ``ServerGateway`` / the webhook app: config holds the
    env-var NAME, the value is read at startup, and a missing name / unset var is a loud refusal to
    boot — never a silent no-op.
    """
    if not env_name:
        raise RuntimeError(
            f"the Slack adapter needs {what}: set slack.{what} in config to the NAME of the env "
            "var holding it (the adapter is opt-in and reads the value at startup)"
        )
    value = os.environ.get(env_name)
    if not value:
        raise RuntimeError(
            f"the Slack adapter's {what} env var {env_name!r} is unset/empty (fail-closed)"
        )
    return value


def build_bolt_app(adapter: SlackAdapter, *, bot_token: str) -> Any:
    """Build the ``AsyncApp`` and register the thin listener shims that delegate to ``adapter``.

    slack-bolt is imported here (not at module import) because its async surface pulls in
    ``aiohttp``; the shims ``ack`` fast and run the real work in a background task so the event is
    acked within Slack's 3s window while the run streams in the background.
    """
    from slack_bolt.async_app import AsyncApp  # lazy: async surface needs aiohttp

    app = AsyncApp(token=bot_token)
    background: set[asyncio.Task[Any]] = set()

    def _spawn(coro: Any) -> None:
        task = asyncio.create_task(coro)
        background.add(task)
        task.add_done_callback(background.discard)

    @app.event("app_mention")
    async def _on_mention(event: dict[str, Any]) -> None:  # pragma: no cover - thin shim
        channel = event.get("channel", "")
        thread_ts = event.get("thread_ts") or event.get("ts", "")
        _spawn(
            adapter.handle_message(
                channel=channel,
                thread_ts=thread_ts,
                user=event.get("user", ""),
                text=event.get("text", ""),
            )
        )

    @app.event("message")
    async def _on_message(event: dict[str, Any]) -> None:  # pragma: no cover - thin shim
        # Only follow up on replies in threads we drive; ignore our own / non-thread chatter.
        if event.get("bot_id") or event.get("subtype"):
            return
        thread_ts = event.get("thread_ts")
        if not thread_ts:
            return
        channel = event.get("channel", "")
        if adapter.registry.destination_for(slack_thread_id(channel, thread_ts)) is None:
            return
        _spawn(
            adapter.handle_message(
                channel=channel,
                thread_ts=thread_ts,
                user=event.get("user", ""),
                text=event.get("text", ""),
            )
        )

    @app.action(_action_matcher())
    async def _on_action(  # pragma: no cover - thin shim
        ack: Any, body: dict[str, Any], action: dict[str, Any]
    ) -> None:
        await ack()
        container = body.get("container") or {}
        channel = (body.get("channel") or {}).get("id", "")
        thread_ts = container.get("thread_ts") or (body.get("message") or {}).get("ts", "")
        _spawn(
            adapter.handle_action(
                action_id=action.get("action_id", ""),
                value=action.get("value", ""),
                user=(body.get("user") or {}).get("id", ""),
                channel=channel,
                thread_ts=thread_ts,
                trigger_id=body.get("trigger_id"),
            )
        )

    @app.view(VIEW_EDIT_CALLBACK_ID)
    async def _on_view(  # pragma: no cover - thin shim
        ack: Any, body: dict[str, Any], view: dict[str, Any]
    ) -> None:
        await ack()
        _spawn(
            adapter.handle_view_submission(view=view, user=(body.get("user") or {}).get("id", ""))
        )

    return app


def _action_matcher() -> Any:
    """A regex matching the escalation button ``action_id`` family (approve|edit|reject)."""
    import re

    return re.compile(r"^opendevops:escalation:(approve|edit|reject)$")


async def start(cfg: AppConfig) -> None:  # pragma: no cover - needs a live websocket
    """Start the Slack Socket-Mode adapter over a :class:`LocalGateway` (blocks forever).

    Reads the bot + app tokens from the env vars NAMED in ``cfg.slack`` (clear error if unset),
    builds the adapter + Bolt app, and runs the ``AsyncSocketModeHandler``. Not exercised in CI
    (Socket Mode needs a live websocket); the logic it wires is covered by the adapter unit tests.
    """
    # Validate the opt-in config BEFORE importing the aiohttp-backed transport, so a misconfigured
    # adapter fails with the clear config error rather than an ImportError.
    bot_token = _require_env(cfg.slack.bot_token_env, "bot_token_env")
    app_token = _require_env(cfg.slack.app_token_env, "app_token_env")

    from slack_bolt.adapter.socket_mode.async_handler import AsyncSocketModeHandler
    from slack_sdk.web.async_client import AsyncWebClient

    from opendevops.gateway import LocalGateway

    gateway = LocalGateway(cfg)
    # AsyncWebClient structurally satisfies SlackClient (same methods, extra typed kwargs); cast so
    # mypy accepts the wider concrete signature against our narrow Protocol.
    client = cast("SlackClient", AsyncWebClient(token=bot_token))
    adapter = SlackAdapter(cfg, gateway, client)
    app = build_bolt_app(adapter, bot_token=bot_token)
    handler = AsyncSocketModeHandler(app, app_token)
    logger.info("starting Slack Socket-Mode adapter (interface=%s)", INTERFACE_SLACK)
    await handler.start_async()
