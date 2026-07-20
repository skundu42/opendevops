"""Shared stream-translation helpers: graph messages -> :class:`RunEvent` dataclasses (T16).

Extracted from :mod:`opendevops.gateway.local` so :class:`LocalGateway` and
:class:`~opendevops.gateway.server.ServerGateway` render byte-identical events from the same
logic instead of two drifting copies. The only difference between the two transports is the *shape*
of a message in an ``updates`` super-step:

* in-process (:class:`LocalGateway`) — a real ``AIMessage`` / ``ToolMessage`` object;
* over the SDK (:class:`ServerGateway`) — the message's ``.model_dump()`` **dict**, because the
  LangGraph Server JSON-encodes every state value with a ``model_dump()`` default (probed against
  ``langgraph_api.serde.default`` + a live in-memory ``langgraph dev`` 0.11.1 server: an ``updates``
  frame is ``{node: {"messages": [ {"type": "ai", "content", "tool_calls", ...}, ... ]}}`` and a
  ``ToolMessage`` dumps to ``{"type": "tool", "content", "tool_call_id", "status", ...}``).

:func:`_coerce_message` bridges the two: an object passes through unchanged (so ``LocalGateway``'s
behavior is identical) and a wire dict is rehydrated with ``convert_to_messages`` (verified to
round-trip a ``model_dump()`` dict back to the same ``AIMessage`` / ``ToolMessage``, tool-calls and
``status`` intact). Everything downstream then operates on real message objects.
"""

from __future__ import annotations

import re
from typing import Any

from langchain_core.messages import AIMessage, BaseMessage, ToolMessage, convert_to_messages

from opendevops.gateway.base import (
    AssistantText,
    RunEvent,
    ToolCall,
    ToolResult,
)

# A tool result whose content starts with this marker is a policy denial (see
# ``policy.middleware._deny_message`` / ``_fail_closed``): ``Denied by policy [<rule_id>]: ...``.
_DENY_PREFIX = "Denied by policy ["
_DENY_RULE_RE = re.compile(r"^Denied by policy \[([^\]]+)\]")

# Tool-result excerpt cap (mirrors the audit excerpt budget; keeps the stream light).
_EXCERPT_CHARS = 2000


def translate_updates(chunk: dict[str, Any]) -> list[RunEvent]:
    """Translate one ``updates``-mode super-step into zero or more :class:`RunEvent`\\ s.

    Only the ``model`` node (assistant text / tool calls) and the ``tools`` node (tool results)
    carry user-facing content; every other node (budget/limit middleware) is skipped. Messages may
    arrive as objects (local) or wire dicts (server) — :func:`_coerce_message` normalizes both.
    """
    events: list[RunEvent] = []
    for _node, payload in chunk.items():
        if not isinstance(payload, dict):
            continue
        for message in payload.get("messages", []) or []:
            events.extend(translate_message(message))
    return events


def translate_message(message: Any) -> list[RunEvent]:
    """Map one graph message (object or wire dict) to its stream events.

    Emits an :class:`AssistantText` for non-empty assistant text, a :class:`ToolCall` per tool
    call, or a :class:`ToolResult` for a tool message. A message that is neither an ``AIMessage``
    nor a ``ToolMessage`` (or an unrehydratable dict) yields nothing.
    """
    msg = _coerce_message(message)
    events: list[RunEvent] = []
    if isinstance(msg, AIMessage):
        text = message_text(msg)
        if text.strip():
            events.append(AssistantText(text=text))
        for call in msg.tool_calls or []:
            args = call.get("args") or {}
            argv = args.get("argv") if isinstance(args.get("argv"), list) else None
            events.append(ToolCall(name=call.get("name", "?"), argv=argv))
    elif isinstance(msg, ToolMessage):
        events.append(translate_tool_result(msg))
    return events


def translate_tool_result(message: ToolMessage) -> ToolResult:
    """Build a :class:`ToolResult`, flagging + extracting the rule id for a policy denial."""
    content = message.content if isinstance(message.content, str) else str(message.content)
    denied = content.startswith(_DENY_PREFIX)
    rule_id: str | None = None
    if denied:
        match = _DENY_RULE_RE.match(content)
        rule_id = match.group(1) if match else None
    excerpt = content[:_EXCERPT_CHARS]
    return ToolResult(excerpt=excerpt, denied=denied, rule_id=rule_id)


def message_text(message: AIMessage) -> str:
    """Plain assistant text of an ``AIMessage`` (joins text blocks; ``""`` for a tool-only turn)."""
    content = message.content
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict) and block.get("type") == "text":
                parts.append(str(block.get("text", "")))
        return "".join(parts)
    return ""


def final_text(final_state: dict[str, Any]) -> str:
    """The last assistant text in the final state (empty if the turn produced none).

    ``final_state`` messages may be objects (local ``ainvoke``) or wire dicts (the SDK ``wait`` /
    last ``values`` frame); :func:`_coerce_message` normalizes both.
    """
    for message in reversed(final_state.get("messages") or []):
        msg = _coerce_message(message)
        if isinstance(msg, AIMessage):
            text = message_text(msg)
            if text.strip():
                return text
    return ""


def extract_interrupt(final_state: Any) -> dict[str, Any] | None:
    """The escalation payload if the segment suspended, else ``None``.

    On an ``interrupt()`` suspend, ``ainvoke``'s result dict (and ``astream``'s final ``values``
    frame) carries ``__interrupt__ = [Interrupt(value=<payload>, id=...)]`` (verified against
    langgraph 1.2.9); over the SDK the same key carries a list of **dicts**
    ``[{"value": <payload>, "id": ...}]`` (probed against a live ``langgraph dev`` 0.11.1 stream and
    ``runs.wait`` return). We surface the first interrupt's ``value`` — the deepagents-shaped review
    envelope the middleware built — reading it as an attribute (object) or a key (dict).
    """
    if not isinstance(final_state, dict):
        return None
    interrupts = final_state.get("__interrupt__")
    if not interrupts:
        return None
    first = interrupts[0]
    value = first.get("value") if isinstance(first, dict) else getattr(first, "value", None)
    if isinstance(value, dict):
        return value
    return {"value": value}


def _coerce_message(message: Any) -> BaseMessage | None:
    """Return ``message`` as a langchain message object (pass-through, or rehydrate a wire dict).

    An in-process object is returned unchanged (``LocalGateway`` path — identical behavior). A
    ``.model_dump()`` wire dict (``ServerGateway`` path) is rehydrated with ``convert_to_messages``;
    an unexpected/unrehydratable shape yields ``None`` (skipped, never raised into the stream).
    """
    if isinstance(message, BaseMessage):
        return message
    if isinstance(message, dict):
        try:
            return convert_to_messages([message])[0]
        except Exception:  # noqa: BLE001 - a malformed wire message is skipped, never fatal
            return None
    return None
