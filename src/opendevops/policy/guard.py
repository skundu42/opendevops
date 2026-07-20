"""``SingleToolCallMiddleware`` — collapse a parallel tool-call turn to one call (T13).

Interrupt-replay safety, third layer
------------------------------------
The escalate path (T13) calls ``langgraph.types.interrupt()`` *inside*
``PolicyMiddleware.awrap_tool_call``. LangGraph re-executes the ``tools`` node from its start
when a run resumes after an interrupt. If a single model turn issued *parallel* tool calls
``[apply (allow), delete-pvc (escalate)]``, the apply would execute, the delete would interrupt,
and — absent a guard — the apply could **execute a second time** across the replay window.

Three independent guards defend that window; this middleware is the third:

1. ``model_kwargs={"tool_choice": {"disable_parallel_tool_use": True}}`` on the Anthropic model
   (``models/registry.py``) — the model is *asked* to emit at most one tool call. Verified
   emergent behavior of the pinned dict-merge precedence, **not** a guaranteed contract.
2. this middleware — if the model regresses and emits >1 tool call anyway, only the first
   survives, so the ``tools`` node never contains a sibling to replay in the first place.
3. the ``tool_results_cache`` in ``PolicyMiddleware`` — even if a sibling did reach the node,
   its ``tool_call_id`` is served from cache on the resume re-execution rather than re-run.

This middleware makes layer 1 (an undocumented model default) non-load-bearing: with the guard
live, correctness holds by *construction* of the tools node regardless of what the model emits.

Mechanism
---------
``awrap_model_call`` runs the model, then inspects the returned ``AIMessage``. When it carries
more than one ``tool_call`` we keep only the **first** and append a bracketed note to the
message content so the model learns why its other calls vanished and re-issues them one at a
time on the next turn. All other message fields (``usage_metadata``, ``id``, ``response_metadata``)
are preserved via ``model_copy`` so budget accounting and provenance are unaffected. For an
Anthropic list-content message the dropped calls' ``tool_use`` blocks are also stripped, so the
trimmed message never re-serializes to the API with a ``tool_use`` that has no matching result.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from langchain.agents.middleware import AgentMiddleware
from langchain.agents.middleware.types import ModelRequest, ModelResponse
from langchain_core.messages import AIMessage

# The note appended to the surviving message so the model self-corrects (reissues sequentially).
_NOTE_TEMPLATE = (
    "[parallel tool calls are disabled: {n} additional call(s) dropped — "
    "reissue them one at a time]"
)


class SingleToolCallMiddleware(AgentMiddleware[Any, Any, Any]):
    """Keep only the first tool call of any AIMessage the model returns (parallel-call guard)."""

    async def awrap_model_call(
        self,
        request: ModelRequest[Any],
        handler: Callable[[ModelRequest[Any]], Awaitable[ModelResponse[Any]]],
    ) -> ModelResponse[Any]:
        response = await handler(request)
        trimmed = [_keep_first_tool_call(m) for m in response.result]
        return ModelResponse(result=trimmed, structured_response=response.structured_response)


def _keep_first_tool_call(message: Any) -> Any:
    """Return ``message`` with at most one tool call; non-AIMessage / single-call pass through."""
    if not isinstance(message, AIMessage):
        return message
    tool_calls = list(message.tool_calls or [])
    if len(tool_calls) <= 1:
        return message

    kept = tool_calls[0]
    kept_id = kept.get("id")
    dropped = len(tool_calls) - 1
    note = _NOTE_TEMPLATE.format(n=dropped)

    return message.model_copy(
        update={
            "content": _append_note(message.content, note, kept_id),
            "tool_calls": [kept],
        }
    )


def _append_note(content: Any, note: str, kept_id: Any) -> Any:
    """Append ``note`` to the message content, dropping non-kept ``tool_use`` blocks in a list.

    * string content (the common case, and every fake-model test): ``"<text>\\n<note>"``.
    * list content (Anthropic block form): keep every block except ``tool_use`` blocks whose id
      is not ``kept_id`` (so a dropped call leaves no orphan ``tool_use`` to re-serialize), then
      append the note as a trailing text block.
    """
    if isinstance(content, list):
        pruned = [
            block
            for block in content
            if not (
                isinstance(block, dict)
                and block.get("type") == "tool_use"
                and block.get("id") != kept_id
            )
        ]
        pruned.append({"type": "text", "text": note})
        return pruned
    text = content if isinstance(content, str) else str(content)
    return f"{text}\n{note}".strip()
