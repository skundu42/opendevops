"""Unit tests for ``SingleToolCallMiddleware`` — the parallel-tool-call guard (T13).

Drives ``awrap_model_call`` directly with a fake handler returning a ``ModelResponse``; asserts
that a multi-tool-call AIMessage is collapsed to its first call (with a self-correct note and
provenance preserved) and that single-call / text-only turns pass through untouched.
"""

from __future__ import annotations

from typing import Any

from langchain.agents.middleware.types import ModelResponse
from langchain_core.messages import AIMessage

from opendevops.policy.guard import SingleToolCallMiddleware


def _handler_returning(*messages: Any) -> Any:
    async def _handler(_request: Any) -> ModelResponse[Any]:
        return ModelResponse(result=list(messages))

    return _handler


def _tc(name: str, call_id: str, args: dict[str, Any]) -> dict[str, Any]:
    return {"name": name, "args": args, "id": call_id, "type": "tool_call"}


async def test_two_tool_calls_collapse_to_first_with_note() -> None:
    mw = SingleToolCallMiddleware()
    msg = AIMessage(
        content="",
        tool_calls=[
            _tc("run_command", "c1", {"argv": ["kubectl", "get", "pods"]}),
            _tc("run_command", "c2", {"argv": ["kubectl", "delete", "pod", "x"]}),
        ],
        usage_metadata={"input_tokens": 5, "output_tokens": 2, "total_tokens": 7},  # type: ignore[arg-type]
    )

    resp = await mw.awrap_model_call(None, _handler_returning(msg))  # type: ignore[arg-type]

    out = resp.result[0]
    assert [c["id"] for c in out.tool_calls] == ["c1"]  # only the first survives
    assert "parallel tool calls are disabled" in out.content
    assert "1 additional call" in out.content
    # provenance/usage preserved so budget accounting is unaffected.
    assert out.usage_metadata == {"input_tokens": 5, "output_tokens": 2, "total_tokens": 7}


async def test_three_tool_calls_report_two_dropped() -> None:
    mw = SingleToolCallMiddleware()
    msg = AIMessage(
        content="here goes",
        tool_calls=[
            _tc("run_command", f"c{i}", {"argv": ["kubectl", "get", "x"]}) for i in range(3)
        ],
    )
    resp = await mw.awrap_model_call(None, _handler_returning(msg))  # type: ignore[arg-type]
    out = resp.result[0]
    assert [c["id"] for c in out.tool_calls] == ["c0"]
    assert "2 additional call(s)" in out.content
    assert out.content.startswith("here goes")


async def test_single_tool_call_is_unchanged() -> None:
    mw = SingleToolCallMiddleware()
    msg = AIMessage(content="", tool_calls=[_tc("run_command", "c1", {"argv": ["kubectl", "get"]})])
    resp = await mw.awrap_model_call(None, _handler_returning(msg))  # type: ignore[arg-type]
    assert resp.result[0] is msg  # passed through untouched


async def test_text_only_message_is_unchanged() -> None:
    mw = SingleToolCallMiddleware()
    msg = AIMessage(content="all healthy")
    resp = await mw.awrap_model_call(None, _handler_returning(msg))  # type: ignore[arg-type]
    assert resp.result[0] is msg


async def test_list_content_strips_dropped_tool_use_blocks() -> None:
    """An Anthropic list-content message drops the non-kept tool_use blocks (no orphan tool_use)."""
    mw = SingleToolCallMiddleware()
    msg = AIMessage(
        content=[
            {"type": "text", "text": "doing two things"},
            {"type": "tool_use", "id": "c1", "name": "run_command", "input": {}},
            {"type": "tool_use", "id": "c2", "name": "run_command", "input": {}},
        ],
        tool_calls=[
            _tc("run_command", "c1", {"argv": ["a"]}),
            _tc("run_command", "c2", {"argv": ["b"]}),
        ],
    )
    resp = await mw.awrap_model_call(None, _handler_returning(msg))  # type: ignore[arg-type]
    out = resp.result[0]
    assert [c["id"] for c in out.tool_calls] == ["c1"]
    tool_use_ids = [
        b["id"] for b in out.content if isinstance(b, dict) and b.get("type") == "tool_use"
    ]
    assert tool_use_ids == ["c1"]  # the c2 tool_use block was stripped
    assert any(
        isinstance(b, dict)
        and b.get("type") == "text"
        and "parallel tool calls" in b.get("text", "")
        for b in out.content
    )
