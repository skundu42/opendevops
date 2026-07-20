"""Scenario 7: a tool-call loop hits the invoke-time recursion_limit -> GraphRecursionError.

The gateway is responsible for catching this and turning it into a clean run summary; here
we only pin that the limit is enforced (and that the invoke-time override beats the deepagents
default of 9_999).
"""

from __future__ import annotations

import itertools
from typing import Any

import pytest
from langchain_core.messages import AIMessage
from langgraph.errors import GraphRecursionError

from .helpers import ai_tool_call, invoke_config, make_context, make_fake_model, start_run


def _infinite_tool_calls() -> Any:
    """A generator that never stops asking to run a tool (distinct ids avoid the exec cache)."""
    for i in itertools.count():
        yield ai_tool_call(
            "run_command",
            {"argv": ["kubectl", "get", "pods", "--namespace", "default"]},
            f"loop-{i}",
        )


async def test_recursion_limit_raises(built_agent: Any) -> None:
    fake = make_fake_model(_infinite_tool_calls())
    graph, audit, _ = built_agent(fake)
    ctx = make_context("run-recursion")
    start_run(audit, ctx)

    with pytest.raises(GraphRecursionError):
        await graph.ainvoke(
            {"messages": [("user", "loop forever")]},
            config=invoke_config(ctx.run_id, recursion_limit=3),
            context=ctx,
        )


async def test_recursion_limit_override_is_respected(built_agent: Any) -> None:
    """A generous invoke-time recursion_limit lets a short scripted run complete normally."""
    fake = make_fake_model(
        [
            ai_tool_call(
                "run_command",
                {"argv": ["kubectl", "get", "pods", "--namespace", "default"]},
                "call-1",
            ),
            AIMessage(content="finished"),
        ]
    )
    graph, audit, _ = built_agent(fake)
    ctx = make_context("run-recursion-ok")
    start_run(audit, ctx)

    out = await graph.ainvoke(
        {"messages": [("user", "one step")]},
        config=invoke_config(ctx.run_id, recursion_limit=25),
        context=ctx,
    )
    assert any(
        isinstance(m, AIMessage) and m.content == "finished" for m in out["messages"]
    )
