"""Scenario 1 (allow) + Scenario 2 (deny): a full model->tool->model turn through the real graph.

Each asserts on BOTH the returned state (the ToolMessage the model saw) and the audit chain the
``PolicyMiddleware`` wrote (which must ``verify()``).

Cross-file integration defect — RESOLVED
-----------------------------------------
Previously the tool executed and the model saw its ``exit_code:`` output, and the *decision*
audit event was written — but the *execution* audit event was NOT emitted in the real graph.
``PolicyMiddleware`` read the per-exec facts from a ``last_exec_meta`` ContextVar that
``run_command`` set; langchain runs the tool coroutine (``tool.ainvoke``) in a *copied*
context, so a ContextVar written inside the tool did not propagate back to the middleware frame
(parent->child works, so the ``current_decision`` gate is fine; child->parent does not). Fixed by
carrying the exec meta on the returned ToolMessage's ``additional_kwargs["exec_meta"]`` (the
return value crosses the boundary) — see task-8-report.md "Cross-file fix: exec-meta return
channel". ``test_allow_flow_emits_execution_event`` below now passes as a normal test.
"""

from __future__ import annotations

from typing import Any

from langchain_core.messages import ToolMessage

from .helpers import (
    ai_text,
    ai_tool_call,
    chain_ok,
    event_types,
    invoke_config,
    make_context,
    make_fake_model,
    read_events,
    start_run,
)


def _tool_messages(state: dict[str, Any]) -> list[ToolMessage]:
    return [m for m in state["messages"] if isinstance(m, ToolMessage)]


async def test_allow_flow_executes_and_audits_decision(built_agent: Any, cfg: Any) -> None:
    """A read-only kubectl call is allowed, executes, and lands an allow decision event."""
    fake = make_fake_model(
        [
            ai_tool_call(
                "run_command",
                {"argv": ["kubectl", "get", "pods", "--namespace", "default"]},
                "call-1",
            ),
            ai_text("No pods are running in the default namespace."),
        ]
    )
    graph, audit, _ = built_agent(fake)
    ctx = make_context("run-allow")
    start_run(audit, ctx)

    out = await graph.ainvoke(
        {"messages": [("user", "list pods in default")]},
        config=invoke_config(ctx.run_id),
        context=ctx,
    )

    # The tool actually executed: the ToolMessage the model saw is the run_command output,
    # prefixed with the exit code (kubectl may be absent / unable to connect in CI — 127 or a
    # connection error is fine; what matters is that an execution happened).
    tool_msgs = _tool_messages(out)
    assert tool_msgs, "expected a run_command ToolMessage in the returned state"
    assert tool_msgs[0].content.startswith("exit_code:")

    # Audit chain: an allow decision (kubectl-read-verbs / channel ro).
    events = read_events(cfg.audit.dir, ctx.run_id)
    decision = next(e for e in events if e["event_type"] == "decision")
    assert decision["decision"]["effect"] == "allow"
    assert decision["decision"]["rule_id"] == "kubectl-read-verbs"
    assert decision["decision"]["channel"] == "ro"
    assert decision["tool"] == "run_command"

    assert chain_ok(cfg.audit.dir, ctx.run_id)


async def test_allow_flow_emits_execution_event(built_agent: Any, cfg: Any) -> None:
    """An executed tool also emits an ``execution`` audit event (via the exec-meta channel)."""
    fake = make_fake_model(
        [
            ai_tool_call(
                "run_command",
                {"argv": ["kubectl", "get", "pods", "--namespace", "default"]},
                "call-1",
            ),
            ai_text("done."),
        ]
    )
    graph, audit, _ = built_agent(fake)
    ctx = make_context("run-allow-exec")
    start_run(audit, ctx)

    await graph.ainvoke(
        {"messages": [("user", "list pods")]},
        config=invoke_config(ctx.run_id),
        context=ctx,
    )

    assert "execution" in event_types(cfg.audit.dir, ctx.run_id)


async def test_deny_flow_blocks_bash_decision_only(built_agent: Any, cfg: Any) -> None:
    """A shell-string ``bash -c`` call is hard-denied: a deny ToolMessage, no execution event."""
    fake = make_fake_model(
        [
            ai_tool_call("run_command", {"argv": ["bash", "-c", "id"]}, "call-1"),
            ai_text("I can't run shell interpreters; here is what I can do instead."),
        ]
    )
    graph, audit, _ = built_agent(fake)
    ctx = make_context("run-deny")
    start_run(audit, ctx)

    out = await graph.ainvoke(
        {"messages": [("user", "run id")]},
        config=invoke_config(ctx.run_id),
        context=ctx,
    )

    tool_msgs = _tool_messages(out)
    assert tool_msgs, "expected a deny ToolMessage in the returned state"
    assert "Denied by policy [interpreters-hard-deny]" in tool_msgs[0].content

    # A decision event fired, but NO execution event (the tool never ran).
    types = event_types(cfg.audit.dir, ctx.run_id)
    assert types == ["run_started", "decision"]
    decision = next(
        e for e in read_events(cfg.audit.dir, ctx.run_id) if e["event_type"] == "decision"
    )
    assert decision["decision"]["effect"] == "deny"
    assert decision["decision"]["rule_id"] == "interpreters-hard-deny"

    assert chain_ok(cfg.audit.dir, ctx.run_id)
