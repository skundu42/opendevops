"""Scenario 4 (per-run cost cap trip) + Scenario 5 (per-tool shell-call limit)."""

from __future__ import annotations

from typing import Any

from langchain_core.messages import AIMessage, ToolMessage

from .helpers import (
    ai_text,
    ai_tool_call,
    budgets,
    chain_ok,
    invoke_config,
    make_context,
    make_fake_model,
    read_events,
    start_run,
    usage,
)

_SENTINEL = "SENTINEL-SECOND-MODEL-CALL-SHOULD-NOT-RUN"


def _ai_texts(state: dict[str, Any]) -> list[str]:
    return [
        m.content
        for m in state["messages"]
        if isinstance(m, AIMessage) and isinstance(m.content, str)
    ]


async def test_cost_cap_trips_and_ends_run(built_agent: Any, cfg: Any) -> None:
    """One priced call ($2.50) crosses 0.9x the $2.00 cap, so the next turn jumps to end.

    The fake's second message is left unconsumed — proving no further model call happened.
    """
    fake = make_fake_model(
        [
            ai_tool_call(
                "run_command",
                {"argv": ["kubectl", "get", "pods", "--namespace", "default"]},
                "call-1",
                usage_metadata=usage(output=100_000),  # 100k * $25/MTok = $2.50 > 0.9 * $2.00
            ),
            ai_text(_SENTINEL, usage_metadata=usage(output=100_000)),
        ]
    )
    graph, audit, _ = built_agent(fake)
    ctx = make_context("run-cost-cap")
    start_run(audit, ctx)

    out = await graph.ainvoke(
        {"messages": [("user", "investigate the outage")]},
        config=invoke_config(ctx.run_id),
        context=ctx,
    )

    # The per-run USD cap tripped and stamped budget_stop.
    assert out.get("budget_stop", {}).get("kind") == "per_run_usd"
    texts = _ai_texts(out)
    assert any("Budget cap reached" in t for t in texts)
    # The second scripted model message was never consumed (the run ended before calling it).
    assert not any(_SENTINEL in t for t in texts)

    assert chain_ok(cfg.audit.dir, ctx.run_id)


async def test_shell_call_limit_blocks_second_call(built_agent: Any, make_cfg: Any) -> None:
    """With ``shell_calls=1``, the second run_command is blocked with the limit's error message."""
    cfg1 = make_cfg(budgets_doc=budgets(shell_calls=1))
    fake = make_fake_model(
        [
            ai_tool_call(
                "run_command",
                {"argv": ["kubectl", "get", "pods", "--namespace", "default"]},
                "call-1",
            ),
            ai_tool_call(
                "run_command",
                {"argv": ["kubectl", "get", "svc", "--namespace", "default"]},
                "call-2",
            ),
            ai_text("done"),
        ]
    )
    graph, audit, _ = built_agent(fake, cfg_override=cfg1)
    ctx = make_context("run-shell-limit")
    start_run(audit, ctx)

    out = await graph.ainvoke(
        {"messages": [("user", "run two commands")]},
        config=invoke_config(ctx.run_id),
        context=ctx,
    )

    tool_msgs = [m for m in out["messages"] if isinstance(m, ToolMessage)]
    # The first executed (exit_code output); the second got the limit error, not an execution.
    assert any(m.content.startswith("exit_code:") for m in tool_msgs)
    assert any("Tool call limit exceeded" in m.content for m in tool_msgs)

    # Only ONE decision event: the second call was blocked before it reached PolicyMiddleware.
    decisions = [
        e for e in read_events(cfg1.audit.dir, ctx.run_id) if e["event_type"] == "decision"
    ]
    assert len(decisions) == 1

    assert chain_ok(cfg1.audit.dir, ctx.run_id)


# Budgets with per-run profiles that differ ONLY in their USD cap, to prove the per-run profile is
# read from runtime.context (T14): scheduled trips at $1.80, incident only at $9.00.
_PROFILE_BUDGETS: dict[str, Any] = {
    "trip_ratio": 0.9,
    "fail_mode_on_counter_outage": "closed",
    "per_run": {
        "default": {
            "usd": 2.00,
            "model_calls": 50,
            "tool_calls": 100,
            "shell_calls": 30,
            "recursion_limit": 250,
            "wall_clock_s": 900,
        },
        "profiles": {
            "scheduled": {"usd": 2.00},  # threshold 0.9 * 2.00 = 1.80
            "incident": {"usd": 10.00},  # threshold 0.9 * 10.00 = 9.00
        },
    },
    "daily": {"global_usd": 50.00, "per_principal_usd": 25.00},
}


def _two_turn_script() -> Any:
    """A run whose first priced call is $2.50 (100k output @ opus), then a second turn."""
    return make_fake_model(
        [
            ai_tool_call(
                "run_command",
                {"argv": ["kubectl", "get", "pods", "--namespace", "default"]},
                "call-1",
                usage_metadata=usage(output=100_000),  # 100k * $25/MTok = $2.50
            ),
            ai_text("SECOND-TURN-RAN", usage_metadata=usage(output=100_000)),
        ]
    )


async def test_per_profile_usd_cap_trips_at_different_costs(
    built_agent: Any, make_cfg: Any
) -> None:
    """The SAME graph trips the per-run USD cap at different spends per ``context.budget_profile``.

    A $2.50 first call trips ``scheduled`` (cap $2.00) on the next turn but not ``incident``
    (cap $10.00), which runs its second turn to completion — the profile is effective per run.
    """
    cfg2 = make_cfg(budgets_doc=_PROFILE_BUDGETS)

    # scheduled: $2.50 spend crosses the $1.80 threshold -> next turn jumps to end.
    graph_s, audit_s, _ = built_agent(_two_turn_script(), cfg_override=cfg2)
    ctx_s = make_context("run-sched", budget_profile="scheduled")
    start_run(audit_s, ctx_s)
    out_s = await graph_s.ainvoke(
        {"messages": [("user", "x")]}, config=invoke_config(ctx_s.run_id), context=ctx_s
    )
    assert out_s.get("budget_stop", {}).get("kind") == "per_run_usd"
    assert not any("SECOND-TURN-RAN" in t for t in _ai_texts(out_s))
    assert chain_ok(cfg2.audit.dir, ctx_s.run_id)

    # incident: $2.50 is under the $9.00 threshold -> the second turn runs, no trip.
    graph_i, audit_i, _ = built_agent(_two_turn_script(), cfg_override=cfg2)
    ctx_i = make_context("run-inc", budget_profile="incident")
    start_run(audit_i, ctx_i)
    out_i = await graph_i.ainvoke(
        {"messages": [("user", "x")]}, config=invoke_config(ctx_i.run_id), context=ctx_i
    )
    assert out_i.get("budget_stop") is None
    assert any("SECOND-TURN-RAN" in t for t in _ai_texts(out_i))
    assert chain_ok(cfg2.audit.dir, ctx_i.run_id)
