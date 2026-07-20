"""Four golden replay trajectories through the REAL policy/audit/budget stack.

Each scenario drives ``build_agent`` (shipped policy, tmp audit, injected fake model) with the one
subprocess surface replaced by :class:`ReplayToolMiddleware` canned output, then asserts two
independent things:

1. **agentevals superset match** — the run's message trajectory is a superset of a stored golden
   reference (``fixtures/<scenario>.json`` ``golden``). Superset mode compares *tool calls* (name +
   exact args), so this pins that the agent made at least the reference calls the model was
   scripted to make. The scripted fake model IS built from the golden, so this is a real
   round-trip: golden -> fake model -> graph -> messages -> matched back against the golden.
2. **mechanical audit gates** (``audit_gates`` — reused by CI): the hash chain verifies, no
   denied call executed, plus a per-scenario invariant (ro-only channel / dry-run-before-real-apply
   + staged manifest / escalation+resolution with approver).

The golden's *model-requested* argv and the replay step's *executed* argv coincide EXCEPT for the
deploy scenario, where ``force-server-dry-run-first`` rewrites a bare ``apply`` to
``--dry-run=server`` — so the golden keeps the bare apply (what the model asked) while the replay
step carries the rewritten argv (what actually ran). See ``replay_middleware`` for the placement
that makes this work.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import aiosqlite
from agentevals.trajectory.match import create_trajectory_match_evaluator
from langchain_core.messages import AIMessage
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
from langgraph.types import Command

from graph.helpers import (
    ai_text,
    ai_tool_call,
    invoke_config,
    make_context,
    make_fake_model,
    start_run,
)

from .audit_gates import (
    chain_verifies,
    channel_violations,
    denied_executions,
    dry_run_before_real_apply,
    escalation_resolutions_with_approver,
    has_escalation,
    read_chain,
    staged_manifest_shas,
)
from .replay_middleware import ReplayStep

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

_SUPERSET = create_trajectory_match_evaluator(trajectory_match_mode="superset")


# --------------------------------------------------------------------------------------
# fixture plumbing (the golden is the single source of truth: it drives the fake model)
# --------------------------------------------------------------------------------------


def load_fixture(name: str) -> dict[str, Any]:
    """Load ``fixtures/<name>.json`` (golden reference trajectory + canned replay steps)."""
    return json.loads((FIXTURES_DIR / f"{name}.json").read_text())


def script_from_golden(golden: list[dict[str, Any]]) -> list[AIMessage]:
    """Build the scripted fake-model messages from the golden's assistant turns, in order.

    An assistant turn with ``tool_calls`` becomes a single-tool-call ``AIMessage``; a plain
    assistant turn becomes a final text ``AIMessage``. ``user`` / ``tool`` roles are graph inputs /
    graph-produced and are not part of what the model emits, so they are skipped.
    """
    script: list[AIMessage] = []
    for message in golden:
        if message.get("role") != "assistant":
            continue
        tool_calls = message.get("tool_calls")
        if tool_calls:
            call = tool_calls[0]
            script.append(ai_tool_call(call["name"], call["args"], call["id"]))
        else:
            script.append(ai_text(message.get("content", "")))
    return script


def replay_steps(fixture: dict[str, Any]) -> list[ReplayStep]:
    """The ordered canned executions for the scenario."""
    return [ReplayStep.from_dict(s) for s in fixture["replay"]]


def assert_superset(out_messages: list[Any], golden: list[dict[str, Any]]) -> None:
    """The run trajectory is a superset of the golden reference (tool calls match)."""
    result = _SUPERSET(outputs=out_messages, reference_outputs=golden)
    assert result["score"] is True, f"trajectory is not a superset of the golden: {result}"


async def _saver() -> tuple[AsyncSqliteSaver, aiosqlite.Connection]:
    conn = await aiosqlite.connect(":memory:")
    return AsyncSqliteSaver(conn), conn


# --------------------------------------------------------------------------------------
# scenario 1 — crashloop-rca (read-only)
# --------------------------------------------------------------------------------------


async def test_crashloop_rca(replay_agent: Any, make_cfg: Any) -> None:
    fx = load_fixture("crashloop_rca")
    cfg = make_cfg()
    fake = make_fake_model(script_from_golden(fx["golden"]))
    graph, audit, replay = replay_agent(fake, replay_steps(fx), cfg_override=cfg)

    ctx = make_context("run-crashloop", environment=fx["environment"])
    start_run(audit, ctx)
    out = await graph.ainvoke(
        {"messages": [("user", fx["user"])]}, config=invoke_config(ctx.run_id), context=ctx
    )

    assert_superset(out["messages"], fx["golden"])

    events = read_chain(cfg.audit.dir, ctx.run_id)
    assert chain_verifies(cfg.audit.dir, ctx.run_id)
    assert denied_executions(events) == []
    # scenario-specific: a diagnosis touches ONLY the read-only credential channel.
    assert channel_violations(events, {"ro"}) == []
    assert replay.remaining == []  # every canned step was consumed exactly once


# --------------------------------------------------------------------------------------
# scenario 2 — deploy-verify-rollback (staging, rw + dry-run enforcement)
# --------------------------------------------------------------------------------------


async def test_deploy_verify_rollback(replay_agent: Any, make_cfg: Any) -> None:
    fx = load_fixture("deploy_verify_rollback")
    cfg = make_cfg()
    fake = make_fake_model(script_from_golden(fx["golden"]))
    graph, audit, replay = replay_agent(fake, replay_steps(fx), cfg_override=cfg)

    ctx = make_context("run-deploy", environment=fx["environment"])
    start_run(audit, ctx)
    out = await graph.ainvoke(
        {"messages": [("user", fx["user"])]}, config=invoke_config(ctx.run_id), context=ctx
    )

    assert_superset(out["messages"], fx["golden"])

    events = read_chain(cfg.audit.dir, ctx.run_id)
    assert chain_verifies(cfg.audit.dir, ctx.run_id)
    assert denied_executions(events) == []
    # scenario-specific: a server dry-run executed BEFORE the real apply, and the applied
    # manifest's content sha256 was recorded (staged_files present).
    assert dry_run_before_real_apply(events) is True
    assert staged_manifest_shas(events), "no staged-manifest sha256 recorded on any execution"
    # every mutating execution used the rw channel (no ro leak on a write path).
    assert channel_violations(events, {"rw"}) == []
    assert replay.remaining == []


# --------------------------------------------------------------------------------------
# scenario 3 — ci-failure-diagnosis (gh read-only)
# --------------------------------------------------------------------------------------


async def test_ci_failure_diagnosis(replay_agent: Any, make_cfg: Any) -> None:
    fx = load_fixture("ci_failure_diagnosis")
    cfg = make_cfg()
    fake = make_fake_model(script_from_golden(fx["golden"]))
    graph, audit, replay = replay_agent(fake, replay_steps(fx), cfg_override=cfg)

    ctx = make_context("run-ci", environment=fx["environment"])
    start_run(audit, ctx)
    out = await graph.ainvoke(
        {"messages": [("user", fx["user"])]}, config=invoke_config(ctx.run_id), context=ctx
    )

    assert_superset(out["messages"], fx["golden"])

    events = read_chain(cfg.audit.dir, ctx.run_id)
    assert chain_verifies(cfg.audit.dir, ctx.run_id)
    assert denied_executions(events) == []
    # scenario-specific: gh inspection is read-only.
    assert channel_violations(events, {"ro"}) == []
    assert replay.remaining == []


# --------------------------------------------------------------------------------------
# scenario 4 — escalated-delete (interrupt/resume; approve -> executes once)
# --------------------------------------------------------------------------------------


async def test_escalated_delete_approve(replay_agent: Any, make_cfg: Any) -> None:
    fx = load_fixture("escalated_delete")
    cfg = make_cfg()
    fake = make_fake_model(script_from_golden(fx["golden"]))

    saver, conn = await _saver()
    try:
        graph, audit, replay = replay_agent(
            fake, replay_steps(fx), cfg_override=cfg, checkpointer=saver
        )
        ctx = make_context("run-escalate", environment=fx["environment"])
        start_run(audit, ctx)

        # First invoke: the destructive delete matches the escalate rule and SUSPENDS.
        suspended = await graph.ainvoke(
            {"messages": [("user", fx["user"])]},
            config=invoke_config(ctx.run_id),
            context=ctx,
        )
        assert "__interrupt__" in suspended
        payload = suspended["__interrupt__"][0].value
        assert payload["review_configs"][0]["rule_id"] == "kubectl-delete-workload-escalate"
        assert replay.consumed == 0  # nothing executed while awaiting approval

        events = read_chain(cfg.audit.dir, ctx.run_id)
        assert has_escalation(events)

        # Resume APPROVE: the delete executes exactly once and the run completes.
        final = await graph.ainvoke(
            Command(resume={"decisions": [{"type": "approve", "approver": fx["approver"]}]}),
            config=invoke_config(ctx.run_id),
            context=ctx,
        )

        assert_superset(final["messages"], fx["golden"])
        assert replay.consumed == 1  # executed exactly once across the resume re-execution
        assert replay.remaining == []

        events = read_chain(cfg.audit.dir, ctx.run_id)
        assert chain_verifies(cfg.audit.dir, ctx.run_id)
        assert denied_executions(events) == []
        # scenario-specific: an escalation was recorded and RESOLVED by a named approver.
        resolutions = escalation_resolutions_with_approver(events)
        assert len(resolutions) == 1
        assert resolutions[0]["approver"] == fx["approver"]
        assert resolutions[0]["type"] == "approve"
    finally:
        await conn.close()
