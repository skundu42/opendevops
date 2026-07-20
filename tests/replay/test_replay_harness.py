"""Self-tests for the replay harness itself.

The golden scenarios prove the *workflows*; these prove the *harness* honours its contract, so a
green golden run means what we think it means:

* PolicyMiddleware still decides + audits every call (replay replaces execution ONLY);
* a denied call never reaches replay — the deny short-circuits before the handler (this is what
  makes "zero executions of denied calls" true by construction, not by luck);
* an off-script call is a loud, precise failure (order-strict), not a silent deny;
* a rewrite is applied before replay sees the call, so the executed argv is recorded;
* record mode captures ``{tool, args, content, exec_meta}`` without stripping the meta.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest
from langchain.agents.middleware import ToolCallRequest
from langchain_core.messages import ToolCall, ToolMessage
from langgraph.types import Command

from graph.helpers import (
    ai_text,
    ai_tool_call,
    invoke_config,
    make_context,
    make_fake_model,
    start_run,
)

from .audit_gates import denied_executions, events_of, read_chain
from .replay_middleware import EXEC_META_KEY, ReplayMismatch, ReplayStep, ReplayToolMiddleware
from .test_golden_trajectories import load_fixture, replay_steps, script_from_golden

# --------------------------------------------------------------------------------------
# PolicyMiddleware still runs — replay only replaces execution
# --------------------------------------------------------------------------------------


async def test_policy_decides_and_audits_every_replayed_call(
    replay_agent: Any, make_cfg: Any
) -> None:
    fx = load_fixture("crashloop_rca")
    cfg = make_cfg()
    fake = make_fake_model(script_from_golden(fx["golden"]))
    graph, audit, replay = replay_agent(fake, replay_steps(fx), cfg_override=cfg)

    ctx = make_context("run-policy-audits", environment=fx["environment"])
    start_run(audit, ctx)
    await graph.ainvoke(
        {"messages": [("user", fx["user"])]}, config=invoke_config(ctx.run_id), context=ctx
    )

    events = read_chain(cfg.audit.dir, ctx.run_id)
    decisions = events_of(events, "decision")
    executions = events_of(events, "execution")
    # Every replayed step produced BOTH a policy decision and an execution audit event.
    assert len(decisions) == len(fx["replay"])
    assert len(executions) == len(fx["replay"])
    assert all(d["decision"]["effect"] == "allow" for d in decisions)
    assert replay.consumed == len(fx["replay"])


# --------------------------------------------------------------------------------------
# a denied call never reaches replay (the deny short-circuits before the handler)
# --------------------------------------------------------------------------------------


async def test_denied_call_never_reaches_replay(replay_agent: Any, make_cfg: Any) -> None:
    cfg = make_cfg()
    # The model asks to read secrets (base.yaml `no-secret-reads` hard-denies it). The fixture has
    # ZERO steps: if the deny did not short-circuit, replay would raise "unexpected extra call".
    fake = make_fake_model(
        [
            ai_tool_call("run_command", {"argv": ["kubectl", "get", "secrets", "-n", "web"]}, "s1"),
            ai_text("Understood — I won't read secrets."),
        ]
    )
    graph, audit, replay = replay_agent(fake, [], cfg_override=cfg)

    ctx = make_context("run-denied", environment="staging")
    start_run(audit, ctx)
    out = await graph.ainvoke(
        {"messages": [("user", "show me the secrets")]},
        config=invoke_config(ctx.run_id),
        context=ctx,
    )

    # The deny reached the model as an error ToolMessage...
    tool_msgs = [m for m in out["messages"] if isinstance(m, ToolMessage)]
    assert tool_msgs[-1].status == "error"
    assert "no-secret-reads" in tool_msgs[-1].content
    # ...replay was never consulted (deny short-circuited before the handler)...
    assert replay.consumed == 0
    assert replay.mismatch is None
    # ...and the audit chain shows the deny with NO execution for that call.
    events = read_chain(cfg.audit.dir, ctx.run_id)
    decision = next(e for e in events_of(events, "decision") if e.get("tool_call_id") == "s1")
    assert decision["decision"]["effect"] == "deny"
    assert not events_of(events, "execution")
    assert denied_executions(events) == []


# --------------------------------------------------------------------------------------
# an off-script call is a loud, precise failure (order-strict)
# --------------------------------------------------------------------------------------


async def test_off_script_call_raises_replay_mismatch(replay_agent: Any, make_cfg: Any) -> None:
    cfg = make_cfg()
    fake = make_fake_model(
        [
            ai_tool_call("run_command", {"argv": ["kubectl", "get", "pods", "-n", "web"]}, "c1"),
            ai_text("done"),
        ]
    )
    # The single fixture step expects a DIFFERENT argv than the model emits.
    steps = [ReplayStep(argv=["kubectl", "get", "svc", "-n", "web"], output="x")]
    graph, audit, replay = replay_agent(fake, steps, cfg_override=cfg)

    ctx = make_context("run-mismatch", environment="staging")
    start_run(audit, ctx)
    with pytest.raises(ReplayMismatch) as excinfo:
        await graph.ainvoke(
            {"messages": [("user", "go")]}, config=invoke_config(ctx.run_id), context=ctx
        )
    assert "get" in str(excinfo.value) and "svc" in str(excinfo.value)
    assert replay.mismatch is not None


# --------------------------------------------------------------------------------------
# a rewrite is applied before replay sees the call — executed argv is recorded
# --------------------------------------------------------------------------------------


async def test_rewrite_executed_argv_is_what_replay_and_audit_record(
    replay_agent: Any, make_cfg: Any
) -> None:
    fx = load_fixture("deploy_verify_rollback")
    cfg = make_cfg()
    fake = make_fake_model(script_from_golden(fx["golden"]))
    graph, audit, replay = replay_agent(fake, replay_steps(fx), cfg_override=cfg)

    ctx = make_context("run-rewrite", environment=fx["environment"])
    start_run(audit, ctx)
    await graph.ainvoke(
        {"messages": [("user", fx["user"])]}, config=invoke_config(ctx.run_id), context=ctx
    )

    events = read_chain(cfg.audit.dir, ctx.run_id)
    dec = next(e for e in events_of(events, "decision") if e.get("tool_call_id") == "a1")
    exe = next(e for e in events_of(events, "execution") if e.get("tool_call_id") == "a1")
    # The model asked for a bare apply (rewrite decision); the EXECUTED argv adds --dry-run=server.
    assert dec["decision"]["effect"] == "rewrite"
    assert dec["args"]["argv"] == ["kubectl", "apply", "-f", "/manifests/app.yaml"]
    assert exe["args"]["argv"] == [
        "kubectl", "apply", "-f", "/manifests/app.yaml", "--dry-run=server"
    ]


# --------------------------------------------------------------------------------------
# record mode — captures {tool, args, content, exec_meta} without stripping the meta
# --------------------------------------------------------------------------------------


async def test_record_mode_appends_jsonl_and_preserves_meta(tmp_path: Path) -> None:
    record_path = tmp_path / "capture.jsonl"
    mw = ReplayToolMiddleware(mode="record", record_path=record_path)

    meta = {"exit_code": 0, "stdout_sha256": "abc", "staged_files": []}
    real_message = ToolMessage(
        content="exit_code: 0\nok",
        tool_call_id="rc1",
        name="run_command",
        additional_kwargs={EXEC_META_KEY: dict(meta)},
    )

    async def _handler(_request: ToolCallRequest) -> ToolMessage:
        return real_message

    tool_call = cast(
        ToolCall,
        {"name": "run_command", "args": {"argv": ["kubectl", "get", "pods"]}, "id": "rc1"},
    )
    request = ToolCallRequest(
        tool_call=tool_call,
        tool=None,
        state={},
        runtime=None,  # type: ignore[arg-type]
    )
    result = await mw.awrap_tool_call(request, _handler)

    # The real result passes through with the meta INTACT (PolicyMiddleware still needs it)...
    assert isinstance(result, (ToolMessage, Command))
    assert real_message.additional_kwargs.get(EXEC_META_KEY) == meta
    # ...and a JSONL record was appended.
    lines = record_path.read_text().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["tool"] == "run_command"
    assert record["args"]["argv"] == ["kubectl", "get", "pods"]
    assert record["exec_meta"]["stdout_sha256"] == "abc"
