"""Graph-level escalation flow: interrupt() suspend + Command(resume=...) through the graph.

Exercises the REAL agent graph + REAL shipped policy + a real ``AsyncSqliteSaver`` checkpointer:
a staging ``kubectl delete pod`` matches ``kubectl-delete-workload-escalate`` (effect escalate),
so the run SUSPENDS on ``interrupt()``. The tests resume it approve / reject / edit and assert:

* THE REPLAY GUARANTEE — resume-approve executes the tool EXACTLY ONCE (spy executor + exactly one
  ``execution`` audit event for the tool_call_id) despite the tools node re-executing on resume;
* the audit chain records escalation -> resolution(approver) and verifies;
* reject returns a deny ToolMessage and the model continues;
* an edited argv is re-authorized from scratch (a denied edit comes back denied);
* a prior allowed sibling call (earlier turn) is not re-executed across the resume.

The subprocess is faked (exit 0) so a delete "succeeds" deterministically; a rw kubeconfig path is
configured so the escalate rule's ``channel: rw`` execution gets its credential.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import aiosqlite
import pytest
from langchain_core.messages import AIMessage, ToolMessage
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
from langgraph.types import Command

import opendevops.tools.run_command as run_command_mod
from opendevops.config import AppConfig
from opendevops.tools.executor import ExecResult

from .helpers import (
    MODELS,
    ai_text,
    ai_tool_call,
    budgets,
    chain_ok,
    invoke_config,
    make_context,
    make_fake_model,
    read_events,
    start_run,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_DIR = REPO_ROOT / "config" / "policy"

_DELETE_ARGV = ["kubectl", "delete", "pod", "x", "-n", "web"]
# An edit whose argv policy ALLOWS (a read) — re-authorized from scratch and executed.
_EDIT_ALLOWED_ARGV = ["kubectl", "get", "pods", "-n", "web"]
# An edit whose argv STILL escalates (delete a deployment) — suspends again for a 2nd approver.
_EDIT_ESCALATING_ARGV = ["kubectl", "delete", "deployment", "web", "-n", "web"]


class _CountingExecutor:
    """A run_command executor stand-in that COUNTS executions (the replay-safety spy)."""

    def __init__(self, home: str) -> None:
        self._home = home
        self.count = 0
        self.argvs: list[list[str]] = []

    @property
    def home(self) -> str:
        return self._home

    async def execute(self, argv: list[str], timeout_s: int, env: dict[str, str]) -> ExecResult:
        self.count += 1
        self.argvs.append(list(argv))
        return ExecResult(exit_code=0, output="pod/x deleted", duration_ms=1, timed_out=False)


def _cfg_with_rw(tmp_path: Path) -> AppConfig:
    return AppConfig.model_validate(
        {
            "targets": {
                "kubernetes": {
                    "kubeconfig_ro": str(tmp_path / "kubeconfig-ro.yaml"),
                    "kubeconfig_rw": str(tmp_path / "kubeconfig-rw.yaml"),
                    "allowed_contexts": ["kind-opendevops"],
                },
                "github": {
                    "token_env": "OPENDEVOPS_TEST_GH_TOKEN",
                    "token_env_rw": "OPENDEVOPS_TEST_GH_TOKEN_RW",  # gh-write rw gate
                    "write_repos": ["octo-org/staging-app"],
                },
                # cloud read packs' coverage gate (names only; not exec'd here).
                "aws": {"credential_env": ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]},
                "gcloud": {"credential_env": ["GOOGLE_APPLICATION_CREDENTIALS"]},
                "azure": {"credential_env": ["AZURE_CLIENT_ID", "AZURE_TENANT_ID"]},
                # ssh-read pack coverage gate (names/paths only; never dialed here).
                "ssh": {
                    "hosts": ["allowed.host.internal"],
                    "user": "deploy",
                    "key_env": "OPENDEVOPS_TEST_SSH_KEY",
                    "known_hosts_path": "/nonexistent/known_hosts",
                },
            },
            "execution": {
                "cmd_timeout_seconds": 60,
                "output_max_chars": 50000,
                "env_allowlist": ["PATH", "HOME"],
            },
            "audit": {"dir": str(tmp_path / "audit")},
            "policy": {"dir": str(POLICY_DIR)},
            "state": {"dir": str(tmp_path / "state")},
            "principals": {},
            "models": copy.deepcopy(MODELS),
            "budgets": budgets(),
        }
    )


async def _saver() -> tuple[AsyncSqliteSaver, aiosqlite.Connection]:
    conn = await aiosqlite.connect(":memory:")
    return AsyncSqliteSaver(conn), conn


def _tool_messages(state: dict[str, Any]) -> list[ToolMessage]:
    return [m for m in state["messages"] if isinstance(m, ToolMessage)]


def _executions_for(events: list[dict[str, Any]], tool_call_id: str) -> list[dict[str, Any]]:
    return [
        e
        for e in events
        if e["event_type"] == "execution" and e.get("tool_call_id") == tool_call_id
    ]


# --------------------------------------------------------------------------------------
# THE REPLAY GUARANTEE — resume approve executes exactly once
# --------------------------------------------------------------------------------------


async def test_escalate_suspends_then_resume_approve_executes_exactly_once(
    built_agent: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    spy = _CountingExecutor(str(home))
    monkeypatch.setattr(run_command_mod, "_DEFAULT_EXECUTOR", spy)

    cfg = _cfg_with_rw(tmp_path)
    fake = make_fake_model(
        [
            ai_tool_call("run_command", {"argv": _DELETE_ARGV}, "call-del"),
            ai_text("Deleted the pod."),
        ]
    )
    saver, conn = await _saver()
    try:
        graph, audit, _ = built_agent(fake, cfg_override=cfg, checkpointer=saver)
        ctx = make_context("run-esc")
        start_run(audit, ctx)

        # First invoke: the delete matches the escalate rule and SUSPENDS on interrupt().
        suspended = await graph.ainvoke(
            {"messages": [("user", "delete pod x")]},
            config=invoke_config(ctx.run_id),
            context=ctx,
        )
        assert "__interrupt__" in suspended
        payload = suspended["__interrupt__"][0].value
        assert payload["action_requests"][0]["args"]["argv"] == _DELETE_ARGV
        assert payload["review_configs"][0]["rule_id"] == "kubectl-delete-workload-escalate"
        assert spy.count == 0  # nothing executed while suspended

        events = read_events(cfg.audit.dir, ctx.run_id)
        assert any(e["event_type"] == "escalation" for e in events)
        assert not _executions_for(events, "call-del")  # no execution yet

        # Resume APPROVE: the tool executes exactly once and the run completes.
        final = await graph.ainvoke(
            Command(resume={"decisions": [{"type": "approve", "approver": "alice"}]}),
            config=invoke_config(ctx.run_id),
            context=ctx,
        )
        assert spy.count == 1  # executed exactly once across the node re-execution
        assert spy.argvs == [_DELETE_ARGV]
        tool_msgs = _tool_messages(final)
        assert any("deleted" in m.content.lower() for m in tool_msgs)

        events = read_events(cfg.audit.dir, ctx.run_id)
        # Exactly one execution audit event for the escalated tool_call_id (dedupe + cache).
        assert len(_executions_for(events, "call-del")) == 1
        resolutions = [e for e in events if e["event_type"] == "resolution"]
        assert len(resolutions) == 1
        assert resolutions[0]["approver"] == "alice"
        assert resolutions[0]["summary"]["type"] == "approve"
        # Exactly one escalation event (the resume re-execution is deduped).
        assert len([e for e in events if e["event_type"] == "escalation"]) == 1
        assert chain_ok(cfg.audit.dir, ctx.run_id)
    finally:
        await conn.close()


# --------------------------------------------------------------------------------------
# reject
# --------------------------------------------------------------------------------------


async def test_resume_reject_denies_and_model_continues(
    built_agent: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    spy = _CountingExecutor(str(home))
    monkeypatch.setattr(run_command_mod, "_DEFAULT_EXECUTOR", spy)

    cfg = _cfg_with_rw(tmp_path)
    fake = make_fake_model(
        [
            ai_tool_call("run_command", {"argv": _DELETE_ARGV}, "call-del"),
            ai_text("Understood, leaving the pod in place."),
        ]
    )
    saver, conn = await _saver()
    try:
        graph, audit, _ = built_agent(fake, cfg_override=cfg, checkpointer=saver)
        ctx = make_context("run-rej")
        start_run(audit, ctx)

        await graph.ainvoke(
            {"messages": [("user", "delete pod x")]},
            config=invoke_config(ctx.run_id),
            context=ctx,
        )
        final = await graph.ainvoke(
            Command(
                resume={
                    "decisions": [
                        {"type": "reject", "message": "too risky", "approver": "bob"}
                    ]
                }
            ),
            config=invoke_config(ctx.run_id),
            context=ctx,
        )

        assert spy.count == 0  # never executed
        tool_msgs = _tool_messages(final)
        deny = tool_msgs[-1]
        assert deny.status == "error"
        assert "kubectl-delete-workload-escalate" in deny.content
        assert "too risky" in deny.content
        # The model saw the deny and produced its follow-up text.
        assert final["messages"][-1].content == "Understood, leaving the pod in place."

        events = read_events(cfg.audit.dir, ctx.run_id)
        assert not _executions_for(events, "call-del")
        resolution = next(e for e in events if e["event_type"] == "resolution")
        assert resolution["approver"] == "bob"
        assert resolution["summary"]["type"] == "reject"
        assert chain_ok(cfg.audit.dir, ctx.run_id)
    finally:
        await conn.close()


# --------------------------------------------------------------------------------------
# edit — re-authorized from scratch; a denied edit comes back denied
# --------------------------------------------------------------------------------------


async def test_resume_edit_reauthorizes_and_denied_edit_comes_back_denied(
    built_agent: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    spy = _CountingExecutor(str(home))
    monkeypatch.setattr(run_command_mod, "_DEFAULT_EXECUTOR", spy)

    cfg = _cfg_with_rw(tmp_path)
    fake = make_fake_model(
        [
            ai_tool_call("run_command", {"argv": _DELETE_ARGV}, "call-del"),
            ai_text("The forced delete was denied by policy."),
        ]
    )
    saver, conn = await _saver()
    try:
        graph, audit, _ = built_agent(fake, cfg_override=cfg, checkpointer=saver)
        ctx = make_context("run-edit")
        start_run(audit, ctx)

        await graph.ainvoke(
            {"messages": [("user", "delete pod x")]},
            config=invoke_config(ctx.run_id),
            context=ctx,
        )
        # Approver EDITS the argv to add --force; policy denies --force (kubectl-mutate-no-force),
        # so the edited command is re-authorized from scratch and comes back denied.
        final = await graph.ainvoke(
            Command(
                resume={
                    "decisions": [
                        {
                            "type": "edit",
                            "args": {"argv": [*_DELETE_ARGV, "--force"]},
                            "approver": "carol",
                        }
                    ]
                }
            ),
            config=invoke_config(ctx.run_id),
            context=ctx,
        )

        assert spy.count == 0  # the edited (forced) delete never executed
        deny = _tool_messages(final)[-1]
        assert deny.status == "error"
        assert "kubectl-mutate-no-force" in deny.content

        events = read_events(cfg.audit.dir, ctx.run_id)
        resolution = next(e for e in events if e["event_type"] == "resolution")
        assert resolution["summary"]["type"] == "edit"
        assert chain_ok(cfg.audit.dir, ctx.run_id)
    finally:
        await conn.close()


# --------------------------------------------------------------------------------------
# sibling replay — an earlier allowed call is not re-executed across the resume
# --------------------------------------------------------------------------------------


async def test_prior_allowed_call_not_re_executed_across_resume(
    built_agent: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    spy = _CountingExecutor(str(home))
    monkeypatch.setattr(run_command_mod, "_DEFAULT_EXECUTOR", spy)

    cfg = _cfg_with_rw(tmp_path)
    fake = make_fake_model(
        [
            # Turn 1: an allowed read (executes, caches, completes its super-step).
            ai_tool_call("run_command", {"argv": ["kubectl", "get", "pods"]}, "call-get"),
            # Turn 2: the escalating delete (suspends).
            ai_tool_call("run_command", {"argv": _DELETE_ARGV}, "call-del"),
            ai_text("Done."),
        ]
    )
    saver, conn = await _saver()
    try:
        graph, audit, _ = built_agent(fake, cfg_override=cfg, checkpointer=saver)
        ctx = make_context("run-sib")
        start_run(audit, ctx)

        suspended = await graph.ainvoke(
            {"messages": [("user", "look then delete")]},
            config=invoke_config(ctx.run_id),
            context=ctx,
        )
        assert "__interrupt__" in suspended
        assert spy.count == 1  # only the allowed get ran before the suspend

        await graph.ainvoke(
            Command(resume={"decisions": [{"type": "approve", "approver": "alice"}]}),
            config=invoke_config(ctx.run_id),
            context=ctx,
        )
        assert spy.count == 2  # the get (1) + the approved delete (1) — the get did NOT re-run

        events = read_events(cfg.audit.dir, ctx.run_id)
        # The allowed sibling's execution audit appears exactly once across the whole run.
        assert len(_executions_for(events, "call-get")) == 1
        assert len(_executions_for(events, "call-del")) == 1
        assert chain_ok(cfg.audit.dir, ctx.run_id)
    finally:
        await conn.close()


# --------------------------------------------------------------------------------------
# I1 — edit-to-allowed: the EDITED argv is recorded and executed (recoverable from the chain)
# --------------------------------------------------------------------------------------


async def test_resume_edit_to_allowed_records_and_executes_edited_argv(
    built_agent: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An edit whose argv policy ALLOWS: the chain carries the edited argv (new decision +
    resolution args) and the execution event records it — not the originally-escalated argv."""
    home = tmp_path / "home"
    home.mkdir()
    spy = _CountingExecutor(str(home))
    monkeypatch.setattr(run_command_mod, "_DEFAULT_EXECUTOR", spy)

    cfg = _cfg_with_rw(tmp_path)
    fake = make_fake_model(
        [
            ai_tool_call("run_command", {"argv": _DELETE_ARGV}, "call-del"),
            ai_text("Listed the pods instead."),
        ]
    )
    saver, conn = await _saver()
    try:
        graph, audit, _ = built_agent(fake, cfg_override=cfg, checkpointer=saver)
        ctx = make_context("run-edit-allow")
        start_run(audit, ctx)

        await graph.ainvoke(
            {"messages": [("user", "delete pod x")]},
            config=invoke_config(ctx.run_id),
            context=ctx,
        )
        final = await graph.ainvoke(
            Command(
                resume={
                    "decisions": [
                        {
                            "type": "edit",
                            "args": {"argv": _EDIT_ALLOWED_ARGV},
                            "approver": "carol",
                        }
                    ]
                }
            ),
            config=invoke_config(ctx.run_id),
            context=ctx,
        )

        # The edited (allowed) argv executed exactly once — the original delete never ran.
        assert spy.count == 1
        assert spy.argvs == [_EDIT_ALLOWED_ARGV]
        assert _tool_messages(final)  # the tool produced a result the model saw

        events = read_events(cfg.audit.dir, ctx.run_id)
        # (a) the re-entry decision event carries the edited argv,
        decisions = [e for e in events if e["event_type"] == "decision"]
        assert any(d["args"]["argv"] == _EDIT_ALLOWED_ARGV for d in decisions)
        # (b) the resolution records the authorized (edited) argv,
        resolution = next(e for e in events if e["event_type"] == "resolution")
        assert resolution["summary"]["type"] == "edit"
        assert resolution["approver"] == "carol"
        assert resolution["args"]["argv"] == _EDIT_ALLOWED_ARGV
        # (c) the single execution event carries the executed (edited) argv.
        execs = _executions_for(events, "call-del")
        assert len(execs) == 1
        assert execs[0]["args"]["argv"] == _EDIT_ALLOWED_ARGV
        assert chain_ok(cfg.audit.dir, ctx.run_id)
    finally:
        await conn.close()


# --------------------------------------------------------------------------------------
# I1 — edit-to-escalating-then-approve (double interrupt): two resolutions, both recorded
# --------------------------------------------------------------------------------------


async def test_edit_to_escalating_then_second_approver_double_interrupt(
    built_agent: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Edit → a still-escalating argv → a SECOND human approves. The chain must record BOTH
    resolutions (editor + final approver), the second escalation, and the executed argv, with
    exactly ONE execution for the tool_call_id."""
    home = tmp_path / "home"
    home.mkdir()
    spy = _CountingExecutor(str(home))
    monkeypatch.setattr(run_command_mod, "_DEFAULT_EXECUTOR", spy)

    cfg = _cfg_with_rw(tmp_path)
    fake = make_fake_model(
        [
            ai_tool_call("run_command", {"argv": _DELETE_ARGV}, "call-del"),
            ai_text("Deleted the deployment."),
        ]
    )
    saver, conn = await _saver()
    try:
        graph, audit, _ = built_agent(fake, cfg_override=cfg, checkpointer=saver)
        ctx = make_context("run-dbl")
        start_run(audit, ctx)

        suspended1 = await graph.ainvoke(
            {"messages": [("user", "delete pod x")]},
            config=invoke_config(ctx.run_id),
            context=ctx,
        )
        assert "__interrupt__" in suspended1

        # First approver EDITS to a still-escalating argv → the run SUSPENDS AGAIN.
        suspended2 = await graph.ainvoke(
            Command(
                resume={
                    "decisions": [
                        {
                            "type": "edit",
                            "args": {"argv": _EDIT_ESCALATING_ARGV},
                            "approver": "carol",
                        }
                    ]
                }
            ),
            config=invoke_config(ctx.run_id),
            context=ctx,
        )
        assert "__interrupt__" in suspended2
        reprompt = suspended2["__interrupt__"][0].value
        assert reprompt["action_requests"][0]["args"]["argv"] == _EDIT_ESCALATING_ARGV
        assert spy.count == 0  # still nothing executed while re-suspended

        # A SECOND human approves the edited argv → it executes exactly once.
        await graph.ainvoke(
            Command(resume={"decisions": [{"type": "approve", "approver": "dave"}]}),
            config=invoke_config(ctx.run_id),
            context=ctx,
        )
        assert spy.count == 1
        assert spy.argvs == [_EDIT_ESCALATING_ARGV]

        events = read_events(cfg.audit.dir, ctx.run_id)
        # TWO resolutions in order: the editor (carol) then the final approver (dave).
        resolutions = [e for e in events if e["event_type"] == "resolution"]
        assert [r["approver"] for r in resolutions] == ["carol", "dave"]
        assert resolutions[0]["summary"]["type"] == "edit"
        assert resolutions[0]["args"]["argv"] == _EDIT_ESCALATING_ARGV
        assert resolutions[1]["summary"]["type"] == "approve"
        # The second escalation (the edited argv) is recorded, not just the original.
        escalations = [e for e in events if e["event_type"] == "escalation"]
        assert len(escalations) == 2
        assert escalations[0]["args"]["argv"] == _DELETE_ARGV
        assert escalations[1]["args"]["argv"] == _EDIT_ESCALATING_ARGV
        # Exactly ONE execution for the tool_call_id, carrying the executed (edited) argv.
        execs = _executions_for(events, "call-del")
        assert len(execs) == 1
        assert execs[0]["args"]["argv"] == _EDIT_ESCALATING_ARGV
        assert chain_ok(cfg.audit.dir, ctx.run_id)
    finally:
        await conn.close()


# --------------------------------------------------------------------------------------
# M4 — graph-tier guard: a dropped parallel sibling gets NO decision audit event
# --------------------------------------------------------------------------------------


async def test_parallel_second_tool_call_dropped_has_no_decision_event(
    built_agent: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A scripted model emitting TWO tool_calls in one AIMessage: SingleToolCallMiddleware keeps
    only the first, so the dropped second call never reaches PolicyMiddleware — no decision (or
    execution) audit event is written for it."""
    home = tmp_path / "home"
    home.mkdir()
    spy = _CountingExecutor(str(home))
    monkeypatch.setattr(run_command_mod, "_DEFAULT_EXECUTOR", spy)

    cfg = _cfg_with_rw(tmp_path)
    two_calls = AIMessage(
        content="",
        tool_calls=[
            {
                "name": "run_command",
                "args": {"argv": ["kubectl", "get", "pods"]},
                "id": "call-a",
                "type": "tool_call",
            },
            {
                "name": "run_command",
                "args": {"argv": ["kubectl", "get", "svc"]},
                "id": "call-b",
                "type": "tool_call",
            },
        ],
    )
    fake = make_fake_model([two_calls, ai_text("Looked around.")])
    saver, conn = await _saver()
    try:
        graph, audit, _ = built_agent(fake, cfg_override=cfg, checkpointer=saver)
        ctx = make_context("run-guard")
        start_run(audit, ctx)

        await graph.ainvoke(
            {"messages": [("user", "look around")]},
            config=invoke_config(ctx.run_id),
            context=ctx,
        )

        # Only the first call executed; the guard dropped the second before policy saw it.
        assert spy.count == 1
        assert spy.argvs == [["kubectl", "get", "pods"]]

        events = read_events(cfg.audit.dir, ctx.run_id)
        decided_ids = {
            e.get("tool_call_id") for e in events if e["event_type"] == "decision"
        }
        assert "call-a" in decided_ids  # the surviving call was authorized
        assert "call-b" not in decided_ids  # the dropped call never reached policy
        assert not _executions_for(events, "call-b")
        assert chain_ok(cfg.audit.dir, ctx.run_id)
    finally:
        await conn.close()
