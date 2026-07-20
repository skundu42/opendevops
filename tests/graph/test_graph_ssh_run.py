"""ssh_run through the REAL graph: decide -> audit(decision) -> execute -> audit(execution) (P5b).

Proves the structured ssh_run tool flows the SAME PolicyMiddleware pipeline as run_command — an
allowed call executes, scrubs, and lands BOTH a decision and an execution audit event; a
non-allowlisted host is denied (decision only, no execution). ``SshExecutor.execute`` is stubbed at
the class level so NO real socket is opened; the key env var is set so the config-pinned credential
resolves.
"""

from __future__ import annotations

from typing import Any

import pytest
from langchain_core.messages import ToolMessage

import opendevops.tools.executor as executor_mod
from opendevops.tools.executor import ExecResult

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

ALLOWED_HOST = "allowed.host.internal"


def _tool_messages(state: dict[str, Any]) -> list[ToolMessage]:
    return [m for m in state["messages"] if isinstance(m, ToolMessage)]


def _stub_executor(monkeypatch: pytest.MonkeyPatch, output: str) -> dict[str, Any]:
    """Stub SshExecutor.execute (no socket) + set the key env var; return a capture dict."""
    captured: dict[str, Any] = {}

    async def _fake_execute(
        self: Any, host: str, argv: list[str], timeout_s: int, cred: Any
    ) -> ExecResult:
        captured["host"] = host
        captured["argv"] = list(argv)
        captured["cred"] = cred
        return ExecResult(0, output, 7, False)

    monkeypatch.setattr(executor_mod.SshExecutor, "execute", _fake_execute)
    monkeypatch.setenv("OPENDEVOPS_TEST_SSH_KEY", "/fake/id_ed25519")
    return captured


async def test_ssh_run_allow_flow_executes_scrubs_and_audits(
    built_agent: Any, cfg: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A secret in the remote output must be scrubbed before it reaches the model / audit excerpt.
    captured = _stub_executor(
        monkeypatch, "nginx active\naws_key=AKIA1234567890ABCDEF"
    )
    fake = make_fake_model(
        [
            ai_tool_call(
                "ssh_run",
                {"host": ALLOWED_HOST, "argv": ["systemctl", "status", "nginx"]},
                "call-ssh-1",
            ),
            ai_text("nginx is active on the host."),
        ]
    )
    graph, audit, _ = built_agent(fake)
    ctx = make_context("run-ssh-allow")
    start_run(audit, ctx)

    out = await graph.ainvoke(
        {"messages": [("user", "check nginx on the host")]},
        config=invoke_config(ctx.run_id),
        context=ctx,
    )

    tool_msgs = _tool_messages(out)
    assert tool_msgs, "expected an ssh_run ToolMessage"
    assert tool_msgs[0].name == "ssh_run"
    assert tool_msgs[0].content.startswith("exit_code: 0")
    assert "AKIA1234567890ABCDEF" not in tool_msgs[0].content
    assert "***" in tool_msgs[0].content
    # The remote argv was passed literally to the executor.
    assert captured["argv"] == ["systemctl", "status", "nginx"]

    events = read_events(cfg.audit.dir, ctx.run_id)
    decision = next(e for e in events if e["event_type"] == "decision")
    assert decision["tool"] == "ssh_run"
    assert decision["decision"]["effect"] == "allow"
    assert decision["decision"]["rule_id"] == "ssh-run-read-commands-multimode"
    assert decision["decision"]["channel"] == "ro"
    # The full structured args (incl. host) are captured on the decision event.
    assert decision["args"]["host"] == ALLOWED_HOST
    assert "execution" in event_types(cfg.audit.dir, ctx.run_id)
    assert chain_ok(cfg.audit.dir, ctx.run_id)


async def test_ssh_run_deny_host_not_allowlisted_no_execution(
    built_agent: Any, cfg: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured = _stub_executor(monkeypatch, "should not run")
    fake = make_fake_model(
        [
            ai_tool_call(
                "ssh_run",
                {"host": "evil.example.com", "argv": ["systemctl", "status"]},
                "call-ssh-deny",
            ),
            ai_text("That host is not allowlisted."),
        ]
    )
    graph, audit, _ = built_agent(fake)
    ctx = make_context("run-ssh-deny")
    start_run(audit, ctx)

    out = await graph.ainvoke(
        {"messages": [("user", "check evil host")]},
        config=invoke_config(ctx.run_id),
        context=ctx,
    )

    tool_msgs = _tool_messages(out)
    assert any("Denied by policy" in m.content for m in tool_msgs)
    # Policy denied BEFORE the handler ran: the executor was never called, no execution event.
    assert captured == {}
    types = event_types(cfg.audit.dir, ctx.run_id)
    assert "decision" in types
    assert "execution" not in types
    assert chain_ok(cfg.audit.dir, ctx.run_id)
