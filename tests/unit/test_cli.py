"""CLI (T9): ``version``, ``audit verify`` (good + tampered), and the ``chat`` REPL smoke test.

The REPL is driven with a stub gateway (a canned event stream) injected through the
``opendevops.cli._build_gateway`` seam, so no real model/graph is built; we assert the
rendering does not crash and that a per-turn cost line is printed. ``audit verify`` is exercised
against a real T2 chain (built with :class:`AuditLogger`) and a tampered copy of it.
"""

from __future__ import annotations

import copy
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from opendevops import cli
from opendevops.audit.logger import AuditLogger
from opendevops.audit.schema import EventType
from opendevops.config import AppConfig
from opendevops.gateway import (
    AssistantText,
    Escalation,
    EscalationEvent,
    RunEnd,
    RunResult,
    ToolCall,
    ToolResult,
)

runner = CliRunner()


# -- version -------------------------------------------------------------------------------


def test_version_prints_version() -> None:
    result = runner.invoke(cli.app, ["version"])
    assert result.exit_code == 0
    assert "opendevops" in result.output


def test_help_lists_chat_and_audit() -> None:
    result = runner.invoke(cli.app, ["--help"])
    assert result.exit_code == 0
    assert "chat" in result.output
    assert "audit" in result.output


# -- audit verify --------------------------------------------------------------------------


def _write_good_chain(audit_dir: Path, run_id: str = "run-good") -> None:
    log = AuditLogger(audit_dir)
    log.start_run(
        run_id, principal={"interface": "cli", "user": "sandipan"}, environment="staging"
    )
    log.append(
        run_id,
        EventType.decision,
        tool="run_command",
        tool_call_id="c1",
        decision={
            "effect": "allow",
            "rule_id": "kubectl-read-verbs",
            "reason": "read verb",
            "channel": "ro",
        },
    )
    log.end_run(run_id, summary={"status": "completed"})


def test_audit_verify_ok_on_good_chain(tmp_path: Path) -> None:
    audit_dir = tmp_path / "audit"
    _write_good_chain(audit_dir)
    result = runner.invoke(cli.app, ["audit", "verify", "--dir", str(audit_dir)])
    assert result.exit_code == 0
    assert "OK" in result.output
    assert "run-good" in result.output


def test_audit_verify_fails_on_tampered_chain(tmp_path: Path) -> None:
    audit_dir = tmp_path / "audit"
    _write_good_chain(audit_dir, run_id="run-bad")
    chain = audit_dir / "run-bad.jsonl"
    lines = chain.read_text().splitlines()
    # Corrupt a byte inside the middle (decision) event; recomputation must catch it.
    lines[1] = lines[1].replace("read verb", "tampered")
    chain.write_text("\n".join(lines) + "\n")

    result = runner.invoke(cli.app, ["audit", "verify", "--dir", str(audit_dir)])
    assert result.exit_code == 1
    assert "FAIL" in result.output


# -- chat REPL smoke -----------------------------------------------------------------------


class _StubGateway:
    """A gateway that yields a canned event stream and tracks daily spend (for the cost line)."""

    def __init__(self, events: list[Any], *, daily: float = 1.23) -> None:
        self._events = events
        self._daily = daily
        self.cancelled: list[str] = []

    async def create_thread(self) -> str:
        return "stub-thread"

    async def stream(self, thread_id: str, user_input: str, **_kwargs: Any) -> AsyncIterator[Any]:
        for event in self._events:
            yield event

    async def run(self, *_args: Any, **_kwargs: Any) -> RunResult:  # pragma: no cover - unused
        raise NotImplementedError

    async def cancel(self, thread_id: str) -> None:
        self.cancelled.append(thread_id)

    async def daily_total(self, scope: str = "global") -> float:
        return self._daily


_ESC_ARGV = ["kubectl", "delete", "pod", "x", "-n", "web"]


class _EscalatingStub(_StubGateway):
    """A stub whose first stream SUSPENDS on an escalation; ``stream_resume`` yields the rest."""

    def __init__(self, events: list[Any], resume_events: list[Any]) -> None:
        super().__init__(events)
        self._resume_events = resume_events
        self.resumed: list[tuple[str, list[dict[str, Any]], str]] = []

    async def stream_resume(
        self, thread_id: str, decisions: list[dict[str, Any]], *, approver: str
    ) -> AsyncIterator[Any]:
        self.resumed.append((thread_id, decisions, approver))
        for event in self._resume_events:
            yield event


def _escalation() -> Escalation:
    payload = {
        "action_requests": [{"action": "run_command", "args": {"argv": _ESC_ARGV}}],
        "review_configs": [
            {
                "rule_id": "kubectl-delete-workload-escalate",
                "reason": "destructive delete requires human approval",
                "allowed_decisions": ["approve", "edit", "reject"],
                "timeout_s": 1800,
            }
        ],
    }
    return Escalation(payload=payload, run_id="run-esc", thread_id="stub-thread")


def _escalation_stub() -> _EscalatingStub:
    esc = _escalation()
    suspend_events = [
        ToolCall(name="run_command", argv=_ESC_ARGV),
        EscalationEvent(escalation=esc),
        RunEnd(
            result=RunResult(
                final_text="",
                run_id="run-esc",
                cost_usd_state=0.0,
                cost_usd_authoritative=0.0,
                usage={},
                interrupted=esc,
            )
        ),
    ]
    resume_events = [
        ToolResult(excerpt="pod/x deleted", denied=False),
        AssistantText(text="Deleted the pod."),
        RunEnd(result=RunResult("Deleted the pod.", "run-esc", 0.001, 0.001, {})),
    ]
    return _EscalatingStub(suspend_events, resume_events)


def _canned_events(cost: float = 0.0123) -> list[Any]:
    result = RunResult(
        final_text="Pods look healthy.",
        run_id="run-1",
        cost_usd_state=cost,
        cost_usd_authoritative=cost,
        usage={"input_tokens": 100},
    )
    return [
        ToolCall(name="run_command", argv=["kubectl", "get", "pods", "-n", "web"]),
        ToolResult(excerpt="exit_code: 0\nNAME READY\npod-1 1/1", denied=False),
        AssistantText(text="Pods look healthy."),
        RunEnd(result=result),
    ]


def _valid_cfg(tmp_path: Path, *, allowed_contexts: list[str]) -> AppConfig:
    from graph.helpers import MODELS, budgets  # type: ignore

    return AppConfig.model_validate(
        {
            "targets": {
                "kubernetes": {
                    "kubeconfig_ro": str(tmp_path / "k.yaml"),
                    "kubeconfig_rw": None,
                    "allowed_contexts": allowed_contexts,
                }
            },
            "execution": {
                "cmd_timeout_seconds": 60,
                "output_max_chars": 50000,
                "env_allowlist": ["PATH", "HOME"],
            },
            "audit": {"dir": str(tmp_path / "audit")},
            "policy": {"dir": str(Path.cwd() / "config" / "policy")},
            "principals": {},
            "models": copy.deepcopy(MODELS),
            "budgets": budgets(),
        }
    )


def test_chat_smoke_renders_events_and_cost_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = _valid_cfg(tmp_path, allowed_contexts=["kind-opendevops"])
    monkeypatch.setattr(cli, "load_config", lambda: cfg)
    stub = _StubGateway(_canned_events())
    monkeypatch.setattr(cli, "_build_gateway", lambda _cfg: stub)

    result = runner.invoke(cli.app, ["chat", "--principal", "sandipan"], input="list pods\n/quit\n")

    assert result.exit_code == 0
    # Tool call, assistant text, and the per-turn cost line all rendered.
    assert "run_command" in result.output
    assert "kubectl get pods -n web" in result.output
    assert "Pods look healthy." in result.output
    assert "(run)" in result.output and "(today)" in result.output


def test_chat_cost_command_prints_totals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = _valid_cfg(tmp_path, allowed_contexts=["kind-opendevops"])
    monkeypatch.setattr(cli, "load_config", lambda: cfg)
    stub = _StubGateway(_canned_events(), daily=4.56)
    monkeypatch.setattr(cli, "_build_gateway", lambda _cfg: stub)

    result = runner.invoke(cli.app, ["chat"], input="/cost\n/quit\n")

    assert result.exit_code == 0
    assert "session $" in result.output
    assert "4.56" in result.output


def test_chat_denial_rendered(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = _valid_cfg(tmp_path, allowed_contexts=["kind-opendevops"])
    monkeypatch.setattr(cli, "load_config", lambda: cfg)
    events = [
        ToolCall(name="run_command", argv=["bash", "-c", "id"]),
        ToolResult(excerpt="Denied by policy [interpreters-hard-deny]: no shells.", denied=True,
                   rule_id="interpreters-hard-deny"),
        AssistantText(text="I can't do that."),
        RunEnd(result=RunResult("I can't do that.", "run-d", 0.0, 0.0, {})),
    ]
    monkeypatch.setattr(cli, "_build_gateway", lambda _cfg: _StubGateway(events))

    result = runner.invoke(cli.app, ["chat"], input="run id\n/quit\n")

    assert result.exit_code == 0
    assert "denied" in result.output
    assert "interpreters-hard-deny" in result.output


def test_chat_escalation_approve_renders_and_resumes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = _valid_cfg(tmp_path, allowed_contexts=["kind-opendevops"])
    monkeypatch.setattr(cli, "load_config", lambda: cfg)
    stub = _escalation_stub()
    monkeypatch.setattr(cli, "_build_gateway", lambda _cfg: stub)
    # Force an interactive session so the "approve" line is read (not auto-rejected).
    monkeypatch.setattr(cli, "_stdin_is_interactive", lambda: True)

    result = runner.invoke(
        cli.app, ["chat", "--principal", "sandipan"], input="delete pod x\napprove\n/quit\n"
    )

    assert result.exit_code == 0
    # The red escalation panel rendered (rule + argv), then the resumed stream to completion.
    assert "human approval required" in result.output
    assert "kubectl-delete-workload-escalate" in result.output
    assert "Deleted the pod." in result.output
    # Resumed once with an approve decision, approver = principal.
    assert len(stub.resumed) == 1
    thread_id, decisions, approver = stub.resumed[0]
    assert decisions == [{"type": "approve"}]
    assert approver == "sandipan"


def test_chat_escalation_non_tty_auto_rejects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = _valid_cfg(tmp_path, allowed_contexts=["kind-opendevops"])
    monkeypatch.setattr(cli, "load_config", lambda: cfg)
    stub = _escalation_stub()
    monkeypatch.setattr(cli, "_build_gateway", lambda _cfg: stub)
    # No monkeypatch of _stdin_is_interactive: under CliRunner stdin is not a tty -> auto-reject.

    result = runner.invoke(cli.app, ["chat"], input="delete pod x\n/quit\n")

    assert result.exit_code == 0
    assert len(stub.resumed) == 1
    _thread, decisions, _approver = stub.resumed[0]
    assert decisions == [{"type": "reject", "message": "non-interactive session"}]


def test_chat_refuses_when_no_allowed_contexts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = _valid_cfg(tmp_path, allowed_contexts=[])
    monkeypatch.setattr(cli, "load_config", lambda: cfg)
    # _build_gateway must never be reached.
    monkeypatch.setattr(
        cli, "_build_gateway", lambda _cfg: pytest.fail("gateway built despite empty contexts")
    )

    result = runner.invoke(cli.app, ["chat"])

    assert result.exit_code == 1
    combined = result.output + (result.stderr if hasattr(result, "stderr") else "")
    assert "gen-kubeconfig.sh" in combined or "allowed_contexts" in combined


def test_chat_config_invalid_message(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom() -> AppConfig:
        raise ValueError("bad config file")

    monkeypatch.setattr(cli, "load_config", _boom)

    result = runner.invoke(cli.app, ["chat"])

    assert result.exit_code == 1
    combined = result.output + (result.stderr if hasattr(result, "stderr") else "")
    assert "config INVALID" in combined
