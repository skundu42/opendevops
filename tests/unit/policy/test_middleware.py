"""Tests for PolicyMiddleware — the awrap_tool_call authorize/audit/gate/cache pipeline.

Drives ``awrap_tool_call`` directly with a fake engine, fake handler, and fake runtime (no full
graph needed) and asserts against a *real* ``AuditLogger`` run file. Also pins the CRITICAL
state-reducer composition: ``DevOpsState`` must accumulate ``run_cost_usd`` / ``run_usage`` /
``tool_results_cache`` rather than replace them.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from langchain.agents.middleware import ToolCallRequest
from langchain_core.messages import ToolMessage
from langgraph.types import Command

from opendevops.audit import AuditLogger, verify_run_file
from opendevops.context import AgentContext
from opendevops.policy.loader import LoadedPolicy
from opendevops.policy.middleware import PolicyMiddleware, _cache_key
from opendevops.policy.schema import Decision, ToolCallCtx
from opendevops.tools.run_command import EXEC_META_KEY, current_decision

MODEL = "anthropic:claude-opus-4-8"


# --------------------------------------------------------------------------------------
# fixtures / doubles
# --------------------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_contextvars() -> Any:
    """Keep the run_command decision gate from leaking between tests."""
    dtok = current_decision.set(None)
    yield
    current_decision.reset(dtok)


class FakeEngine:
    """A stand-in PolicyEngine: returns a canned Decision (or raises to test belt-and-braces)."""

    def __init__(self, decision: Decision | None = None, *, raises: bool = False) -> None:
        self._decision = decision
        self._raises = raises
        self.calls = 0
        self.last_ctx: ToolCallCtx | None = None

    async def decide(self, ctx: ToolCallCtx) -> Decision:
        self.calls += 1
        self.last_ctx = ctx
        if self._raises:
            raise RuntimeError("engine boom")
        assert self._decision is not None
        return self._decision


_EXEC_META: dict[str, Any] = {
    "stdout_sha256": "deadbeef",
    "duration_ms": 7,
    "exit_code": 0,
    "truncated": False,
    "scrub_count": 0,
}


def _tag_exec_meta(command: Command[Any], meta: dict[str, Any] | None = None) -> None:
    """Tag the ToolMessage inside a Command's update with the exec-meta transport key."""
    payload = meta if meta is not None else _EXEC_META
    for message in command.update.get("messages", []):
        if isinstance(message, ToolMessage):
            message.additional_kwargs[EXEC_META_KEY] = dict(payload)


class SpyHandler:
    """Records invocation + the argv/decision it saw, and models run_command's return channel.

    When ``sets_exec_meta`` is set, it tags the ToolMessage it returns (or the ToolMessage inside
    ``return_command``) with ``additional_kwargs[EXEC_META_KEY]`` — exactly how run_command hands
    its per-exec audit facts to PolicyMiddleware. A built-in tool leaves the tag off (no exec).

    ``exec_meta_overrides`` merges on top of the base ``_EXEC_META`` fixture (e.g. to set
    ``staged_files`` / ``stdout_sha256`` for a staging-bridge test) without every call site
    needing to build the full meta dict by hand.
    """

    def __init__(
        self,
        *,
        sets_exec_meta: bool,
        content: str = "exit_code: 0\nok",
        exec_meta_overrides: dict[str, Any] | None = None,
    ) -> None:
        self._sets_exec_meta = sets_exec_meta
        self._content = content
        self._exec_meta_overrides = exec_meta_overrides
        self.calls = 0
        self.seen_decision: Any = "UNSET"
        self.seen_argv: Any = "UNSET"
        self.return_command: Command[Any] | None = None

    def _exec_meta(self) -> dict[str, Any]:
        meta = dict(_EXEC_META)
        if self._exec_meta_overrides:
            meta.update(self._exec_meta_overrides)
        return meta

    async def __call__(self, request: ToolCallRequest) -> ToolMessage | Command[Any]:
        self.calls += 1
        self.seen_decision = current_decision.get()
        self.seen_argv = request.tool_call["args"].get("argv")
        if self.return_command is not None:
            if self._sets_exec_meta:
                _tag_exec_meta(self.return_command, self._exec_meta())
            return self.return_command
        tool_call_id = request.tool_call["id"]
        extra = {EXEC_META_KEY: self._exec_meta()} if self._sets_exec_meta else {}
        return ToolMessage(
            content=self._content, tool_call_id=tool_call_id, additional_kwargs=extra
        )


@dataclass
class FakeRuntime:
    context: Any = None


def _context(run_id: str = "run-1", environment: str = "staging") -> AgentContext:
    return AgentContext(
        principal="sandipan",
        interface="cli",
        environment=environment,
        budget_profile="interactive",
        run_id=run_id,
    )


def _request(
    tool_name: str,
    args: dict[str, Any],
    tool_call_id: str,
    *,
    state: dict[str, Any] | None = None,
    context: AgentContext | None = None,
) -> ToolCallRequest:
    return ToolCallRequest(
        tool_call={"id": tool_call_id, "name": tool_name, "args": args},
        tool=None,
        state=state if state is not None else {},
        runtime=FakeRuntime(context=context if context is not None else _context()),
    )


def _loaded(tool_family: dict[str, str | None] | None = None) -> LoadedPolicy:
    return LoadedPolicy(
        files={},
        rules_by_id={},
        flags_allowed_merged={},
        tool_family_by_rule=tool_family or {"kubectl-get": "kubectl"},
        policy_version="sha256:test-policy",
    )


def _mw(engine: Any, audit: AuditLogger, loaded: LoadedPolicy | None = None) -> PolicyMiddleware:
    return PolicyMiddleware(
        engine=engine, audit=audit, loaded=loaded or _loaded(), model=MODEL
    )


def _started_logger(tmp_path: Path, run_id: str = "run-1") -> AuditLogger:
    logger = AuditLogger(tmp_path)
    logger.start_run(
        run_id,
        principal={"interface": "cli", "user": "sandipan"},
        environment="staging",
        policy_version="sha256:test-policy",
    )
    return logger


def _events(tmp_path: Path, run_id: str = "run-1") -> list[dict[str, Any]]:
    path = tmp_path / f"{run_id}.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()]


def _types(tmp_path: Path, run_id: str = "run-1") -> list[str]:
    return [e["event_type"] for e in _events(tmp_path, run_id)]


def _expected_cache(
    tool_name: str, args: dict[str, Any], content: str, *, run_id: str = "run-1"
) -> dict[str, str]:
    return {_cache_key(run_id, "call_1", tool_name, args): content}


# --------------------------------------------------------------------------------------
# allow path (run_command)
# --------------------------------------------------------------------------------------


async def test_allow_sets_gate_audits_both_and_caches(tmp_path: Path) -> None:
    engine = FakeEngine(Decision.allow("kubectl-get", "read-only kubectl", channel="ro"))
    handler = SpyHandler(sets_exec_meta=True)
    audit = _started_logger(tmp_path)
    mw = _mw(engine, audit)
    argv = ["kubectl", "get", "pods"]
    req = _request("run_command", {"argv": argv, "timeout_s": 10}, "call_1")

    result = await mw.awrap_tool_call(req, handler)

    # the decision contextvar was set DURING the handler (gate) and reset afterwards
    assert handler.calls == 1
    assert handler.seen_decision is not None
    assert handler.seen_decision.tool_call_id == "call_1"
    assert handler.seen_decision.channel == "ro"
    assert handler.seen_decision.tool_family == "kubectl"
    assert handler.seen_decision.argv == ("kubectl", "get", "pods")
    assert current_decision.get() is None  # reset after the call

    # both a decision and an execution event landed in the run file
    assert _types(tmp_path) == ["run_started", "decision", "execution"]
    assert verify_run_file(tmp_path / "run-1.jsonl").ok is True

    # the result is a Command that both delivers the ToolMessage and persists the cache entry
    assert isinstance(result, Command)
    assert result.update["messages"][0].content == "exit_code: 0\nok"
    assert result.update["tool_results_cache"] == _expected_cache(
        "run_command", {"argv": argv, "timeout_s": 10}, "exit_code: 0\nok"
    )
    # the exec-meta transport key was stripped before the message reached the model/cache
    assert EXEC_META_KEY not in result.update["messages"][0].additional_kwargs


async def test_allow_second_call_same_id_is_served_from_cache(tmp_path: Path) -> None:
    engine = FakeEngine(Decision.allow("kubectl-get", "ro", channel="ro"))
    handler = SpyHandler(sets_exec_meta=True)
    audit = _started_logger(tmp_path)
    mw = _mw(engine, audit)
    argv = ["kubectl", "get", "pods"]

    first = await mw.awrap_tool_call(
        _request("run_command", {"argv": argv}, "call_1"), handler
    )
    assert isinstance(first, Command)
    cache = first.update["tool_results_cache"]

    # simulate the graph having applied the cache update into state, then re-invoke the node
    second = await mw.awrap_tool_call(
        _request("run_command", {"argv": argv}, "call_1", state={"tool_results_cache": cache}),
        handler,
    )

    # neither the engine nor the handler ran again — the cache short-circuited everything
    assert engine.calls == 1
    assert handler.calls == 1
    assert isinstance(second, ToolMessage)
    assert second.content == "exit_code: 0\nok"
    assert second.tool_call_id == "call_1"


async def test_same_call_id_on_later_run_cannot_replay_stale_cache(tmp_path: Path) -> None:
    """Checkpoint state survives turns, but cache entries are bound to run + exact payload."""
    engine = FakeEngine(Decision.allow("kubectl-get", "ro", channel="ro"))
    handler = SpyHandler(sets_exec_meta=True, content="fresh")
    audit = _started_logger(tmp_path, "run-1")
    audit.start_run(
        "run-2",
        principal={"interface": "cli", "user": "sandipan"},
        environment="staging",
        policy_version="sha256:test-policy",
    )
    mw = _mw(engine, audit)
    stale_args = {"argv": ["kubectl", "get", "pods"]}
    stale = _expected_cache("run_command", stale_args, "stale", run_id="run-1")
    fresh_args = {"argv": ["kubectl", "get", "services"]}

    result = await mw.awrap_tool_call(
        _request(
            "run_command",
            fresh_args,
            "call_1",
            state={"tool_results_cache": stale},
            context=_context(run_id="run-2"),
        ),
        handler,
    )

    assert engine.calls == 1
    assert handler.calls == 1
    assert isinstance(result, Command)
    assert result.update["tool_results_cache"] == _expected_cache(
        "run_command", fresh_args, "fresh", run_id="run-2"
    )


# --------------------------------------------------------------------------------------
# deny path
# --------------------------------------------------------------------------------------


async def test_deny_returns_error_message_decision_only_nothing_cached(tmp_path: Path) -> None:
    engine = FakeEngine(Decision.deny("kubectl-delete-deny", "mutation not allowed"))
    handler = SpyHandler(sets_exec_meta=True)
    audit = _started_logger(tmp_path)
    mw = _mw(engine, audit)
    req = _request("run_command", {"argv": ["kubectl", "delete", "pod", "x"]}, "call_1")

    result = await mw.awrap_tool_call(req, handler)

    assert handler.calls == 0  # never executed
    assert current_decision.get() is None  # gate never set
    assert isinstance(result, ToolMessage)
    assert result.status == "error"
    assert "kubectl-delete-deny" in result.content
    assert "mutation not allowed" in result.content
    # decision event only, no execution event
    assert _types(tmp_path) == ["run_started", "decision"]
    # a plain ToolMessage (no Command) => nothing persisted to the cache channel
    assert not isinstance(result, Command)


# --------------------------------------------------------------------------------------
# rewrite path
# --------------------------------------------------------------------------------------


async def test_rewrite_executes_rewritten_argv_and_audits_it(tmp_path: Path) -> None:
    rewritten = ["kubectl", "get", "pods", "-o", "wide"]
    engine = FakeEngine(
        Decision.rewrite(
            "kubectl-force-wide", "add -o wide", rewritten_argv=rewritten, channel="ro"
        )
    )
    handler = SpyHandler(sets_exec_meta=True)
    audit = _started_logger(tmp_path)
    mw = _mw(engine, audit, _loaded({"kubectl-force-wide": "kubectl"}))
    req = _request("run_command", {"argv": ["kubectl", "get", "pods"]}, "call_1")

    await mw.awrap_tool_call(req, handler)

    # the handler received the REWRITTEN argv, and the gate authorized the rewritten argv
    assert handler.seen_argv == rewritten
    assert handler.seen_decision.argv == tuple(rewritten)

    decision_event = next(e for e in _events(tmp_path) if e["event_type"] == "decision")
    assert decision_event["decision"]["effect"] == "rewrite"
    assert decision_event["decision"]["rule_id"] == "kubectl-force-wide"
    assert decision_event["decision"]["rewritten_argv"] == rewritten
    # the recorded request args still show what the model asked for (original argv)
    assert decision_event["args"]["argv"] == ["kubectl", "get", "pods"]


# --------------------------------------------------------------------------------------
# escalate path (interrupt + resume dispatch)
# --------------------------------------------------------------------------------------
#
# The real interrupt()/suspend/resume mechanics are exercised end-to-end at the graph tier
# (tests/graph/test_graph_escalation.py — the replay contract). Here we monkeypatch the module-level
# ``interrupt`` to return a canned resume value, which is exactly what langgraph delivers to the
# call on the RESUME node re-execution — letting us unit-test the approve/edit/reject DISPATCH and
# the escalation/resolution audit events without a checkpointer.


def _patch_interrupt(monkeypatch: Any, resume_value: Any) -> list[dict[str, Any]]:
    """Patch ``middleware.interrupt`` to return ``resume_value``; return the captured payloads."""
    import opendevops.policy.middleware as mw_module

    captured: list[dict[str, Any]] = []

    def _fake_interrupt(payload: dict[str, Any]) -> Any:
        captured.append(payload)
        return resume_value

    monkeypatch.setattr(mw_module, "interrupt", _fake_interrupt)
    return captured


def _delete_loaded() -> LoadedPolicy:
    from opendevops.policy.schema import Escalation, Match, Rule

    rule = Rule(
        id="kubectl-delete-workload-escalate",
        match=Match(),
        effect="escalate",
        channel="rw",
        environments=["staging"],
        escalation=Escalation(timeout_s=1800, on_timeout="deny"),
        reason="destructive delete requires human approval",
    )
    return LoadedPolicy(
        files={},
        rules_by_id={rule.id: rule},
        flags_allowed_merged={},
        tool_family_by_rule={rule.id: "kubectl"},
        policy_version="sha256:test-policy",
    )


async def test_escalate_approve_executes_once_and_audits_escalation_resolution(
    tmp_path: Path, monkeypatch: Any
) -> None:
    # The engine's escalate Decision carries NO channel; the middleware resolves it from the
    # escalate rule (loaded.rules_by_id -> channel "rw") for the approved execution.
    engine = FakeEngine(
        Decision.escalate(
            "kubectl-delete-workload-escalate", "destructive delete requires human approval"
        )
    )
    handler = SpyHandler(sets_exec_meta=True)
    audit = _started_logger(tmp_path)
    mw = _mw(engine, audit, _delete_loaded())
    captured = _patch_interrupt(
        monkeypatch, {"decisions": [{"type": "approve", "approver": "alice"}]}
    )
    req = _request("run_command", {"argv": ["kubectl", "delete", "pod", "x"]}, "call_1")

    result = await mw.awrap_tool_call(req, handler)

    # The interrupt payload was the deepagents-shaped review envelope.
    assert captured and captured[0]["action_requests"][0]["action"] == "run_command"
    assert captured[0]["review_configs"][0]["timeout_s"] == 1800
    # Approved => the tool executed exactly once via the allow path, gated rw.
    assert handler.calls == 1
    assert handler.seen_decision.channel == "rw"
    assert isinstance(result, Command)
    assert result.update["tool_results_cache"] == _expected_cache(
        "run_command", {"argv": ["kubectl", "delete", "pod", "x"]}, handler._content
    )
    # Full audit trail: decision(escalate) -> escalation -> resolution(alice) -> execution.
    assert _types(tmp_path) == [
        "run_started",
        "decision",
        "escalation",
        "resolution",
        "execution",
    ]
    resolution = next(e for e in _events(tmp_path) if e["event_type"] == "resolution")
    assert resolution["approver"] == "alice"
    assert resolution["summary"]["type"] == "approve"


async def test_escalate_reject_denies_and_audits_resolution(
    tmp_path: Path, monkeypatch: Any
) -> None:
    engine = FakeEngine(
        Decision.escalate("kubectl-delete-workload-escalate", "needs approval")
    )
    handler = SpyHandler(sets_exec_meta=True)
    audit = _started_logger(tmp_path)
    mw = _mw(engine, audit, _delete_loaded())
    _patch_interrupt(
        monkeypatch,
        {"decisions": [{"type": "reject", "message": "not now", "approver": "bob"}]},
    )
    req = _request("run_command", {"argv": ["kubectl", "delete", "pod", "x"]}, "call_1")

    result = await mw.awrap_tool_call(req, handler)

    assert handler.calls == 0  # never executed
    assert isinstance(result, ToolMessage)
    assert result.status == "error"
    assert "kubectl-delete-workload-escalate" in result.content
    assert "not now" in result.content
    assert not isinstance(result, Command)  # nothing cached on a reject
    assert _types(tmp_path) == ["run_started", "decision", "escalation", "resolution"]
    resolution = next(e for e in _events(tmp_path) if e["event_type"] == "resolution")
    assert resolution["approver"] == "bob"
    assert resolution["summary"]["type"] == "reject"


async def test_escalate_edit_reauthorizes_from_scratch_and_can_deny(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """An edited argv re-enters the pipeline (decided fresh); a denied edit comes back denied."""

    class _EditEngine:
        """Escalate the original delete, then DENY the edited argv on the re-entry decide."""

        def __init__(self) -> None:
            self.calls = 0

        async def decide(self, ctx: ToolCallCtx) -> Decision:
            self.calls += 1
            if self.calls == 1:
                return Decision.escalate("kubectl-delete-workload-escalate", "needs approval")
            # The re-entry sees the edited argv and denies it (re-authorized from scratch).
            return Decision.deny("kubectl-mutate-no-force", "force/cascade not allowed")

    engine = _EditEngine()
    handler = SpyHandler(sets_exec_meta=True)
    audit = _started_logger(tmp_path)
    mw = _mw(engine, audit, _delete_loaded())
    _patch_interrupt(
        monkeypatch,
        {
            "decisions": [
                {
                    "type": "edit",
                    "args": {"argv": ["kubectl", "delete", "pod", "x", "--force"]},
                    "approver": "carol",
                }
            ]
        },
    )
    req = _request("run_command", {"argv": ["kubectl", "delete", "pod", "x"]}, "call_1")

    result = await mw.awrap_tool_call(req, handler)

    # Re-decided from scratch (two decide calls) and the edited argv came back denied.
    assert engine.calls == 2
    assert handler.calls == 0
    assert isinstance(result, ToolMessage)
    assert result.status == "error"
    assert "kubectl-mutate-no-force" in result.content


# --------------------------------------------------------------------------------------
# fail-closed: engine raising
# --------------------------------------------------------------------------------------


async def test_engine_raising_fails_closed_with_policy_error_event(tmp_path: Path) -> None:
    engine = FakeEngine(raises=True)
    handler = SpyHandler(sets_exec_meta=True)
    audit = _started_logger(tmp_path)
    mw = _mw(engine, audit)
    req = _request("run_command", {"argv": ["kubectl", "get", "pods"]}, "call_1")

    result = await mw.awrap_tool_call(req, handler)

    assert handler.calls == 0
    assert isinstance(result, ToolMessage)
    assert result.status == "error"
    assert "__fail_closed__" in result.content
    assert "policy_error" in _types(tmp_path)


# --------------------------------------------------------------------------------------
# fail-closed: audit logger failure (append to an un-started run)
# --------------------------------------------------------------------------------------


async def test_audit_failure_fails_closed_without_crashing(tmp_path: Path) -> None:
    engine = FakeEngine(Decision.allow("kubectl-get", "ro", channel="ro"))
    handler = SpyHandler(sets_exec_meta=True)
    audit = AuditLogger(tmp_path)  # NOTE: start_run never called => append raises
    mw = _mw(engine, audit)
    req = _request("run_command", {"argv": ["kubectl", "get", "pods"]}, "call_1")

    result = await mw.awrap_tool_call(req, handler)

    # no crash into the graph; the tool never executed
    assert handler.calls == 0
    assert isinstance(result, ToolMessage)
    assert result.status == "error"
    assert "__fail_closed__" in result.content
    # the best-effort policy_error append also failed (un-started run) but was swallowed
    assert not (tmp_path / "run-1.jsonl").exists()


async def test_missing_run_id_fails_closed(tmp_path: Path) -> None:
    engine = FakeEngine(Decision.allow("kubectl-get", "ro", channel="ro"))
    handler = SpyHandler(sets_exec_meta=True)
    audit = _started_logger(tmp_path)
    mw = _mw(engine, audit)
    # a context whose run_id is empty => cannot correlate audit => fail closed
    bad_ctx = AgentContext(
        principal="p", interface="cli", environment="staging", budget_profile="x", run_id=""
    )
    req = _request("run_command", {"argv": ["kubectl", "get", "pods"]}, "call_1", context=bad_ctx)

    result = await mw.awrap_tool_call(req, handler)

    assert handler.calls == 0
    assert isinstance(result, ToolMessage)
    assert "__fail_closed__" in result.content


async def test_missing_environment_fails_closed(tmp_path: Path) -> None:
    """A context with no environment must NOT default to 'staging' (which would enable the staging
    allow set): it fails closed like a missing run_id, deny + best-effort policy_error."""
    engine = FakeEngine(Decision.allow("kubectl-get", "ro", channel="ro"))
    handler = SpyHandler(sets_exec_meta=True)
    audit = _started_logger(tmp_path)
    mw = _mw(engine, audit)
    # empty environment => no safe overlay to apply => fail closed (before engine.decide runs).
    bad_ctx = AgentContext(
        principal="p", interface="cli", environment="", budget_profile="x", run_id="run-1"
    )
    req = _request("run_command", {"argv": ["kubectl", "get", "pods"]}, "call_1", context=bad_ctx)

    result = await mw.awrap_tool_call(req, handler)

    assert handler.calls == 0
    assert isinstance(result, ToolMessage)
    assert "__fail_closed__" in result.content
    # the run_id is present, so the best-effort policy_error audit event IS written.
    assert "policy_error" in _types(tmp_path)


# --------------------------------------------------------------------------------------
# built-in FS tool: decision event only, no execution event, no gate
# --------------------------------------------------------------------------------------


async def test_builtin_fs_tool_decision_only_no_execution_event(tmp_path: Path) -> None:
    engine = FakeEngine(
        Decision.allow("__builtin_fs__", "deepagents built-in", channel="ro")
    )
    # a built-in tool does NOT set last_exec_meta
    handler = SpyHandler(sets_exec_meta=False)
    audit = _started_logger(tmp_path)
    mw = _mw(engine, audit)
    req = _request("read_file", {"file_path": "/output/x.txt"}, "call_1")

    result = await mw.awrap_tool_call(req, handler)

    assert handler.calls == 1
    # the exec gate is only for run_command; a built-in sees no decision contextvar
    assert handler.seen_decision is None
    # decision event written, execution event NOT (no exec_meta, output is graph state)
    assert _types(tmp_path) == ["run_started", "decision"]
    # still cached (absorbs resume re-execution), keyed by tool_call_id
    assert isinstance(result, Command)
    assert result.update["tool_results_cache"] == _expected_cache(
        "read_file", {"file_path": "/output/x.txt"}, "exit_code: 0\nok"
    )


async def test_builtin_tool_returning_command_passes_files_through_and_caches(
    tmp_path: Path,
) -> None:
    """A tool that returns a Command (e.g. a files update) is passed through, cache merged in."""
    engine = FakeEngine(Decision.allow("__builtin_fs__", "builtin", channel="ro"))
    handler = SpyHandler(sets_exec_meta=False)
    handler.return_command = Command(
        update={
            "files": {"/output/big.txt": {"content": "ZZZ"}},
            "messages": [ToolMessage(content="wrote file", tool_call_id="call_1")],
        }
    )
    audit = _started_logger(tmp_path)
    mw = _mw(engine, audit)
    req = _request("write_file", {"file_path": "/output/big.txt", "content": "ZZZ"}, "call_1")

    result = await mw.awrap_tool_call(req, handler)

    assert isinstance(result, Command)
    # files + messages preserved unchanged; cache added additively
    assert result.update["files"] == {"/output/big.txt": {"content": "ZZZ"}}
    assert result.update["messages"][0].content == "wrote file"
    assert result.update["tool_results_cache"] == _expected_cache(
        "write_file",
        {"file_path": "/output/big.txt", "content": "ZZZ"},
        "wrote file",
    )


# --------------------------------------------------------------------------------------
# run_command Command spill: files pass-through + staged_files in the execution audit
# --------------------------------------------------------------------------------------


async def test_run_command_spill_records_staged_file_and_passes_command_through(
    tmp_path: Path,
) -> None:
    engine = FakeEngine(Decision.allow("kubectl-get", "ro", channel="ro"))
    handler = SpyHandler(sets_exec_meta=True)
    spill_path = "/output/call_1.txt"
    spill_msg = ToolMessage(content="exit_code: 0\n...truncated...", tool_call_id="call_1")
    handler.return_command = Command(
        update={
            "files": {spill_path: {"content": "A" * 5000}},
            "messages": [spill_msg],
        }
    )
    audit = _started_logger(tmp_path)
    mw = _mw(engine, audit)
    req = _request("run_command", {"argv": ["kubectl", "get", "pods"]}, "call_1")

    result = await mw.awrap_tool_call(req, handler)

    assert isinstance(result, Command)
    assert spill_path in result.update["files"]
    assert next(iter(result.update["tool_results_cache"].values())).startswith("exit_code: 0")

    exec_event = next(e for e in _events(tmp_path) if e["event_type"] == "execution")
    assert exec_event["execution"]["staged_files"] == [
        {"path": spill_path, "sha256": "deadbeef"}
    ]
    assert exec_event["execution"]["stdout_sha256"] == "deadbeef"
    assert exec_event["args"]["scrub_count"] == 0


# --------------------------------------------------------------------------------------
# Staging bridge -> audit link: meta["staged_files"] must reach execution.staged_files
# --------------------------------------------------------------------------------------


async def test_staged_files_from_exec_meta_land_in_execution_audit(tmp_path: Path) -> None:
    """A staged apply's manifest ref (``meta['staged_files']``) reaches the execution audit event.

    Drives a staged apply end-to-end through PolicyMiddleware: the handler models run_command
    tagging its returned ToolMessage with ``EXEC_META`` including ``staged_files`` (the
    staging bridge's record of the manifest it materialized), and asserts that entry lands,
    unmodified, in the written execution audit event's ``execution.staged_files``. Regression
    guard: deleting the ``meta["staged_files"]`` concat in
    ``PolicyMiddleware._staged_files`` would leave every *other* test in this file green.
    """
    engine = FakeEngine(Decision.allow("kubectl-apply", "apply manifest", channel="rw"))
    staged_entry = {"path": "/manifests/deploy.yaml", "sha256": "abc123deadbeef"}
    handler = SpyHandler(
        sets_exec_meta=True, exec_meta_overrides={"staged_files": [staged_entry]}
    )
    audit = _started_logger(tmp_path)
    mw = _mw(engine, audit, _loaded({"kubectl-apply": "kubectl"}))
    argv = ["kubectl", "apply", "-f", "/manifests/deploy.yaml"]
    req = _request("run_command", {"argv": argv}, "call_1")

    result = await mw.awrap_tool_call(req, handler)

    assert isinstance(result, Command)
    exec_event = next(e for e in _events(tmp_path) if e["event_type"] == "execution")
    assert exec_event["execution"]["staged_files"] == [staged_entry]


async def test_staged_files_concat_meta_and_spill_have_distinct_entries(tmp_path: Path) -> None:
    """A staged manifest ref AND a truncation spill both land in staged_files, distinctly.

    Command return with a ``files`` update (the truncation spill) AND ``meta["staged_files"]``
    (the applied manifest) set together: both entries must be present with distinct paths/shas
    — the applied-manifest entry is not overwritten or dropped by the spill entry, or vice versa.
    """
    engine = FakeEngine(Decision.allow("kubectl-apply", "apply manifest", channel="rw"))
    staged_entry = {"path": "/manifests/deploy.yaml", "sha256": "manifest-sha-abc"}
    spill_path = "/output/call_1.txt"
    handler = SpyHandler(
        sets_exec_meta=True,
        exec_meta_overrides={
            "staged_files": [staged_entry],
            "stdout_sha256": "spill-sha-xyz",
        },
    )
    spill_msg = ToolMessage(content="exit_code: 0\n...truncated...", tool_call_id="call_1")
    handler.return_command = Command(
        update={
            "files": {spill_path: {"content": "A" * 5000}},
            "messages": [spill_msg],
        }
    )
    audit = _started_logger(tmp_path)
    mw = _mw(engine, audit, _loaded({"kubectl-apply": "kubectl"}))
    argv = ["kubectl", "apply", "-f", "/manifests/deploy.yaml"]
    req = _request("run_command", {"argv": argv}, "call_1")

    result = await mw.awrap_tool_call(req, handler)

    assert isinstance(result, Command)
    exec_event = next(e for e in _events(tmp_path) if e["event_type"] == "execution")
    staged = exec_event["execution"]["staged_files"]
    assert staged == [staged_entry, {"path": spill_path, "sha256": "spill-sha-xyz"}]
    assert {f["path"] for f in staged} == {"/manifests/deploy.yaml", spill_path}
    assert {f["sha256"] for f in staged} == {"manifest-sha-abc", "spill-sha-xyz"}


# --------------------------------------------------------------------------------------
# Dry-run recording: a successful server dry-run records staged shas into dry_run_ok
# --------------------------------------------------------------------------------------


_STAGED = {"path": "/manifests/deploy.yaml", "sha256": "manifest-sha-abc"}
_SERVER_DRY_RUN_ARGV = ["kubectl", "apply", "-f", "/manifests/deploy.yaml", "--dry-run=server"]


async def test_successful_server_dry_run_records_dry_run_ok(tmp_path: Path) -> None:
    """A rewrite to --dry-run=server that exits 0 records each staged manifest sha as True."""
    engine = FakeEngine(
        Decision.rewrite(
            "force-server-dry-run-first",
            "inject server dry-run",
            rewritten_argv=_SERVER_DRY_RUN_ARGV,
            channel="rw",
        )
    )
    handler = SpyHandler(
        sets_exec_meta=True, exec_meta_overrides={"staged_files": [_STAGED], "exit_code": 0}
    )
    audit = _started_logger(tmp_path)
    mw = _mw(engine, audit, _loaded({"force-server-dry-run-first": "kubectl"}))
    # the model asked for a bare apply; the engine rewrote it to --dry-run=server
    bare = ["kubectl", "apply", "-f", "/manifests/deploy.yaml"]
    req = _request("run_command", {"argv": bare}, "call_1")

    result = await mw.awrap_tool_call(req, handler)

    assert handler.seen_argv == _SERVER_DRY_RUN_ARGV  # executed the rewritten (server dry-run) argv
    assert isinstance(result, Command)
    # Keys are RUN-SCOPED (``{run_id}:{sha}``); the default context's run_id is "run-1".
    assert result.update["dry_run_ok"] == {"run-1:manifest-sha-abc": True}
    # the cache entry rides on the same Command update
    assert result.update["tool_results_cache"] == _expected_cache(
        "run_command", {"argv": bare}, handler._content
    )


async def test_explicit_server_dry_run_also_records(tmp_path: Path) -> None:
    """A model-supplied --dry-run=server (no rewrite) that exits 0 records too."""
    engine = FakeEngine(Decision.allow("kubectl-apply", "apply", channel="rw"))
    handler = SpyHandler(
        sets_exec_meta=True, exec_meta_overrides={"staged_files": [_STAGED], "exit_code": 0}
    )
    audit = _started_logger(tmp_path)
    mw = _mw(engine, audit, _loaded({"kubectl-apply": "kubectl"}))
    req = _request("run_command", {"argv": _SERVER_DRY_RUN_ARGV}, "call_1")

    result = await mw.awrap_tool_call(req, handler)

    assert isinstance(result, Command)
    assert result.update["dry_run_ok"] == {"run-1:manifest-sha-abc": True}


async def test_non_dry_run_success_records_nothing(tmp_path: Path) -> None:
    """A successful apply that is NOT a server dry-run (--dry-run=none) records no dry_run_ok."""
    engine = FakeEngine(Decision.allow("kubectl-apply", "apply", channel="rw"))
    handler = SpyHandler(
        sets_exec_meta=True, exec_meta_overrides={"staged_files": [_STAGED], "exit_code": 0}
    )
    audit = _started_logger(tmp_path)
    mw = _mw(engine, audit, _loaded({"kubectl-apply": "kubectl"}))
    argv = ["kubectl", "apply", "-f", "/manifests/deploy.yaml", "--dry-run=none"]
    req = _request("run_command", {"argv": argv}, "call_1")

    result = await mw.awrap_tool_call(req, handler)

    assert isinstance(result, Command)
    assert "dry_run_ok" not in result.update


async def test_failed_server_dry_run_records_nothing(tmp_path: Path) -> None:
    """A server dry-run that exits non-zero must NOT record (an unvalidated manifest)."""
    engine = FakeEngine(
        Decision.rewrite(
            "force-server-dry-run-first",
            "inject server dry-run",
            rewritten_argv=_SERVER_DRY_RUN_ARGV,
            channel="rw",
        )
    )
    handler = SpyHandler(
        sets_exec_meta=True,
        content="exit_code: 1\nerror validating",
        exec_meta_overrides={"staged_files": [_STAGED], "exit_code": 1},
    )
    audit = _started_logger(tmp_path)
    mw = _mw(engine, audit, _loaded({"force-server-dry-run-first": "kubectl"}))
    bare = ["kubectl", "apply", "-f", "/manifests/deploy.yaml"]
    req = _request("run_command", {"argv": bare}, "call_1")

    result = await mw.awrap_tool_call(req, handler)

    assert isinstance(result, Command)
    assert "dry_run_ok" not in result.update


async def test_run_command_ctx_carries_files_and_dry_run_ok_from_state(tmp_path: Path) -> None:
    """For run_command, the ctx surfaces the virtual-FS files + recorded dry_run_ok from state."""
    engine = FakeEngine(Decision.allow("kubectl-apply", "apply", channel="rw"))
    handler = SpyHandler(sets_exec_meta=True)
    audit = _started_logger(tmp_path)
    mw = _mw(engine, audit, _loaded({"kubectl-apply": "kubectl"}))
    state = {
        "files": {"/manifests/deploy.yaml": {"content": "yaml"}},
        "dry_run_ok": {"manifest-sha-abc": True},
    }
    req = _request(
        "run_command",
        {"argv": ["kubectl", "apply", "-f", "/manifests/deploy.yaml", "--dry-run=none"]},
        "call_1",
        state=state,
    )

    await mw.awrap_tool_call(req, handler)

    assert engine.last_ctx is not None
    assert dict(engine.last_ctx.files or {}) == state["files"]
    assert dict(engine.last_ctx.dry_run_ok or {}) == state["dry_run_ok"]


async def test_non_run_command_ctx_leaves_files_none(tmp_path: Path) -> None:
    """A non-run_command tool call carries no files / dry_run_ok on its ctx (populated lazily)."""
    engine = FakeEngine(Decision.allow("__builtin_fs__", "builtin", channel="ro"))
    handler = SpyHandler(sets_exec_meta=False)
    audit = _started_logger(tmp_path)
    mw = _mw(engine, audit)
    state = {"files": {"/x": {"content": "y"}}, "dry_run_ok": {"s": True}}
    req = _request("read_file", {"file_path": "/x"}, "call_1", state=state)

    await mw.awrap_tool_call(req, handler)

    assert engine.last_ctx is not None
    assert engine.last_ctx.files is None
    assert engine.last_ctx.dry_run_ok is None


# --------------------------------------------------------------------------------------
# decision event provenance fields
# --------------------------------------------------------------------------------------


async def test_decision_event_carries_provenance(tmp_path: Path) -> None:
    engine = FakeEngine(Decision.allow("kubectl-get", "ro", channel="ro"))
    handler = SpyHandler(sets_exec_meta=True)
    audit = _started_logger(tmp_path)
    mw = _mw(engine, audit)
    req = _request("run_command", {"argv": ["kubectl", "get", "pods"]}, "call_1")

    await mw.awrap_tool_call(req, handler)

    dec = next(e for e in _events(tmp_path) if e["event_type"] == "decision")
    assert dec["model"] == MODEL
    assert dec["policy_version"] == "sha256:test-policy"
    assert dec["principal"] == {"interface": "cli", "user": "sandipan"}
    assert dec["environment"] == "staging"
    assert dec["tool"] == "run_command"
    assert dec["tool_call_id"] == "call_1"
    assert dec["decision"]["channel"] == "ro"


async def test_deny_decision_records_channel_none(tmp_path: Path) -> None:
    engine = FakeEngine(Decision.deny("some-deny", "nope"))
    handler = SpyHandler(sets_exec_meta=False)
    audit = _started_logger(tmp_path)
    mw = _mw(engine, audit)
    req = _request("run_command", {"argv": ["rm", "-rf", "/"]}, "call_1")

    await mw.awrap_tool_call(req, handler)

    dec = next(e for e in _events(tmp_path) if e["event_type"] == "decision")
    assert dec["decision"]["channel"] == "none"


# --------------------------------------------------------------------------------------
# state composition (CRITICAL): reducers must accumulate, not replace
# --------------------------------------------------------------------------------------


def test_devops_state_channels_are_accumulating_reducers() -> None:
    """DevOpsState must wire commutative reducers for the budget keys + the tool cache.

    Guards the CRITICAL invariant: composing BudgetStateMixin by inheritance (not
    re-declaration) preserves ``_add_cost`` / ``_merge_usage``; a regression to plain fields
    would silently make langgraph REPLACE instead of accumulate.
    """
    from langgraph.channels.binop import BinaryOperatorAggregate
    from langgraph.graph import END, START, StateGraph

    from opendevops.state import DevOpsState

    g = StateGraph(DevOpsState)
    g.add_node("n", lambda s: {})
    g.add_edge(START, "n")
    g.add_edge("n", END)
    g.compile()

    for key in ("run_cost_usd", "run_usage", "tool_results_cache", "dry_run_ok", "messages"):
        assert isinstance(g.channels[key], BinaryOperatorAggregate), key


def test_tool_cache_reducer_merges_partial_updates() -> None:
    from opendevops.state import _merge_tool_cache

    assert _merge_tool_cache({"a": "1"}, {"b": "2"}) == {"a": "1", "b": "2"}
    # right-biased on conflict, and None-safe on either side
    assert _merge_tool_cache({"a": "1"}, {"a": "2"}) == {"a": "2"}
    assert _merge_tool_cache(None, {"a": "1"}) == {"a": "1"}
    assert _merge_tool_cache({"a": "1"}, None) == {"a": "1"}


def test_dry_run_ok_reducer_accumulates_across_calls() -> None:
    """dry_run_ok must ACCUMULATE (a multi-manifest deploy validates one sha per call).

    A LastValue field would forget every previously-validated manifest on each new write, so a
    second dry-run recording would drop the first manifest's sha and re-deny its real apply.
    """
    from opendevops.state import _merge_dry_run_ok

    assert _merge_dry_run_ok({"a": True}, {"b": True}) == {"a": True, "b": True}
    assert _merge_dry_run_ok(None, {"a": True}) == {"a": True}
    assert _merge_dry_run_ok({"a": True}, None) == {"a": True}


async def test_graph_control_flow_exceptions_propagate(tmp_path: Path) -> None:
    """GraphInterrupt/GraphBubbleUp raised by the handler must NOT become fail-closed denies.

    LangGraph control flow subclasses Exception, but converting it into a deny would break
    every interrupt/HITL suspend-resume flow — including the escalate path, which calls
    interrupt() inside the pipeline itself. Pin: it propagates, no policy_error is written,
    and the exec-gate contextvar is still reset by the finally.
    """
    from langgraph.errors import GraphInterrupt

    engine = FakeEngine(Decision.allow("kubectl-get", "ro", channel="ro"))
    audit = _started_logger(tmp_path)
    mw = _mw(engine, audit)

    async def interrupting_handler(request: ToolCallRequest) -> ToolMessage:
        raise GraphInterrupt()

    request = _request("run_command", {"argv": ["kubectl", "get", "pods"]}, "call-int")
    with pytest.raises(GraphInterrupt):
        await mw.awrap_tool_call(request, interrupting_handler)

    # decision event was written before the handler ran; no policy_error afterwards
    types = _types(tmp_path)
    assert "decision" in types
    assert "policy_error" not in types
    # the finally reset the exec gate — nothing leaks to a later call
    assert current_decision.get() is None
