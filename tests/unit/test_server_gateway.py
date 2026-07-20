"""ServerGateway (T16): drive a graph over a faked ``langgraph_sdk`` client at the wire boundary.

No live server in CI — every test uses ``_FakeLangGraphClient``, whose scripted threads / runs /
stream payloads are modeled on the REAL wire shapes probed against langgraph-sdk 0.4.2 + a live
in-memory ``langgraph dev`` 0.11.1 server (cited inline). In particular:

* messages arrive as ``.model_dump()`` **dicts** (``{"type": "ai"|"tool", ...}``), because the
  LangGraph Server JSON-encodes every state value with a ``model_dump()`` default;
* ``runs.stream(stream_mode=["updates","values"])`` yields ``StreamPart(event, data, id)`` — a
  ``metadata`` frame, then interleaved ``values`` (full state) and ``updates`` (``{node: {...}}``);
* ``runs.wait`` returns the final state values dict; a suspend rides ``__interrupt__`` in it;
* ``on_run_created`` fires with ``{"run_id", "thread_id"}`` (the SERVER run id, for cancel);
* resume is ``command={"resume": {"decisions": [...]}}``.
"""

from __future__ import annotations

import asyncio
import copy
from typing import Any

import pytest
from langgraph_sdk.schema import StreamPart

from graph.helpers import MODELS, budgets
from opendevops.config import AppConfig
from opendevops.gateway import (
    AssistantText,
    Escalation,
    EscalationEvent,
    GatewayConfigError,
    RunEnd,
    RunResult,
    ServerGateway,
    ToolCall,
    ToolResult,
)

_MAIN = "anthropic:claude-opus-4-8"
_SRV_RUN = "019f0000-0000-7000-8000-00000000run1"
_SRV_THREAD = "019f0000-0000-7000-8000-0000000thread"
_PODS = ["kubectl", "get", "pods", "-n", "default"]
_DELETE = ["kubectl", "delete", "pod", "x"]


# -- wire-shaped message builders (probed: server encodes messages via .model_dump()) ------


def _ai_tc(argv: list[str], call_id: str, *, usage: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "type": "ai",
        "content": "",
        "tool_calls": [
            {"name": "run_command", "args": {"argv": argv}, "id": call_id, "type": "tool_call"}
        ],
        "response_metadata": {"model_name": _MAIN},
        "usage_metadata": usage,
    }


def _tool(content: str, call_id: str, *, status: str = "success") -> dict[str, Any]:
    return {
        "type": "tool",
        "content": content,
        "tool_call_id": call_id,
        "name": "run_command",
        "status": status,
    }


def _ai_text(text: str) -> dict[str, Any]:
    return {"type": "ai", "content": text, "tool_calls": [], "response_metadata": {}}


def _updates(node: str, messages: list[dict[str, Any]]) -> StreamPart:
    return StreamPart(event="updates", data={node: {"messages": messages}}, id=None)


def _values(state: dict[str, Any]) -> StreamPart:
    return StreamPart(event="values", data=state, id=None)


def _metadata() -> StreamPart:
    return StreamPart(event="metadata", data={"run_id": _SRV_RUN, "attempt": 1}, id=None)


# -- the fake SDK client -------------------------------------------------------------------


class _FakeThreads:
    def __init__(self, thread_id: str = _SRV_THREAD) -> None:
        self._thread_id = thread_id
        self.created: list[dict[str, Any]] = []

    async def create(self, **kwargs: Any) -> dict[str, Any]:
        self.created.append(kwargs)
        return {"thread_id": self._thread_id}


class _FakeRuns:
    """Scripted ``runs`` sub-client recording every call and callback for assertions."""

    def __init__(
        self,
        *,
        wait_values: dict[str, Any] | None = None,
        stream_parts: list[StreamPart] | None = None,
        delay: float = 0.0,
        exc: Exception | None = None,
        hang: bool = False,
    ) -> None:
        self._wait_values = wait_values if wait_values is not None else {}
        self._stream_parts = stream_parts or []
        self._delay = delay
        self._exc = exc
        self._hang = hang
        self.calls: list[dict[str, Any]] = []
        self.cancels: list[dict[str, Any]] = []

    async def wait(
        self,
        thread_id: str | None,
        assistant_id: str,
        *,
        input: Any = None,  # noqa: A002 - mirrors the SDK's own param name
        command: Any = None,
        config: Any = None,
        context: Any = None,
        on_run_created: Any = None,
        **_kw: Any,
    ) -> Any:
        self.calls.append(
            {
                "method": "wait",
                "thread_id": thread_id,
                "assistant_id": assistant_id,
                "input": input,
                "command": command,
                "config": config,
                "context": context,
            }
        )
        if on_run_created is not None:
            on_run_created({"run_id": _SRV_RUN, "thread_id": thread_id})
        if self._delay:
            await asyncio.sleep(self._delay)
        if self._exc is not None:
            raise self._exc
        return self._wait_values

    async def stream(
        self,
        thread_id: str | None,
        assistant_id: str,
        *,
        input: Any = None,  # noqa: A002 - mirrors the SDK's own param name
        command: Any = None,
        stream_mode: Any = None,
        config: Any = None,
        context: Any = None,
        on_run_created: Any = None,
        **_kw: Any,
    ) -> Any:
        self.calls.append(
            {
                "method": "stream",
                "thread_id": thread_id,
                "assistant_id": assistant_id,
                "input": input,
                "command": command,
                "stream_mode": stream_mode,
                "config": config,
                "context": context,
            }
        )
        if on_run_created is not None:
            on_run_created({"run_id": _SRV_RUN, "thread_id": thread_id})
        for part in self._stream_parts:
            yield part
        if self._hang:
            await asyncio.sleep(60)
        if self._exc is not None:
            raise self._exc

    async def cancel(
        self, thread_id: str, run_id: str, *, wait: bool = False, action: str = "interrupt",
        **_kw: Any,
    ) -> None:
        self.cancels.append({"thread_id": thread_id, "run_id": run_id, "action": action})


class _FakeClient:
    def __init__(self, runs: _FakeRuns, threads: _FakeThreads | None = None) -> None:
        self.runs = runs
        self.threads = threads or _FakeThreads()
        self.closed = False

    async def aclose(self) -> None:
        self.closed = True


# -- config + gateway builders -------------------------------------------------------------


def _make_cfg(*, url: str | None = "http://localhost:8123", api_key_env: str | None = None,
              budgets_doc: dict[str, Any] | None = None) -> AppConfig:
    return AppConfig.model_validate(
        {
            "targets": {"kubernetes": {"kubeconfig_ro": "/tmp/k.yaml"}},
            "execution": {
                "cmd_timeout_seconds": 60,
                "output_max_chars": 50000,
                "env_allowlist": ["PATH"],
            },
            "audit": {"dir": "/tmp/opendevops-test-audit"},
            "policy": {"dir": "./config/policy"},
            "server": {"url": url, "api_key_env": api_key_env},
            "models": copy.deepcopy(MODELS),
            "budgets": budgets_doc if budgets_doc is not None else budgets(),
        }
    )


def _gateway(runs: _FakeRuns, *, cfg: AppConfig | None = None) -> ServerGateway:
    return ServerGateway(cfg if cfg is not None else _make_cfg(), client=_FakeClient(runs))


# -- config error --------------------------------------------------------------------------


def test_missing_url_raises_config_error() -> None:
    """Constructing a ServerGateway without a configured server.url fails closed."""
    with pytest.raises(GatewayConfigError):
        ServerGateway(_make_cfg(url=None), client=_FakeClient(_FakeRuns()))


# -- thread create -------------------------------------------------------------------------


async def test_create_thread_returns_server_thread_id() -> None:
    runs = _FakeRuns()
    gw = _gateway(runs)
    thread_id = await gw.create_thread()
    assert thread_id == _SRV_THREAD
    # No caller-chosen id -> server mints it (no thread_id/if_exists passed).
    assert gw._client.threads.created == [{}]  # type: ignore[attr-defined]


async def test_create_thread_reuses_caller_chosen_id_idempotently() -> None:
    """A deterministic incident thread id is passed with if_exists=do_nothing (reuse, not error)."""
    threads = _FakeThreads(thread_id="4a9cf785-7879-5d45-b426-5d886da331e3")
    gw = ServerGateway(_make_cfg(), client=_FakeClient(_FakeRuns(), threads))
    chosen = "4a9cf785-7879-5d45-b426-5d886da331e3"
    thread_id = await gw.create_thread(thread_id=chosen)
    assert thread_id == chosen
    assert threads.created == [{"thread_id": chosen, "if_exists": "do_nothing"}]


# -- run happy path ------------------------------------------------------------------------


async def test_run_happy_path_context_verbatim_and_result_fields() -> None:
    """run() passes the same context LocalGateway does, and reads cost/usage from final state."""
    runs = _FakeRuns(
        wait_values={
            "messages": [
                _ai_tc(_PODS, "c1"),
                _tool("NAME READY\npod-a 1/1", "c1"),
                _ai_text("Pods look healthy."),
            ],
            "run_cost_usd": 0.01375,
            "run_usage": {"input_tokens": 1500, "output_tokens": 250},
        }
    )
    gw = _gateway(runs)
    result = await gw.run(
        "thread-1", "list pods", profile="default",
        principal="sandipan", interface="http", environment="staging",
    )

    assert isinstance(result, RunResult)
    assert result.final_text == "Pods look healthy."
    assert result.error is None
    # Accounting divergence: authoritative == state, and the blind-spot flag is set.
    assert result.cost_usd_state == pytest.approx(0.01375)
    assert result.cost_usd_authoritative == pytest.approx(0.01375)
    assert result.usage["authoritative_unavailable"] is True
    assert result.usage["input_tokens"] == 1500

    # Context passed through verbatim (the SAME fields LocalGateway injects in-graph).
    call = runs.calls[0]
    assert call["method"] == "wait"
    assert call["assistant_id"] == "devops"
    assert call["context"] == {
        "principal": "sandipan",
        "interface": "http",
        "environment": "staging",
        "budget_profile": "default",
        "run_id": result.run_id,
    }
    # recursion_limit from the resolved profile rides the run config; input is the wire shape.
    assert call["config"] == {"recursion_limit": 250}
    assert call["input"] == {"messages": [{"role": "user", "content": "list pods"}]}


async def test_run_carries_profile_recursion_limit() -> None:
    """The resolved profile's recursion_limit rides the run config (not a hardcoded value)."""
    runs = _FakeRuns(wait_values={"messages": [_ai_text("ok")], "run_cost_usd": 0.0})
    gw = _gateway(runs, cfg=_make_cfg(budgets_doc=budgets(recursion_limit=99)))
    await gw.run(
        "t", "hi", profile="default", principal="p", interface="http", environment="prod"
    )
    assert runs.calls[0]["config"] == {"recursion_limit": 99}
    assert runs.calls[0]["context"]["budget_profile"] == "default"


# -- stream translation --------------------------------------------------------------------


async def test_stream_translates_events_and_ends_with_runend() -> None:
    runs = _FakeRuns(
        stream_parts=[
            _metadata(),
            _values({"messages": []}),
            _updates("model", [_ai_tc(_PODS, "c1")]),
            _values({"messages": [_ai_tc(_PODS, "c1")], "run_cost_usd": 0.01}),
            _updates("tools", [_tool("NAME READY", "c1")]),
            _updates("model", [_ai_text("All good.")]),
            _values(
                {
                    "messages": [
                        _ai_tc(_PODS, "c1"),
                        _tool("NAME READY", "c1"),
                        _ai_text("All good."),
                    ],
                    "run_cost_usd": 0.01375,
                    "run_usage": {"input_tokens": 1500, "output_tokens": 250},
                }
            ),
        ]
    )
    gw = _gateway(runs)
    events = [
        ev
        async for ev in gw.stream(
            "thread-s", "list pods", principal="sandipan", interface="http", environment="staging"
        )
    ]

    tool_calls = [e for e in events if isinstance(e, ToolCall)]
    tool_results = [e for e in events if isinstance(e, ToolResult)]
    texts = [e for e in events if isinstance(e, AssistantText)]
    ends = [e for e in events if isinstance(e, RunEnd)]

    assert tool_calls and tool_calls[0].name == "run_command"
    assert tool_calls[0].argv == _PODS
    assert tool_results and not tool_results[0].denied
    assert tool_results[0].excerpt == "NAME READY"
    assert any(t.text == "All good." for t in texts)
    # Exactly one RunEnd, and it is the last event; it carries the final accounting.
    assert len(ends) == 1
    assert isinstance(events[-1], RunEnd)
    assert ends[0].result.final_text == "All good."
    assert ends[0].result.cost_usd_authoritative == pytest.approx(0.01375)
    assert ends[0].result.usage["authoritative_unavailable"] is True
    # stream_mode is the updates+values pair (never messages).
    assert runs.calls[0]["stream_mode"] == ["updates", "values"]


async def test_stream_flags_policy_denial_with_rule_id() -> None:
    """A denied tool result (wire dict) is flagged with its rule id, same as LocalGateway."""
    runs = _FakeRuns(
        stream_parts=[
            _metadata(),
            _updates("model", [_ai_tc(["bash", "-c", "id"], "c1")]),
            _updates(
                "tools",
                [
                    _tool(
                        "Denied by policy [interpreters-hard-deny]: no shells.",
                        "c1",
                        status="error",
                    )
                ],
            ),
            _values({"messages": [], "run_cost_usd": 0.0}),
        ]
    )
    gw = _gateway(runs)
    events = [
        ev
        async for ev in gw.stream(
            "thread-d", "run id", principal="sandipan", interface="http", environment="staging"
        )
    ]
    denials = [e for e in events if isinstance(e, ToolResult) and e.denied]
    assert denials and denials[0].rule_id == "interpreters-hard-deny"


# -- escalation / resume -------------------------------------------------------------------


async def test_run_suspends_on_escalation_then_resume_completes() -> None:
    """A run whose final state carries __interrupt__ returns interrupted; resume finishes it."""
    interrupt_payload = {
        "action_requests": [{"action": "run_command", "args": {"argv": _DELETE}}],
        "review_configs": [
            {
                "rule_id": "kubectl-delete-workload-escalate",
                "reason": "destructive",
                "allowed_decisions": ["approve", "edit", "reject"],
                "timeout_s": 300,
            }
        ],
    }
    runs = _FakeRuns(
        wait_values={
            "messages": [_ai_tc(_DELETE, "call-del")],
            "run_cost_usd": 0.01,
            "__interrupt__": [{"value": interrupt_payload, "id": "int-1"}],
        }
    )
    gw = _gateway(runs)
    result = await gw.run(
        "thread-esc", "delete pod x", principal="sandipan", interface="http", environment="staging"
    )

    assert result.interrupted is not None
    assert isinstance(result.interrupted, Escalation)
    assert result.interrupted.thread_id == "thread-esc"
    assert result.interrupted.payload["review_configs"][0]["rule_id"] == (
        "kubectl-delete-workload-escalate"
    )
    assert result.cost_usd_state == pytest.approx(0.01)

    # RESUME: same run_id (chain locality), approver injected into each decision.
    runs._wait_values = {
        "messages": [_ai_text("Left the pod alone.")],
        "run_cost_usd": 0.01375,
    }
    resumed = await gw.resume_interrupt(
        "thread-esc", [{"type": "reject", "message": "no"}], approver="alice"
    )
    assert resumed.interrupted is None
    assert resumed.run_id == result.run_id  # same run continued -> same chain
    assert resumed.final_text == "Left the pod alone."

    resume_call = runs.calls[-1]
    assert resume_call["command"] == {
        "resume": {"decisions": [{"type": "reject", "message": "no", "approver": "alice"}]}
    }
    # The resume reuses the suspended run's context (same run_id).
    assert resume_call["context"]["run_id"] == result.run_id


async def test_resume_without_suspended_raises() -> None:
    from opendevops.gateway import GatewayError

    runs = _FakeRuns()
    gw = _gateway(runs)
    with pytest.raises(GatewayError):
        await gw.resume_interrupt("nope", [{"type": "approve"}], approver="alice")


async def test_stream_emits_escalation_event_then_runend() -> None:
    interrupt_payload = {
        "action_requests": [{"action": "run_command", "args": {"argv": _DELETE}}],
        "review_configs": [{"rule_id": "kubectl-delete-workload-escalate", "reason": "d"}],
    }
    runs = _FakeRuns(
        stream_parts=[
            _metadata(),
            _updates("model", [_ai_tc(_DELETE, "call-del")]),
            _values(
                {
                    "messages": [_ai_tc(_DELETE, "call-del")],
                    "run_cost_usd": 0.01,
                    "__interrupt__": [{"value": interrupt_payload, "id": "int-1"}],
                }
            ),
        ]
    )
    gw = _gateway(runs)
    events = [
        ev
        async for ev in gw.stream(
            "thread-se", "delete", principal="p", interface="http", environment="staging"
        )
    ]
    escalations = [e for e in events if isinstance(e, EscalationEvent)]
    assert len(escalations) == 1
    assert escalations[0].escalation.payload["review_configs"][0]["rule_id"] == (
        "kubectl-delete-workload-escalate"
    )
    # EscalationEvent is second-to-last; RunEnd is last and carries the Escalation.
    assert isinstance(events[-1], RunEnd)
    assert isinstance(events[-2], EscalationEvent)
    assert events[-1].result.interrupted is not None


# -- cancel --------------------------------------------------------------------------------


async def test_cancel_calls_server_runs_cancel() -> None:
    """After a run captures the server run id (on_run_created), cancel targets it on the server."""
    runs = _FakeRuns(wait_values={"messages": [_ai_text("done")], "run_cost_usd": 0.0})
    gw = _gateway(runs)
    await gw.run("thread-c", "hi", principal="p", interface="http", environment="staging")
    await gw.cancel("thread-c")
    assert runs.cancels == [{"thread_id": "thread-c", "run_id": _SRV_RUN, "action": "interrupt"}]


async def test_cancel_noop_without_known_server_run() -> None:
    runs = _FakeRuns()
    gw = _gateway(runs)
    await gw.cancel("unknown-thread")  # must not raise
    assert runs.cancels == []


# -- wall clock ----------------------------------------------------------------------------


async def test_run_wall_clock_timeout_cancels_server_run(monkeypatch: pytest.MonkeyPatch) -> None:
    runs = _FakeRuns(wait_values={"messages": [_ai_text("x")]}, delay=5.0)
    cfg = _make_cfg()
    gw = ServerGateway(cfg, client=_FakeClient(runs))
    tiny = cfg.budgets.per_run.default.model_copy(update={"wall_clock_s": 0.05})
    monkeypatch.setattr(type(cfg.budgets), "profile", lambda _self, name="default": tiny)

    result = await gw.run(
        "thread-w", "hang", principal="p", interface="http", environment="staging"
    )
    assert result.error == "wall clock exceeded"
    assert result.budget_stop == {"kind": "wall_clock", "limit": 0.05}
    # The still-running server run was cancelled (never a suspended one — wait returns promptly
    # on a suspend, so a timeout implies a genuinely-running run).
    assert runs.cancels == [{"thread_id": "thread-w", "run_id": _SRV_RUN, "action": "interrupt"}]


# -- unexpected error ----------------------------------------------------------------------


async def test_run_unexpected_error_wraps_in_gateway_run_error() -> None:
    from opendevops.gateway import GatewayRunError

    runs = _FakeRuns(exc=RuntimeError("boom from sdk"))
    gw = _gateway(runs)
    with pytest.raises(GatewayRunError):
        await gw.run("t", "hi", principal="p", interface="http", environment="staging")


async def test_stream_unexpected_error_ends_with_friendly_runend() -> None:
    runs = _FakeRuns(
        stream_parts=[_metadata(), _updates("model", [_ai_text("partial")])],
        exc=RuntimeError("stream broke"),
    )
    gw = _gateway(runs)
    events = [
        ev
        async for ev in gw.stream(
            "t", "hi", principal="p", interface="http", environment="staging"
        )
    ]
    assert isinstance(events[-1], RunEnd)
    assert events[-1].result.error == "unexpected error"


# -- aclose --------------------------------------------------------------------------------


async def test_aclose_closes_client() -> None:
    runs = _FakeRuns()
    client = _FakeClient(runs)
    gw = ServerGateway(_make_cfg(), client=client)
    await gw.aclose()
    assert client.closed is True


# -- api key resolution (build_client) -----------------------------------------------------


def test_build_client_reads_api_key_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """The real client build reads the key from the env var NAMED by config (never the key)."""
    captured: dict[str, Any] = {}

    def _fake_get_client(*, url: str | None = None, api_key: Any = None, **_kw: Any) -> Any:
        captured["url"] = url
        captured["api_key"] = api_key
        return _FakeClient(_FakeRuns())

    monkeypatch.setattr("opendevops.gateway.server.get_client", _fake_get_client)
    monkeypatch.setenv("MY_LG_KEY", "secret-token")
    ServerGateway(_make_cfg(url="http://srv:8123", api_key_env="MY_LG_KEY"))
    assert captured == {"url": "http://srv:8123", "api_key": "secret-token"}


def test_build_client_no_api_key_env_passes_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """api_key_env=None => api_key=None passed explicitly (suppresses ambient env auto-load)."""
    captured: dict[str, Any] = {}

    def _fake_get_client(*, url: str | None = None, api_key: Any = "SENTINEL", **_kw: Any) -> Any:
        captured["api_key"] = api_key
        return _FakeClient(_FakeRuns())

    monkeypatch.setattr("opendevops.gateway.server.get_client", _fake_get_client)
    ServerGateway(_make_cfg(url="http://srv:8123", api_key_env=None))
    assert captured["api_key"] is None
