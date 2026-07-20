"""LocalGateway: run/stream accounting, audit book-ends, budget/timeout/cancel paths.

Reuses the graph suite's pure builders (``graph.helpers``: the ``BindableFake`` model, scripted
``usage`` blocks, the shipped-equivalent ``MODELS`` / ``budgets`` documents) and points the built
agent at the *shipped* policy dir, so these exercise the real middleware stack — only the model
is faked. ``registry.build_chat_model`` is monkeypatched to inject the fake before the gateway
calls the real :func:`opendevops.agent.build_agent`.

The scripted assistant messages carry ``response_metadata={"model_name": ...}`` because the
usage-metadata callback only records a call when both ``usage_metadata`` *and* a model name are
present (verified against langchain-core 1.4.9) — that is what makes the gateway's authoritative
ledger non-empty under a fake model.
"""

from __future__ import annotations

import asyncio
import copy
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from langchain_core.messages import AIMessage
from langgraph.errors import GraphRecursionError

import opendevops.tools.run_command as run_command_mod
from graph.helpers import MODELS, BindableFake, budgets, usage
from opendevops.audit import verify_run_file
from opendevops.audit.logger import AuditLogger
from opendevops.budget.daily import InMemoryDailyCounter
from opendevops.config import AppConfig
from opendevops.gateway import (
    AssistantText,
    Escalation,
    GatewayError,
    GatewayRunError,
    LocalGateway,
    RunEnd,
    RunResult,
    ToolCall,
    ToolResult,
)
from opendevops.models import registry
from opendevops.tools.executor import ExecResult

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_DIR = REPO_ROOT / "config" / "policy"

_MAIN = "anthropic:claude-opus-4-8"
_SUMMARIZER = "anthropic:claude-haiku-4-5"
_PODS = ["kubectl", "get", "pods", "-n", "default"]


# -- scripted messages (model_name set so the usage callback records them) -----------------


def _tc(
    argv: list[str], call_id: str, *, usage_metadata: dict[str, Any] | None = None
) -> AIMessage:
    return AIMessage(
        content="",
        tool_calls=[
            {"name": "run_command", "args": {"argv": argv}, "id": call_id, "type": "tool_call"}
        ],
        usage_metadata=usage_metadata,  # type: ignore[arg-type]
        response_metadata={"model_name": _MAIN},
    )


def _txt(text: str, *, usage_metadata: dict[str, Any] | None = None) -> AIMessage:
    return AIMessage(
        content=text,
        usage_metadata=usage_metadata,  # type: ignore[arg-type]
        response_metadata={"model_name": _MAIN},
    )


def _wf(path: str, content: str, call_id: str) -> AIMessage:
    """A write_file tool call (stages a manifest into the deepagents virtual FS)."""
    return AIMessage(
        content="",
        tool_calls=[
            {
                "name": "write_file",
                "args": {"file_path": path, "content": content},
                "id": call_id,
                "type": "tool_call",
            }
        ],
        response_metadata={"model_name": _MAIN},
    )


def _make_cfg(
    tmp_path: Path, *, budgets_doc: dict[str, Any] | None = None, rw: bool = False
) -> AppConfig:
    return AppConfig.model_validate(
        {
            "targets": {
                "kubernetes": {
                    "kubeconfig_ro": str(tmp_path / "kubeconfig-ro.yaml"),
                    "kubeconfig_rw": str(tmp_path / "kubeconfig-rw.yaml") if rw else None,
                    "allowed_contexts": ["kind-opendevops"],
                },
                # gh-read pack allows require the gh credential family at boot; the
                # gh-write rw allows require the write PAT (token_env_rw => "gh-rw") + write_repos.
                "github": {
                    "token_env": "OPENDEVOPS_TEST_GH_TOKEN",
                    "token_env_rw": "OPENDEVOPS_TEST_GH_TOKEN_RW",
                    "write_repos": ["octo-org/staging-app"],
                },
                # aws/gcloud/az-read packs require their cloud credential families at boot
                # (coverage gate). Names only; values are never read in these fake-model tests.
                "aws": {"credential_env": ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]},
                "gcloud": {"credential_env": ["GOOGLE_APPLICATION_CREDENTIALS"]},
                "azure": {"credential_env": ["AZURE_CLIENT_ID", "AZURE_TENANT_ID"]},
                # ssh-read pack coverage gate (names/paths only; never dialed here).
                "ssh": {
                    "hosts": ["allowed.host.internal"],
                    "user": "deploy",
                    "key_env": "OPENDEVOPS_TEST_SSH_KEY",
                    "known_hosts_path": str(tmp_path / "known_hosts"),
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
            "budgets": budgets_doc if budgets_doc is not None else budgets(),
        }
    )


BuildGateway = Callable[..., tuple[LocalGateway, AuditLogger, InMemoryDailyCounter, AppConfig]]


@pytest_asyncio.fixture
async def build_gateway(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> AsyncIterator[BuildGateway]:
    """Factory: a real ``LocalGateway`` over the shipped policy with an injected fake model.

    Closes each gateway's checkpointer connection at teardown (inside the test's event loop) so
    the lazily-built AsyncSqliteSaver does not leak its worker thread past the loop.
    """
    created: list[LocalGateway] = []

    def _build(
        messages: list[AIMessage],
        *,
        counter: InMemoryDailyCounter | None = None,
        budgets_doc: dict[str, Any] | None = None,
        rw: bool = False,
    ) -> tuple[LocalGateway, AuditLogger, InMemoryDailyCounter, AppConfig]:
        cfg = _make_cfg(tmp_path, budgets_doc=budgets_doc, rw=rw)
        fake = BindableFake(messages=iter(messages))
        monkeypatch.setattr(registry, "build_chat_model", lambda _c, _n: fake)
        audit = AuditLogger(cfg.audit.dir)
        cnt = counter if counter is not None else InMemoryDailyCounter()
        gw = LocalGateway(cfg, audit=audit, counter=cnt)
        created.append(gw)
        return gw, audit, cnt, cfg

    yield _build
    for gw in created:
        await gw.aclose()


def _event_types(cfg: AppConfig, run_id: str) -> list[str]:
    return [e["event_type"] for e in _read_events(cfg, run_id)]


def _read_events(cfg: AppConfig, run_id: str) -> list[dict[str, Any]]:
    import json

    path = Path(cfg.audit.dir) / f"{run_id}.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _run_completed_summary(cfg: AppConfig, run_id: str) -> dict[str, Any]:
    """The ``summary`` payload of a run's ``run_completed`` audit event."""
    import json

    path = Path(cfg.audit.dir) / f"{run_id}.jsonl"
    for line in reversed(path.read_text().splitlines()):
        if not line.strip():
            continue
        event = json.loads(line)
        if event["event_type"] == "run_completed":
            return dict(event["summary"])
    raise AssertionError(f"no run_completed event in {run_id}.jsonl")


# -- create_thread -------------------------------------------------------------------------


async def test_create_thread_returns_unique_ids(build_gateway: BuildGateway) -> None:
    gw, *_ = build_gateway([_txt("hi")])
    a = await gw.create_thread()
    b = await gw.create_thread()
    assert a != b
    assert isinstance(a, str) and a


async def test_create_thread_returns_caller_chosen_id(build_gateway: BuildGateway) -> None:
    """A caller-chosen thread id (webhook incident thread) is returned verbatim."""
    gw, *_ = build_gateway([_txt("hi")])
    chosen = "4a9cf785-7879-5d45-b426-5d886da331e3"
    assert await gw.create_thread(thread_id=chosen) == chosen


# -- happy run -----------------------------------------------------------------------------


async def test_happy_run_returns_result_and_writes_verified_chain(
    build_gateway: BuildGateway,
) -> None:
    gw, _audit, counter, cfg = build_gateway(
        [
            _tc(_PODS, "c1", usage_metadata=usage(input=1000, output=200)),
            _txt("Pods look healthy.", usage_metadata=usage(input=500, output=50)),
        ]
    )
    result = await gw.run(
        "thread-1", "list pods", principal="sandipan", interface="cli", environment="staging"
    )

    assert isinstance(result, RunResult)
    assert result.final_text == "Pods look healthy."
    assert result.error is None
    # Both cost numbers are populated; with matching model names authoritative == state.
    assert result.cost_usd_state == pytest.approx(0.01375)
    assert result.cost_usd_authoritative == pytest.approx(0.01375)
    assert result.usage["input_tokens"] == 1500
    assert result.usage["output_tokens"] == 250

    # The daily counter was charged (by the in-graph middleware) exactly the run cost.
    assert await counter.total("global") == pytest.approx(0.01375)

    # Audit chain book-ends verify and record the full turn.
    assert _event_types(cfg, result.run_id) == [
        "run_started",
        "decision",
        "execution",
        "run_completed",
    ]
    assert verify_run_file(Path(cfg.audit.dir) / f"{result.run_id}.jsonl").ok


# -- streaming translation -----------------------------------------------------------------


async def test_stream_translates_events_and_ends_with_runend(build_gateway: BuildGateway) -> None:
    gw, _audit, _counter, cfg = build_gateway(
        [
            _tc(_PODS, "c1", usage_metadata=usage(input=1000, output=200)),
            _txt("All good.", usage_metadata=usage(input=500, output=50)),
        ]
    )
    events = [
        ev
        async for ev in gw.stream(
            "thread-s", "list pods", principal="sandipan", interface="cli", environment="staging"
        )
    ]

    tool_calls = [e for e in events if isinstance(e, ToolCall)]
    tool_results = [e for e in events if isinstance(e, ToolResult)]
    texts = [e for e in events if isinstance(e, AssistantText)]
    ends = [e for e in events if isinstance(e, RunEnd)]

    assert tool_calls and tool_calls[0].name == "run_command"
    assert tool_calls[0].argv == ["kubectl", "get", "pods", "-n", "default"]
    assert tool_results and not tool_results[0].denied
    assert any(t.text == "All good." for t in texts)
    # Exactly one RunEnd, and it is the last event.
    assert len(ends) == 1
    assert isinstance(events[-1], RunEnd)
    assert ends[0].result.final_text == "All good."
    assert ends[0].result.cost_usd_authoritative == pytest.approx(0.01375)
    assert verify_run_file(Path(cfg.audit.dir) / f"{ends[0].result.run_id}.jsonl").ok


async def test_stream_flags_policy_denial_with_rule_id(build_gateway: BuildGateway) -> None:
    gw, *_ = build_gateway(
        [
            _tc(["bash", "-c", "id"], "c1", usage_metadata=usage(input=10, output=2)),
            _txt("I can't run shell interpreters."),
        ]
    )
    events = [
        ev
        async for ev in gw.stream(
            "thread-d", "run id", principal="sandipan", interface="cli", environment="staging"
        )
    ]
    denials = [e for e in events if isinstance(e, ToolResult) and e.denied]
    assert denials, "expected a denied tool result in the stream"
    assert denials[0].rule_id == "interpreters-hard-deny"


# -- daily pre-check refusal ---------------------------------------------------------------


async def test_daily_precheck_refuses_before_any_model_call(build_gateway: BuildGateway) -> None:
    counter = InMemoryDailyCounter()
    await counter.add("global", 999.0)  # over the 50.00 global cap
    gw, _audit, cnt, cfg = build_gateway([_txt("SHOULD NOT RUN")], counter=counter)

    result = await gw.run(
        "thread-r", "hello", principal="sandipan", interface="cli", environment="staging"
    )

    assert result.error == "daily budget exhausted"
    assert result.final_text == ""
    assert result.cost_usd_state == 0.0
    assert result.cost_usd_authoritative == 0.0
    assert result.budget_stop == {
        "kind": "daily_usd",
        "scope": "global",
        "spent": 999.0,
        "cap": 50.0,
    }
    # No model call happened: the counter was not charged beyond the pre-seed.
    assert await cnt.total("global") == pytest.approx(999.0)
    # Refusal is still audited for traceability.
    assert _event_types(cfg, result.run_id) == ["run_started", "budget_trip", "run_completed"]
    assert verify_run_file(Path(cfg.audit.dir) / f"{result.run_id}.jsonl").ok


async def test_daily_precheck_refuses_on_principal_cap(build_gateway: BuildGateway) -> None:
    counter = InMemoryDailyCounter()
    await counter.add("principal:sandipan", 30.0)  # over the 25.00 per-principal cap
    gw, _audit, _cnt, _cfg = build_gateway([_txt("SHOULD NOT RUN")], counter=counter)

    result = await gw.run(
        "thread-p", "hello", principal="sandipan", interface="cli", environment="staging"
    )

    assert result.error == "daily budget exhausted"
    assert result.budget_stop is not None
    assert result.budget_stop["scope"] == "principal:sandipan"


# -- authoritative-delta accounting (the summarizer-coverage rule) --------------------------


async def test_authoritative_delta_charges_only_the_summarizer_delta(
    build_gateway: BuildGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A summarizer call in the callback aggregate (but not in state) is charged as a delta.

    The middleware charges the two main (opus) calls to the counter during the run; the gateway
    then sees the callback aggregate contain an extra haiku (summarizer) call and tops up the
    counter with ONLY that delta — never re-charging the opus calls already counted.
    """
    gw, _audit, counter, _cfg = build_gateway(
        [
            _tc(_PODS, "c1", usage_metadata=usage(input=1000, output=200)),
            _txt("done.", usage_metadata=usage(input=500, output=50)),
        ]
    )
    # Aggregate the gateway will read: the opus total the middleware also saw + a haiku summarizer.
    aggregate = {
        _MAIN: usage(input=1500, output=250),  # opus: $0.01375 (== state_total)
        _SUMMARIZER: usage(input=2000, output=100),  # haiku: (2000*1 + 100*5)/1e6 = $0.0025
    }
    monkeypatch.setattr(gw, "_usage_aggregate", lambda _cb: aggregate)

    result = await gw.run(
        "thread-a", "investigate", principal="sandipan", interface="cli", environment="staging"
    )

    assert result.cost_usd_state == pytest.approx(0.01375)
    assert result.cost_usd_authoritative == pytest.approx(0.01625)  # 0.01375 + 0.0025
    # Counter = middleware's opus charge (0.01375) + gateway's haiku delta (0.0025) = authoritative.
    assert await counter.total("global") == pytest.approx(0.01625)
    assert await counter.total("principal:sandipan") == pytest.approx(0.01625)


async def test_unknown_model_name_priced_with_main_and_counted_missing(
    build_gateway: BuildGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unmapped model name in the aggregate is priced with the main row + flagged missing."""
    gw, _audit, _counter, _cfg = build_gateway(
        [_txt("done.", usage_metadata=usage(input=100, output=10))]
    )
    monkeypatch.setattr(
        gw, "_usage_aggregate", lambda _cb: {"mystery-model-9000": usage(input=1000, output=200)}
    )
    result = await gw.run(
        "thread-u", "hi", principal="sandipan", interface="cli", environment="staging"
    )
    # Priced with the main (opus) row: (1000*5 + 200*25)/1e6 = 0.01.
    assert result.cost_usd_authoritative == pytest.approx(0.01)
    assert result.usage["usage_missing"] >= 1


# -- wall-clock timeout --------------------------------------------------------------------


async def test_wall_clock_timeout_cancels_and_audits(
    build_gateway: BuildGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    gw, _audit, _counter, cfg = build_gateway([_txt("never reached")])

    async def _slow(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        await asyncio.sleep(5)
        return {}

    monkeypatch.setattr(gw._agent, "ainvoke", _slow)
    # A tiny wall clock (float via model_copy; pydantic does not re-validate the copy). Patch the
    # resolver on the class — a pydantic model instance rejects setattr of a non-field method.
    tiny = gw._cfg.budgets.per_run.default.model_copy(update={"wall_clock_s": 0.05})
    monkeypatch.setattr(type(gw._cfg.budgets), "profile", lambda _self, name="default": tiny)

    result = await gw.run(
        "thread-t", "hang", principal="sandipan", interface="cli", environment="staging"
    )

    assert result.error == "wall clock exceeded"
    assert result.budget_stop == {"kind": "wall_clock", "limit": 0.05}
    types = _event_types(cfg, result.run_id)
    assert types == ["run_started", "budget_trip", "run_completed"]
    assert verify_run_file(Path(cfg.audit.dir) / f"{result.run_id}.jsonl").ok


# -- recursion limit -----------------------------------------------------------------------


async def test_recursion_error_maps_to_friendly_error(
    build_gateway: BuildGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    gw, _audit, _counter, cfg = build_gateway([_txt("never reached")])

    async def _boom(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise GraphRecursionError("recursion limit reached")

    monkeypatch.setattr(gw._agent, "ainvoke", _boom)

    result = await gw.run(
        "thread-x", "loop", principal="sandipan", interface="cli", environment="staging"
    )

    assert result.error == "recursion limit exceeded"
    assert result.budget_stop is not None and result.budget_stop["kind"] == "recursion"
    assert _event_types(cfg, result.run_id) == ["run_started", "budget_trip", "run_completed"]


# -- unexpected error path -----------------------------------------------------------------


async def test_unexpected_error_closes_chain_and_wraps(
    build_gateway: BuildGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    gw, _audit, _counter, cfg = build_gateway([_txt("never reached")])

    async def _boom(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise ValueError("kaboom")

    monkeypatch.setattr(gw._agent, "ainvoke", _boom)

    with pytest.raises(GatewayRunError) as excinfo:
        await gw.run("thread-e", "x", principal="sandipan", interface="cli", environment="staging")

    assert isinstance(excinfo.value.cause, ValueError)
    # The chain was still closed with an error status before re-raising.
    assert _event_types(cfg, excinfo.value.run_id) == ["run_started", "run_completed"]


async def test_stream_unexpected_error_closes_chain_and_ends_with_runend(
    build_gateway: BuildGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A mid-stream unexpected error must close the chain and surface as a RunEnd (never raise).

    The CLI REPL streams exclusively, so an escaping error would crash it and leave the audit
    chain open. Instead the gateway must catch it, write ``run_completed(status=error)``, and
    yield a terminal :class:`RunEnd` whose :class:`RunResult` carries a friendly error string —
    the REPL then renders the error (``result.error``) and stays alive. Modelled here as a fake
    ``astream`` that emits one assistant chunk (proving output already flowed) and then raises.
    """
    gw, _audit, _counter, cfg = build_gateway([_txt("never reached")])

    async def _boom_stream(*_args: Any, **_kwargs: Any) -> AsyncIterator[tuple[str, Any]]:
        yield "updates", {"model": {"messages": [AIMessage(content="partial ")]}}
        raise ValueError("kaboom")

    monkeypatch.setattr(gw._agent, "astream", _boom_stream)

    events = [
        ev
        async for ev in gw.stream(
            "thread-se", "x", principal="sandipan", interface="cli", environment="staging"
        )
    ]

    # The pre-error assistant text still streamed (mid-stream failure, not a pre-run one).
    texts = [e for e in events if isinstance(e, AssistantText)]
    assert any(t.text.strip() == "partial" for t in texts)
    # No raise: the stream terminated with exactly one RunEnd, and it is the last event.
    ends = [e for e in events if isinstance(e, RunEnd)]
    assert len(ends) == 1
    assert isinstance(events[-1], RunEnd)
    # The RunEnd carries a friendly, REPL-renderable error (RunResult.error is what the REPL
    # prints in red); no cost/text is attributed to the failed turn.
    assert isinstance(ends[0].result, RunResult)
    assert ends[0].result.error
    assert ends[0].result.final_text == ""
    assert ends[0].result.cost_usd_authoritative == 0.0
    # The chain was still closed with an error status (run_started -> run_completed) and verifies.
    assert _event_types(cfg, ends[0].result.run_id) == ["run_started", "run_completed"]
    assert _run_completed_summary(cfg, ends[0].result.run_id)["status"] == "error"
    assert verify_run_file(Path(cfg.audit.dir) / f"{ends[0].result.run_id}.jsonl").ok


# -- finalize accounting outage ------------------------------------------------------------


class _RaisingAddCounter(InMemoryDailyCounter):
    """A counter whose ``add`` always raises — models a daily-counter outage at the finalize
    top-up. ``total`` still works so the pre-check and in-graph ``before_model`` gates pass."""

    async def add(self, scope: str, usd: float) -> float:
        raise RuntimeError("counter outage")


async def test_finalize_counter_outage_completes_run_and_flags_failure(
    build_gateway: BuildGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A counter outage at the finalize top-up must be guarded: the run still completes.

    ``_finalize`` runs outside ``run()``'s try/except, so an unguarded ``counter.add`` raise at
    finalize would escape with no ``run_completed``. The scripted turn carries no usage_metadata,
    so the in-graph middleware charges nothing during the run — the ONLY ``add`` is the finalize
    delta. The gateway sees a non-empty callback aggregate, computes a positive delta, and its
    top-up ``add`` raises; that must be caught, flagged ``counter_write_failed``, and NOT crash
    the turn. The authoritative figure (which priced fine) is preserved.
    """
    counter = _RaisingAddCounter()
    gw, _audit, _cnt, cfg = build_gateway([_txt("done.")], counter=counter)
    # Force a positive finalize delta so the guarded top-up counter.add is actually exercised.
    monkeypatch.setattr(gw, "_usage_aggregate", lambda _cb: {_MAIN: usage(input=1000, output=200)})

    result = await gw.run(
        "thread-f", "hi", principal="sandipan", interface="cli", environment="staging"
    )

    # The run completed: no raise, no error surfaced to the caller.
    assert result.error is None
    assert result.final_text == "done."
    # Pricing succeeded even though the counter write did not — authoritative is preserved.
    assert result.cost_usd_authoritative == pytest.approx(0.01)  # (1000*5 + 200*25)/1e6
    # The counter outage is flagged, never raised.
    assert result.usage["counter_write_failed"] is True
    # The chain still closed and verifies, with the flag recorded in the run_completed summary.
    types = _event_types(cfg, result.run_id)
    assert types[0] == "run_started" and types[-1] == "run_completed"
    assert verify_run_file(Path(cfg.audit.dir) / f"{result.run_id}.jsonl").ok
    summary = _run_completed_summary(cfg, result.run_id)
    assert summary["status"] == "completed"
    assert summary["usage"]["counter_write_failed"] is True


# -- cancel --------------------------------------------------------------------------------


async def test_cancel_interrupts_in_flight_run(
    build_gateway: BuildGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    gw, _audit, _counter, _cfg = build_gateway([_txt("never reached")])

    async def _slow(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        await asyncio.sleep(5)
        return {}

    monkeypatch.setattr(gw._agent, "ainvoke", _slow)

    task = asyncio.ensure_future(
        gw.run("thread-c", "hang", principal="sandipan", interface="cli", environment="staging")
    )
    await asyncio.sleep(0.1)  # let the run reach its guarded await
    await gw.cancel("thread-c")
    result = await task

    assert result.error == "run cancelled"
    assert result.budget_stop is not None and result.budget_stop["kind"] == "cancelled"


# -- escalation: suspend + resume accounting + checkpointer file ----------------------------


_DELETE = ["kubectl", "delete", "pod", "x", "-n", "web"]


class _CountingExecutor:
    """A run_command executor stand-in that counts executions (no real subprocess)."""

    def __init__(self, home: str) -> None:
        self._home = home
        self.count = 0

    @property
    def home(self) -> str:
        return self._home

    async def execute(self, argv: list[str], timeout_s: int, env: dict[str, str]) -> ExecResult:
        self.count += 1
        return ExecResult(exit_code=0, output="ok", duration_ms=1, timed_out=False)


async def test_run_suspends_on_escalation_then_resume_accounts_and_completes_once(
    build_gateway: BuildGateway,
) -> None:
    """A run that escalates returns interrupted (chain OPEN); resume finishes it, one completion."""
    gw, _audit, counter, cfg = build_gateway(
        [
            _tc(_DELETE, "call-del", usage_metadata=usage(input=1000, output=200)),
            _txt("Left the pod alone.", usage_metadata=usage(input=500, output=50)),
        ]
    )

    run_result = await gw.run(
        "thread-esc", "delete pod x", principal="sandipan", interface="cli", environment="staging"
    )

    # SUSPENDED: an Escalation is surfaced and the chain is still open (no run_completed yet).
    assert run_result.interrupted is not None
    assert isinstance(run_result.interrupted, Escalation)
    assert run_result.interrupted.thread_id == "thread-esc"
    payload = run_result.interrupted.payload
    assert payload["review_configs"][0]["rule_id"] == "kubectl-delete-workload-escalate"
    types = _event_types(cfg, run_result.run_id)
    assert "escalation" in types
    assert "run_completed" not in types
    # Only the first segment's spend so far.
    assert run_result.cost_usd_state == pytest.approx(0.01)

    # RESUME (reject): the run completes; cost accumulates across the segment; ONE run_completed.
    resumed = await gw.resume_interrupt(
        "thread-esc", [{"type": "reject", "message": "no"}], approver="alice"
    )
    assert resumed.interrupted is None
    assert resumed.run_id == run_result.run_id  # same run continued
    assert resumed.final_text == "Left the pod alone."
    assert resumed.cost_usd_state == pytest.approx(0.01375)  # 0.01 + 0.00375
    assert await counter.total("global") == pytest.approx(0.01375)

    types = _event_types(cfg, resumed.run_id)
    assert types.count("run_completed") == 1  # exactly one completion at the true end
    assert types.count("escalation") == 1 and types.count("resolution") == 1
    resolution = next(
        e for e in _read_events(cfg, resumed.run_id) if e["event_type"] == "resolution"
    )
    assert resolution["approver"] == "alice"
    assert verify_run_file(Path(cfg.audit.dir) / f"{resumed.run_id}.jsonl").ok


async def test_stream_emits_escalation_event_then_runend(build_gateway: BuildGateway) -> None:
    """The stream surfaces an EscalationEvent (with the review payload) just before the RunEnd."""
    from opendevops.gateway import EscalationEvent

    gw, _audit, _counter, _cfg = build_gateway(
        [
            _tc(_DELETE, "call-del", usage_metadata=usage(input=10, output=2)),
            _txt("done."),
        ]
    )
    events = [
        ev
        async for ev in gw.stream(
            "thread-se",
            "delete pod x",
            principal="sandipan",
            interface="cli",
            environment="staging",
        )
    ]

    escalations = [e for e in events if isinstance(e, EscalationEvent)]
    ends = [e for e in events if isinstance(e, RunEnd)]
    assert len(escalations) == 1
    assert (
        escalations[0].escalation.payload["review_configs"][0]["rule_id"]
        == "kubectl-delete-workload-escalate"
    )
    # The EscalationEvent is the second-to-last event; RunEnd is last and carries the Escalation.
    assert isinstance(events[-1], RunEnd)
    assert isinstance(events[-2], EscalationEvent)
    assert ends[0].result.interrupted is not None


async def test_checkpointer_file_created_in_secure_state_dir(
    build_gateway: BuildGateway,
) -> None:
    gw, _audit, _counter, cfg = build_gateway([_txt("hi", usage_metadata=usage(input=1, output=1))])
    await gw.run("thread-cp", "hi", principal="sandipan", interface="cli", environment="staging")

    state_dir = cfg.state.dir
    assert state_dir.is_dir()
    assert oct(state_dir.stat().st_mode & 0o777) == "0o700"
    assert (state_dir / "checkpoints.sqlite3").exists()


async def test_run_scoped_dry_run_not_reused_across_runs_on_a_thread(
    build_gateway: BuildGateway, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A turn-N server dry-run must NOT validate a turn-N+1 real apply (run-scoping).

    Two runs share one thread (so the checkpointer carries ``files`` + ``dry_run_ok`` across them).
    Run 1 dry-runs manifest A. Run 2's ``--dry-run=none`` apply of A is DENIED (run 1's recorded
    sha is scoped to run 1's id), and only ALLOWED after run 2 dry-runs A itself.
    """
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(run_command_mod, "_DEFAULT_EXECUTOR", _CountingExecutor(str(home)))

    manifest_path = "/manifests/a.yaml"
    manifest = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n"
    gw, _audit, _counter, cfg = build_gateway(
        [
            # Run 1: write A, then a bare apply (rewritten to --dry-run=server; records {run1:sha}).
            _wf(manifest_path, manifest, "r1-write"),
            _tc(["kubectl", "apply", "-f", manifest_path], "r1-dry"),
            _txt("Dry-ran A."),
            # Run 2 (same thread): a real apply of A — DENIED (run 1's dry-run is not reused)...
            _tc(["kubectl", "apply", "-f", manifest_path, "--dry-run=none"], "r2-real-denied"),
            # ...then run 2 dry-runs A itself (records {run2:sha})...
            _tc(["kubectl", "apply", "-f", manifest_path], "r2-dry"),
            # ...and the real apply is now permitted.
            _tc(["kubectl", "apply", "-f", manifest_path, "--dry-run=none"], "r2-real-ok"),
            _txt("Applied A for real."),
        ],
        rw=True,
    )

    r1 = await gw.run(
        "thread-dry", "dry-run A", principal="sandipan", interface="cli", environment="staging"
    )
    r2 = await gw.run(
        "thread-dry", "apply A", principal="sandipan", interface="cli", environment="staging"
    )

    e1 = _read_events(cfg, r1.run_id)
    e2 = _read_events(cfg, r2.run_id)

    def _decision(events: list[dict[str, Any]], tcid: str) -> dict[str, Any]:
        return next(
            e for e in events if e["event_type"] == "decision" and e.get("tool_call_id") == tcid
        )

    # Run 1 recorded a server dry-run (rewrite).
    assert _decision(e1, "r1-dry")["decision"]["rule_id"] == "force-server-dry-run-first"
    # Run 2's first real apply is DENIED — run 1's dry-run did NOT carry over.
    r2_denied = _decision(e2, "r2-real-denied")["decision"]
    assert r2_denied["effect"] == "deny"
    assert r2_denied["rule_id"] == "require-dry-run-before-real-apply"
    # After run 2 dry-runs A itself, the real apply is permitted.
    assert _decision(e2, "r2-real-ok")["decision"]["effect"] == "allow"
    assert _decision(e2, "r2-real-ok")["decision"]["rule_id"] == "kubectl-apply"


# -- summarizer replacement: REAL trigger -> haiku in authoritative, not state ----


async def test_summarizer_trigger_adds_haiku_delta_to_authoritative(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A REAL summarization trigger during a run: the haiku summarizer call lands in the callback
    aggregate (authoritative) but not in state (the in-graph middleware only prices the MAIN
    model), so the run's authoritative cost exceeds state by exactly the summarizer's usage, and
    the daily counter is topped up with only that delta.

    The default (main-model) summarizer is replaced by our haiku one via the harness-profile
    exclusion, so the summary model call is priced on the haiku row. Summarization is forced to
    fire mid-run by lowering the deepagents factory's trigger/keep defaults.
    """
    import deepagents.middleware.summarization as summ_mod

    monkeypatch.setattr(
        summ_mod,
        "compute_summarization_defaults",
        lambda _m: {
            "trigger": ("messages", 3),
            "keep": ("messages", 2),
            "truncate_args_settings": {"trigger": ("messages", 9999), "keep": ("messages", 9999)},
        },
    )
    # Distinct MAIN (opus) and SUMMARIZER (haiku) fakes, dispatched on the agent role.
    main_fake = BindableFake(
        messages=iter(
            [
                _tc(_PODS, "c1", usage_metadata=usage(input=1000, output=200)),
                _tc(
                    ["kubectl", "get", "svc", "-n", "default"],
                    "c2",
                    usage_metadata=usage(input=1000, output=200),
                ),
                _txt("all healthy.", usage_metadata=usage(input=500, output=50)),
            ]
        )
    )
    haiku_fake = BindableFake(
        messages=iter(
            [
                AIMessage(
                    content="SUMMARY of prior context",
                    usage_metadata=usage(input=2000, output=100),  # haiku: 0.0025
                    response_metadata={"model_name": _SUMMARIZER},
                )
            ]
        )
    )
    monkeypatch.setattr(
        registry,
        "build_chat_model",
        lambda _cfg, name: haiku_fake if name == "summarizer" else main_fake,
    )

    cfg = _make_cfg(tmp_path)
    counter = InMemoryDailyCounter()
    gw = LocalGateway(cfg, audit=AuditLogger(cfg.audit.dir), counter=counter)
    try:
        result = await gw.run(
            "thread-sum",
            "investigate",
            principal="sandipan",
            interface="cli",
            environment="staging",
        )
    finally:
        await gw.aclose()

    # State = MAIN (opus) only: 2 tool turns (0.01 each) + final text (0.00375) = 0.02375.
    assert result.cost_usd_state == pytest.approx(0.02375)
    # Authoritative adds the haiku summarizer usage (2000*1 + 100*5)/1e6 = 0.0025.
    assert result.cost_usd_authoritative == pytest.approx(0.02625)
    assert result.cost_usd_authoritative > result.cost_usd_state
    # The daily counter received the middleware's opus charge + the gateway's haiku delta.
    assert await counter.total("global") == pytest.approx(0.02625)


# -- log-summarizer subagent: REAL task-wrap accounting (haiku spend is authoritative) --


async def test_log_summarizer_subagent_spend_lands_in_authoritative(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The haiku log-summarizer subagent's model call is captured by the run's authoritative ledger.

    This is the §3.4 "subagents included" claim, now actually exercised end-to-end (NOT a
    monkeypatched aggregate): the MAIN (opus) model calls the ``task`` tool with
    ``subagent_type=log-summarizer`` (policy-allowed), deepagents invokes the tool-less haiku
    subagent inside that tool call, and because that runs within the gateway's
    ``get_usage_metadata_callback()`` scope (an inheritable contextvar), the subagent's usage lands
    in the authoritative aggregate. The in-graph middleware prices only the MAIN model, so
    authoritative EXCEEDS state by exactly the subagent's spend, and the daily counter is topped up
    with that delta.
    """
    # Distinct MAIN (opus) and SUBAGENT (haiku) fakes, dispatched on the agent role.
    main_fake = BindableFake(
        messages=iter(
            [
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "task",
                            "args": {
                                "description": "Summarize these crashloop logs: <...>",
                                "subagent_type": "log-summarizer",
                            },
                            "id": "call-sub",
                            "type": "tool_call",
                        }
                    ],
                    usage_metadata=usage(input=1000, output=200),  # opus: 0.01
                    response_metadata={"model_name": _MAIN},
                ),
                _txt(
                    "RCA: the container OOMs on startup.",
                    usage_metadata=usage(input=500, output=50),
                ),
            ]
        )
    )
    sub_fake = BindableFake(
        messages=iter(
            [
                AIMessage(
                    content="DIGEST: OOMKilled x7; exit 137; memory limit 128Mi exceeded at boot.",
                    usage_metadata=usage(input=2000, output=100),  # haiku: 0.0025
                    response_metadata={"model_name": _SUMMARIZER},
                )
            ]
        )
    )
    monkeypatch.setattr(
        registry,
        "build_chat_model",
        lambda _cfg, name: sub_fake if name == "log_summarizer" else main_fake,
    )

    cfg = _make_cfg(tmp_path)
    counter = InMemoryDailyCounter()
    gw = LocalGateway(cfg, audit=AuditLogger(cfg.audit.dir), counter=counter)
    try:
        result = await gw.run(
            "thread-sub",
            "investigate",
            principal="sandipan",
            interface="cli",
            environment="staging",
        )
    finally:
        await gw.aclose()

    # State = MAIN (opus) only: task-call turn (0.01) + final text (0.00375) = 0.01375.
    assert result.cost_usd_state == pytest.approx(0.01375)
    # Authoritative adds the haiku subagent usage (2000*1 + 100*5)/1e6 = 0.0025.
    assert result.cost_usd_authoritative == pytest.approx(0.01625)
    assert result.cost_usd_authoritative > result.cost_usd_state
    # The daily counter received the middleware's opus charge + the gateway's haiku subagent delta.
    assert await counter.total("global") == pytest.approx(0.01625)
    # The subagent actually ran: the main model's final answer follows the delegated digest.
    assert "OOMs on startup" in result.final_text


# -- stream consumer abandonment -------------------------------------------------


def _only_run_events(cfg: AppConfig) -> tuple[str, list[dict[str, Any]]]:
    """The (run_id, events) of the single run chain file under the tmp audit dir."""
    import json

    files = list(Path(cfg.audit.dir).glob("*.jsonl"))
    assert len(files) == 1, f"expected exactly one run file, got {files}"
    events = [json.loads(line) for line in files[0].read_text().splitlines() if line.strip()]
    return files[0].stem, events


async def test_stream_abandonment_closes_chain_as_abandoned(build_gateway: BuildGateway) -> None:
    """Abandoning the stream (aclose after one event) closes the audit chain as ``abandoned``.

    Left unhandled, an abandoned stream leaks an open chain (``run_started`` with no
    ``run_completed``). The gateway must catch GeneratorExit, cancel the in-flight task, and close
    the chain — verified here by consuming a single event, ``aclose()``-ing, then reading the chain.
    """
    gw, _audit, _counter, cfg = build_gateway(
        [
            _tc(_PODS, "c1", usage_metadata=usage(input=1000, output=200)),
            _txt("done.", usage_metadata=usage(input=500, output=50)),
        ]
    )
    agen = gw.stream(
        "thread-ab", "list pods", principal="sandipan", interface="cli", environment="staging"
    )
    first = await agen.__anext__()  # consume exactly one event, then abandon
    assert isinstance(first, (ToolCall, AssistantText, ToolResult))
    await agen.aclose()

    # No in-flight task lingers for the thread.
    assert "thread-ab" not in gw._tasks
    # The chain closed with an ``abandoned`` run_completed and still verifies.
    _run_id, events = _only_run_events(cfg)
    types = [e["event_type"] for e in events]
    assert types[0] == "run_started"
    assert types[-1] == "run_completed"
    assert events[-1]["summary"]["status"] == "abandoned"
    assert verify_run_file(Path(cfg.audit.dir) / f"{_run_id}.jsonl").ok


async def test_stream_resume_abandonment_closes_chain_and_kills_pending_interrupt(
    build_gateway: BuildGateway,
) -> None:
    """Abandoning a RESUMED stream must CLOSE the escalation chain, not leak it.

    Without a symmetric GeneratorExit guard, ``stream_resume`` leaked a permanently unclosable
    chain: ``_pop_suspended`` runs before the first yield, so an ``aclose()`` mid-resume left
    ``run_started/decision/escalation/resolution`` open forever AND the suspended record already
    gone (a second resume would raise). Disposition (a): cancel the in-flight task, close the chain
    as ``abandoned``, and — deliberately — leave the pending interrupt dead, so a subsequent
    ``resume_interrupt`` raises the friendly :class:`GatewayError`.
    """
    gw, _audit, _counter, cfg = build_gateway(
        [
            _tc(_DELETE, "call-del", usage_metadata=usage(input=1000, output=200)),
            _txt("Left the pod alone.", usage_metadata=usage(input=500, output=50)),
        ]
    )
    run_result = await gw.run(
        "thread-rab",
        "delete pod x",
        principal="sandipan",
        interface="cli",
        environment="staging",
    )
    # SUSPENDED on the escalation: the chain is open (no run_completed yet).
    assert isinstance(run_result.interrupted, Escalation)
    assert "run_completed" not in _event_types(cfg, run_result.run_id)

    # RESUME (reject), consume exactly one event, then abandon the generator.
    agen = gw.stream_resume("thread-rab", [{"type": "reject", "message": "no"}], approver="alice")
    first = await agen.__anext__()
    assert isinstance(first, (ToolCall, AssistantText, ToolResult))
    await agen.aclose()

    # No in-flight task lingers for the thread.
    assert "thread-rab" not in gw._tasks
    # The escalation chain is now CLOSED as ``abandoned`` (run_completed last) and still verifies.
    events = _read_events(cfg, run_result.run_id)
    types = [e["event_type"] for e in events]
    assert types[0] == "run_started"
    assert types[-1] == "run_completed"
    assert types.count("run_completed") == 1
    assert "escalation" in types and "resolution" in types
    assert events[-1]["summary"]["status"] == "abandoned"
    assert verify_run_file(Path(cfg.audit.dir) / f"{run_result.run_id}.jsonl").ok

    # Disposition (a): the suspended record was NOT re-registered, so the pending interrupt is
    # dead — a second resume raises the friendly GatewayError rather than resuming a closed chain.
    assert "thread-rab" not in gw._suspended
    with pytest.raises(GatewayError, match="no suspended run to resume"):
        await gw.resume_interrupt(
            "thread-rab", [{"type": "reject", "message": "no"}], approver="bob"
        )


# -- interrupted-run accounting: guarded pricing + usage detail --------------


class _RaisingPriceTable:
    """A price table whose ``cost_usd`` always raises — models a pricing outage at finalize."""

    prices: dict[str, Any] = {}

    def cost_usd(self, model_key: str, usage: Any) -> float:
        raise RuntimeError("price table down")


def _tiny_wall_clock(gw: LocalGateway, monkeypatch: pytest.MonkeyPatch) -> None:
    """Force a ~instant wall-clock timeout for the next run."""
    tiny = gw._cfg.budgets.per_run.default.model_copy(update={"wall_clock_s": 0.05})
    monkeypatch.setattr(type(gw._cfg.budgets), "profile", lambda _self, name="default": tiny)


async def test_interrupted_run_guards_pricing_raise(
    build_gateway: BuildGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pricing raise in ``_interrupted`` must not mask the timeout or leave the chain open.

    ``_price_aggregate`` is guarded like ``_account_segment``: a raising price table degrades the
    interrupted run to zero cost/usage plus a logged exception, and the chain still closes.
    """
    gw, _audit, _counter, cfg = build_gateway([_txt("never reached")])

    async def _slow(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        await asyncio.sleep(5)
        return {}

    monkeypatch.setattr(gw._agent, "ainvoke", _slow)
    _tiny_wall_clock(gw, monkeypatch)
    monkeypatch.setattr(gw, "_price_table", _RaisingPriceTable())
    monkeypatch.setattr(gw, "_usage_aggregate", lambda _cb: {_MAIN: usage(input=1000, output=200)})

    # Must NOT raise; the chain still closes with the timeout mapping intact.
    result = await gw.run(
        "thread-pg", "hang", principal="sandipan", interface="cli", environment="staging"
    )

    assert result.error == "wall clock exceeded"
    assert result.budget_stop == {"kind": "wall_clock", "limit": 0.05}
    # Guarded pricing degraded to zero cost/usage rather than escaping.
    assert result.cost_usd_authoritative == 0.0
    assert result.usage == {}
    assert _event_types(cfg, result.run_id) == ["run_started", "budget_trip", "run_completed"]
    assert verify_run_file(Path(cfg.audit.dir) / f"{result.run_id}.jsonl").ok


async def test_interrupted_run_includes_partial_usage_detail(
    build_gateway: BuildGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An interrupted run carries the callback aggregate's partial token usage (regression pin)."""
    gw, _audit, _counter, cfg = build_gateway([_txt("never reached")])

    async def _slow(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        await asyncio.sleep(5)
        return {}

    monkeypatch.setattr(gw._agent, "ainvoke", _slow)
    _tiny_wall_clock(gw, monkeypatch)
    monkeypatch.setattr(gw, "_usage_aggregate", lambda _cb: {_MAIN: usage(input=1000, output=200)})

    result = await gw.run(
        "thread-ud", "hang", principal="sandipan", interface="cli", environment="staging"
    )

    assert result.error == "wall clock exceeded"
    # The partial token detail from the callback is surfaced on the RunResult.
    assert result.usage["input_tokens"] == 1000
    assert result.usage["output_tokens"] == 200
    # Priced with the main (opus) row: (1000*5 + 200*25)/1e6 = 0.01.
    assert result.cost_usd_authoritative == pytest.approx(0.01)
