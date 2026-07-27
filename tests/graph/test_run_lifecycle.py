"""RunLifecycleMiddleware: in-graph audit book-ends for the SERVER build path.

In service mode the graph runs inside the LangGraph Server, so ``ServerGateway`` (a different host)
cannot write the ``run_started`` / ``run_completed`` book-ends where the in-graph
``decision`` / ``execution`` events land. :class:`~opendevops.agent.RunLifecycleMiddleware`
(enabled via ``build_agent(..., run_lifecycle=True)``) writes them in-graph, in the SAME per-run
chain file — chain locality. These tests build the REAL agent with an injected fake model and,
crucially, do NOT seed the chain the way the gateway would: the middleware must do it.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import aiosqlite
import pytest
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
    event_types,
    invoke_config,
    make_context,
    make_fake_model,
    read_events,
    usage,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_DIR = REPO_ROOT / "config" / "policy"
_DELETE_ARGV = ["kubectl", "delete", "pod", "x", "-n", "web"]


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
    """A config with a rw kubeconfig, so the escalate rule's ``channel: rw`` execution resolves."""
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
                "aws": {
                    "credential_env": ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"],
                    "credential_env_rw": ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"],
                },
                "gcloud": {
                    "credential_env": ["GOOGLE_APPLICATION_CREDENTIALS"],
                    "credential_env_rw": ["GOOGLE_APPLICATION_CREDENTIALS"],
                },
                "azure": {
                    "credential_env": ["AZURE_CLIENT_ID", "AZURE_TENANT_ID"],
                    "credential_env_rw": ["AZURE_CLIENT_ID", "AZURE_TENANT_ID"],
                },
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


async def test_server_build_writes_book_ends_in_chain_without_gateway_seed(
    built_agent: Any, cfg: Any
) -> None:
    """A run_lifecycle graph seeds + closes the chain itself (no gateway start_run/end_run)."""
    fake = make_fake_model(
        [ai_text("Pods look healthy.", usage_metadata=usage(input=1000, output=200))]
    )
    graph, _audit, _counter = built_agent(fake, run_lifecycle=True)
    ctx = make_context("run-srv-text")  # NOTE: no start_run(...) — the middleware must seed it.

    await graph.ainvoke(
        {"messages": [("user", "list pods")]}, config=invoke_config(ctx.run_id), context=ctx
    )

    # The chain exists, is book-ended by the middleware, and verifies.
    assert event_types(cfg.audit.dir, ctx.run_id) == [
        "run_started",
        "model_call",
        "run_completed",
    ]
    assert chain_ok(cfg.audit.dir, ctx.run_id)

    events = read_events(cfg.audit.dir, ctx.run_id)
    started = events[0]
    assert started["principal"] == {"interface": "cli", "user": "sandipan"}
    assert started["environment"] == "staging"
    assert started["model"] == "anthropic:claude-opus-4-8"

    summary = events[-1]["summary"]
    assert summary["status"] == "completed"
    # Accounting divergence: authoritative == state, flagged unavailable (gateway cannot see calls).
    assert summary["cost_state"] > 0.0
    assert summary["cost_authoritative"] == summary["cost_state"]
    assert summary["usage"]["authoritative_unavailable"] is True


async def test_server_build_book_ends_wrap_in_graph_decision_event(
    built_agent: Any, cfg: Any
) -> None:
    """The in-graph decision event sits INSIDE the middleware's book-ends, one verified chain."""
    fake = make_fake_model(
        [
            ai_tool_call("run_command", {"argv": ["bash", "-c", "id"]}, "c1",
                         usage_metadata=usage(input=10, output=2)),
            ai_text("I can't run shell interpreters.", usage_metadata=usage(input=5, output=2)),
        ]
    )
    graph, _audit, _counter = built_agent(fake, run_lifecycle=True)
    ctx = make_context("run-srv-deny")

    await graph.ainvoke(
        {"messages": [("user", "run id")]}, config=invoke_config(ctx.run_id), context=ctx
    )

    types = event_types(cfg.audit.dir, ctx.run_id)
    # run_started seeds, the deny decision lands in-graph, run_completed closes — all one chain.
    assert types[0] == "run_started"
    assert types[-1] == "run_completed"
    assert "decision" in types
    assert chain_ok(cfg.audit.dir, ctx.run_id)


async def test_local_build_writes_no_book_ends_when_gateway_does_not_seed(
    built_agent: Any, cfg: Any
) -> None:
    """Without run_lifecycle AND without a gateway seed, no chain file is created (gate proof).

    This is what keeps LocalGateway byte-identical: the default build has no in-graph book-ends, so
    a text-only turn that the gateway did not seed writes nothing — the middleware is the only
    difference between the two build paths.
    """
    fake = make_fake_model([ai_text("hi", usage_metadata=usage(input=1, output=1))])
    graph, _audit, _counter = built_agent(fake, run_lifecycle=False)
    ctx = make_context("run-local-noseed")

    await graph.ainvoke(
        {"messages": [("user", "hi")]}, config=invoke_config(ctx.run_id), context=ctx
    )

    assert not (Path(cfg.audit.dir) / f"{ctx.run_id}.jsonl").exists()


# --------------------------------------------------------------------------------------
# durable rehydration across workers (Finding 1): a resume handled by a SECOND run_lifecycle
# graph with a FRESH AuditLogger on the same audit dir + shared checkpointer.
#
# Mirrors the reviewer's probe topology: worker 1 (graph1/audit1) suspends the escalation; worker 2
# (graph2/audit2 — a distinct AuditLogger with empty in-process state) picks up the approved resume.
# On resume the tools node re-executes BEFORE the lifecycle seed, so worker 2's FIRST disk touch is
# an append; without durable rehydration that raised UnknownRunError and PolicyMiddleware DENIED the
# human-approved action, then a second genesis run_started broke chain linkage. With rehydration:
# the approved tool runs EXACTLY once, the book-ends stay single, and the chain verifies.
# --------------------------------------------------------------------------------------


async def test_resume_on_fresh_logger_across_workers_executes_once_and_verifies(
    built_agent: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    spy = _CountingExecutor(str(home))
    monkeypatch.setattr(run_command_mod, "_DEFAULT_EXECUTOR", spy)

    cfg = _cfg_with_rw(tmp_path)
    saver, conn = await _saver()
    try:
        # Worker 1: build a run_lifecycle graph with its OWN fresh AuditLogger (audit1). It seeds
        # the chain (no gateway start_run) and suspends on the escalate interrupt.
        fake1 = make_fake_model([ai_tool_call("run_command", {"argv": _DELETE_ARGV}, "call-del")])
        graph1, audit1, _ = built_agent(
            fake1, cfg_override=cfg, checkpointer=saver, run_lifecycle=True
        )
        ctx = make_context("run-2worker")  # NOTE: no start_run — the middleware seeds it.

        suspended = await graph1.ainvoke(
            {"messages": [("user", "delete pod x")]},
            config=invoke_config(ctx.run_id),
            context=ctx,
        )
        assert "__interrupt__" in suspended
        assert spy.count == 0  # nothing executed while suspended
        # Worker 1 wrote run_started + the in-graph decision/escalation, chain still OPEN.
        types_after_suspend = event_types(cfg.audit.dir, ctx.run_id)
        assert types_after_suspend[0] == "run_started"
        assert "escalation" in types_after_suspend
        assert "run_completed" not in types_after_suspend

        # Worker 2: a SECOND run_lifecycle graph with a DISTINCT fresh AuditLogger (audit2, empty
        # in-process _runs) on the SAME audit dir + SAME checkpointer picks up the approved resume.
        fake2 = make_fake_model([ai_text("Deleted the pod.")])
        graph2, audit2, _ = built_agent(
            fake2, cfg_override=cfg, checkpointer=saver, run_lifecycle=True
        )
        assert audit2 is not audit1  # a genuinely fresh logger — the whole point of the probe

        final = await graph2.ainvoke(
            Command(resume={"decisions": [{"type": "approve", "approver": "alice"}]}),
            config=invoke_config(ctx.run_id),
            context=ctx,
        )

        # The human-approved action executed EXACTLY once (not fail-closed denied).
        assert spy.count == 1
        assert spy.argvs == [_DELETE_ARGV]
        tool_msgs = [
            m for m in final["messages"] if getattr(m, "type", None) == "tool"
        ]
        assert any("deleted" in str(m.content).lower() for m in tool_msgs)

        events = read_events(cfg.audit.dir, ctx.run_id)
        types = [e["event_type"] for e in events]
        # Book-ends are SINGLE (no second genesis seed, no double completion).
        assert types.count("run_started") == 1
        assert types.count("run_completed") == 1
        assert types[0] == "run_started"
        assert types[-1] == "run_completed"
        # The resume's decision/escalation replays deduped across the process boundary.
        assert types.count("decision") == 1
        assert types.count("escalation") == 1
        # Exactly one resolution, carrying the approver worker 2 injected.
        resolutions = [e for e in events if e["event_type"] == "resolution"]
        assert len(resolutions) == 1
        assert resolutions[0]["approver"] == "alice"
        # Exactly one execution for the escalated tool_call_id, and the chain VERIFIES.
        execs = [
            e
            for e in events
            if e["event_type"] == "execution" and e.get("tool_call_id") == "call-del"
        ]
        assert len(execs) == 1
        assert chain_ok(cfg.audit.dir, ctx.run_id)
    finally:
        await conn.close()
