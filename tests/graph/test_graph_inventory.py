"""Scenario 3: the boot-time tool-inventory assertion + neutralization of execute / scoping of task.

Covers:
* the *real* build (real ChatAnthropic model) binds ``task`` as an active tool exposing ONLY the
  named log-summarizer subagent (the harness profile drops the general-purpose one) and passes the
  boot assertion (``execute`` stays bound but tolerated) — P5c;
* a fake-model build (where the harness profile does not apply) still binds ``task`` (with the
  general-purpose subagent too); a ``task`` call for an ARBITRARY subagent is hard-denied by policy,
  and ``execute`` is hard-denied when the model calls it;
* the assertion actually checks — shrinking ``EXPECTED_ACTIVE`` makes it fail boot.
"""

from __future__ import annotations

from typing import Any

import pytest
from langchain_core.messages import ToolMessage

import opendevops.agent as agent_mod
from opendevops.agent import (
    EXPECTED_ACTIVE,
    TOLERATED_DENIED,
    _bound_tool_names,
    build_agent,
)
from opendevops.audit.logger import AuditLogger
from opendevops.budget.daily import InMemoryDailyCounter

from .helpers import ai_text, ai_tool_call, invoke_config, make_context, make_fake_model, start_run


def test_real_build_binds_scoped_task_tolerates_execute(cfg: Any, monkeypatch: Any) -> None:
    """The real build binds exactly the active tools (incl. ``task``) + the tolerated ``execute``.

    ``task`` is an ACTIVE tool now (P5c): the build passes the named log-summarizer subagent, so
    ``task`` is bound; the harness profile drops the auto-added general-purpose subagent, so
    production ``task`` exposes only that one subagent. The boot assertion passes.
    """
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-used-at-construction")
    graph = build_agent(cfg, audit=AuditLogger(cfg.audit.dir), counter=InMemoryDailyCounter())

    bound = _bound_tool_names(graph)
    assert bound >= EXPECTED_ACTIVE, f"missing active tools: {sorted(EXPECTED_ACTIVE - bound)}"
    assert "task" in bound, "task is an active (policy-scoped) tool once a named subagent is passed"
    assert "execute" in bound, "execute is bound by the required FilesystemMiddleware (tolerated)"
    # Nothing bound beyond the active tools + the tolerated built-ins.
    assert bound - EXPECTED_ACTIVE <= TOLERATED_DENIED


async def test_fake_build_denies_arbitrary_subagent(built_agent: Any, cfg: Any) -> None:
    """A ``task`` call for an ARBITRARY subagent_type is denied by policy, not executed (P5c).

    The subagent never runs (the fake model would have to script the subagent turn); the denial
    lands as a ``no-arbitrary-subagents`` deny ToolMessage and the model self-corrects.
    """
    fake = make_fake_model(
        [
            ai_tool_call(
                "task",
                {"description": "do work", "subagent_type": "general-purpose"},
                "call-task",
            ),
            ai_text("Only the log-summarizer subagent is available."),
        ]
    )
    graph, audit, _ = built_agent(fake)
    ctx = make_context("run-task-deny")
    start_run(audit, ctx)

    out = await graph.ainvoke(
        {"messages": [("user", "spawn a subagent")]},
        config=invoke_config(ctx.run_id),
        context=ctx,
    )

    tool_msgs = [m for m in out["messages"] if isinstance(m, ToolMessage)]
    assert any("Denied by policy [no-arbitrary-subagents]" in m.content for m in tool_msgs)


async def test_fake_build_denies_execute(built_agent: Any, cfg: Any) -> None:
    """The bound-but-inert ``execute`` shell tool is hard-denied by policy when called."""
    fake = make_fake_model(
        [
            ai_tool_call("execute", {"command": "id"}, "call-exec"),
            ai_text("The shell execute tool is disabled."),
        ]
    )
    graph, audit, _ = built_agent(fake)
    ctx = make_context("run-exec-deny")
    start_run(audit, ctx)

    out = await graph.ainvoke(
        {"messages": [("user", "run a shell command")]},
        config=invoke_config(ctx.run_id),
        context=ctx,
    )

    tool_msgs = [m for m in out["messages"] if isinstance(m, ToolMessage)]
    assert any("Denied by policy [no-builtin-shell-execute]" in m.content for m in tool_msgs)


def test_inventory_assertion_actually_checks(built_agent: Any, monkeypatch: Any) -> None:
    """Shrinking EXPECTED_ACTIVE turns the built-in FS tools into surplus and fails boot."""
    monkeypatch.setattr(agent_mod, "EXPECTED_ACTIVE", frozenset({"run_command"}))
    with pytest.raises(RuntimeError, match="tool inventory mismatch"):
        built_agent(make_fake_model([ai_text("x")]))


def _subagent_graph(graph: Any, name: str) -> Any:
    """Extract the compiled subagent runnable the ``task`` tool routes ``name`` to.

    The ``task`` StructuredTool closes over a ``subagent_graphs`` ``{name: runnable}`` dict
    (deepagents ``_build_task_tool``); read it through the closure.
    """
    task_tool = graph.nodes["tools"].bound.tools_by_name["task"]
    func = task_tool.func
    closure = dict(zip(func.__code__.co_freevars, func.__closure__ or (), strict=False))
    graphs = closure["subagent_graphs"].cell_contents
    return graphs[name]


def test_log_summarizer_subagent_is_tool_less(cfg: Any, monkeypatch: Any) -> None:
    """The log-summarizer subagent has NO tools — it cannot reach run_command / execute / anything.

    Proven two ways: the builder's runnable has no ``tools`` node, and the SAME is true of the
    subagent graph the wired ``task`` tool actually routes to in the real build.
    """
    from opendevops.agent import _build_log_summarizer_subagent
    from opendevops.policy.engine import LOG_SUMMARIZER_SUBAGENT

    spec = _build_log_summarizer_subagent(cfg)
    assert spec["name"] == LOG_SUMMARIZER_SUBAGENT
    # A tool-less langchain create_agent graph has no "tools" node at all (only __start__ + model).
    assert "tools" not in spec["runnable"].nodes

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-used-at-construction")
    graph = build_agent(cfg, audit=AuditLogger(cfg.audit.dir), counter=InMemoryDailyCounter())
    sub = _subagent_graph(graph, LOG_SUMMARIZER_SUBAGENT)
    assert "tools" not in sub.nodes, "the log-summarizer subagent must expose no tools"
