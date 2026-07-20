"""Reusable graph-test helpers (importable by the T8 graph tests and T9's gateway tests).

Pure functions and small builders that pair with the fixtures in ``conftest.py``:

* :class:`BindableFake` / :func:`make_fake_model` — a ``GenericFakeChatModel`` whose
  ``bind_tools`` returns ``self`` (see docs/api-notes.md §7: a bare fake makes the graph raise
  ``NotImplementedError`` because the factory always calls ``model.bind_tools(...)``).
* :func:`ai_tool_call` / :func:`ai_text` / :func:`usage` — build the scripted ``AIMessage``s a
  fake model yields (a tool call, a final text turn, and a ``usage_metadata`` block).
* :func:`make_context` / :func:`start_run` / :func:`invoke_config` — the run-scoped
  ``AgentContext``, the audit-chain seed, and the langgraph invoke config.
* :func:`read_events` / :func:`event_types` / :func:`chain_ok` — read/verify the per-run audit
  chain the middleware wrote.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage

from opendevops.audit import verify_run_file
from opendevops.audit.logger import AuditLogger
from opendevops.context import AgentContext

# Mirrors config/models.yaml — main -> opus (priced), so build_agent's boot check passes.
# ``log_summarizer`` -> haiku is the P5c named subagent (see agent.py); build_agent resolves its
# model via ``registry.build_chat_model(cfg, "log_summarizer")`` so the alias must be present here.
MODELS: dict[str, Any] = {
    "agents": {"main": "opus", "summarizer": "haiku", "log_summarizer": "haiku"},
    "aliases": {
        "opus": "anthropic:claude-opus-4-8",
        "sonnet": "anthropic:claude-sonnet-5",
        "haiku": "anthropic:claude-haiku-4-5",
    },
    "pricing": {
        "anthropic:claude-opus-4-8": {
            "input": 5.00,
            "output": 25.00,
            "cache_read": 0.50,
            "cache_write": 6.25,
        },
        "anthropic:claude-sonnet-5": {
            "input": 3.00,
            "output": 15.00,
            "cache_read": 0.30,
            "cache_write": 3.75,
        },
        "anthropic:claude-haiku-4-5": {
            "input": 1.00,
            "output": 5.00,
            "cache_read": 0.10,
            "cache_write": 1.25,
        },
    },
    "fallback_pricing": "error",
}


def budgets(**default_overrides: Any) -> dict[str, Any]:
    """A budgets document with the shipped defaults, overriding fields on ``per_run.default``.

    (E.g. ``budgets(shell_calls=1)`` for the tool-call-limit scenario, or ``budgets(usd=2.0)``.)
    """
    default: dict[str, Any] = {
        "usd": 2.00,
        "model_calls": 50,
        "tool_calls": 100,
        "shell_calls": 30,
        "recursion_limit": 250,
        "wall_clock_s": 900,
    }
    default.update(default_overrides)
    return {
        "trip_ratio": 0.9,
        "fail_mode_on_counter_outage": "closed",
        "per_run": {"default": default, "profiles": {}},
        "daily": {"global_usd": 50.00, "per_principal_usd": 25.00},
    }


class BindableFake(GenericFakeChatModel):
    """A ``GenericFakeChatModel`` that tolerates the factory's ``bind_tools`` call.

    The deepagents factory always calls ``model.bind_tools(final_tools, ...)`` even when the
    tool set comes from middleware; the stock fake raises ``NotImplementedError`` there. Returning
    ``self`` makes the fake ignore the binding and replay its scripted messages.
    """

    def bind_tools(self, tools: Any, **kwargs: Any) -> BindableFake:
        return self


def make_fake_model(messages: Any) -> BindableFake:
    """Build a fake chat model that yields ``messages`` (a list or any iterable) in order."""
    return BindableFake(messages=iter(messages))


def usage(
    *, input: int = 0, output: int = 0, cache_read: int = 0, cache_creation: int = 0
) -> dict[str, Any]:
    """A langchain ``usage_metadata`` block in the exact shape ``PriceTable.cost_usd`` reads."""
    return {
        "input_tokens": input,
        "output_tokens": output,
        "total_tokens": input + output,
        "input_token_details": {"cache_read": cache_read, "cache_creation": cache_creation},
    }


def ai_tool_call(
    name: str, args: dict[str, Any], call_id: str, *, usage_metadata: dict[str, Any] | None = None
) -> AIMessage:
    """An ``AIMessage`` carrying a single tool call (and optional usage metadata)."""
    return AIMessage(
        content="",
        tool_calls=[{"name": name, "args": args, "id": call_id, "type": "tool_call"}],
        usage_metadata=usage_metadata,  # type: ignore[arg-type]
    )


def ai_text(text: str, *, usage_metadata: dict[str, Any] | None = None) -> AIMessage:
    """A plain final ``AIMessage`` (no tool call) that ends the agent loop."""
    return AIMessage(content=text, usage_metadata=usage_metadata)  # type: ignore[arg-type]


def make_context(
    run_id: str,
    *,
    principal: str = "sandipan",
    interface: str = "cli",
    environment: str = "staging",
    budget_profile: str = "default",
) -> AgentContext:
    """The run-scoped ``AgentContext`` the middleware reads from ``runtime.context``."""
    return AgentContext(
        principal=principal,
        interface=interface,  # type: ignore[arg-type]
        environment=environment,  # type: ignore[arg-type]
        budget_profile=budget_profile,
        run_id=run_id,
    )


def start_run(audit: AuditLogger, ctx: AgentContext) -> None:
    """Seed the audit chain for ``ctx.run_id`` (the gateway does this in production)."""
    audit.start_run(
        ctx.run_id,
        principal={"interface": ctx.interface, "user": ctx.principal},
        environment=ctx.environment,
    )


def invoke_config(run_id: str, *, recursion_limit: int | None = None) -> dict[str, Any]:
    """The langgraph invoke config (thread id + optional recursion limit override)."""
    config: dict[str, Any] = {"configurable": {"thread_id": run_id}}
    if recursion_limit is not None:
        config["recursion_limit"] = recursion_limit
    return config


def read_events(audit_dir: Path, run_id: str) -> list[dict[str, Any]]:
    """Parse the per-run audit chain file into a list of event dicts (in order)."""
    import json

    path = Path(audit_dir) / f"{run_id}.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def event_types(audit_dir: Path, run_id: str) -> list[str]:
    """The ``event_type`` of each event in the run chain, in order."""
    return [e["event_type"] for e in read_events(audit_dir, run_id)]


def chain_ok(audit_dir: Path, run_id: str) -> bool:
    """True iff the per-run audit chain verifies (linkage + hash recomputation)."""
    return verify_run_file(Path(audit_dir) / f"{run_id}.jsonl").ok
