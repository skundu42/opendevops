"""API-reality spike: introspect the pinned libraries and verify the plan's assumptions.

Run against the INSTALLED packages (deepagents 0.6.12 / langchain 1.3.14 / langgraph 1.2.9):

    uv run python scripts/api_spike.py

Prints a structured report. Every expectation from the plan's verified research brief is
checked against the real installed API; any mismatch is flagged as a DIVERGENCE. The prose
write-up lives in docs/api-notes.md — regenerate it from this script's output.
"""

from __future__ import annotations

import importlib
import inspect
from importlib.metadata import version
from typing import Any

divergences: list[str] = []
notes: list[str] = []


def rec_div(msg: str) -> None:
    divergences.append(msg)
    print(f"  [DIVERGENCE] {msg}")


def rec_note(msg: str) -> None:
    notes.append(msg)
    print(f"  [note] {msg}")


def hr(title: str) -> None:
    print(f"\n{'=' * 78}\n{title}\n{'=' * 78}")


def try_import(modname: str, *names: str) -> dict[str, Any]:
    """Import names from a module, returning {name: obj}; records divergences on failure."""
    out: dict[str, Any] = {}
    try:
        mod = importlib.import_module(modname)
    except Exception as exc:  # noqa: BLE001
        rec_div(f"cannot import module {modname!r}: {exc}")
        return out
    for n in names:
        if hasattr(mod, n):
            out[n] = getattr(mod, n)
            print(f"  ok: from {modname} import {n}")
        else:
            rec_div(f"{modname!r} has no attribute {n!r}")
    return out


def main() -> None:
    hr("versions")
    for pkg in [
        "deepagents",
        "langchain",
        "langgraph",
        "langchain-core",
        "langchain-anthropic",
    ]:
        try:
            print(f"  {pkg}=={version(pkg)}")
        except Exception as exc:  # noqa: BLE001
            rec_div(f"cannot read version of {pkg}: {exc}")

    # ---- 1. create_deep_agent signature --------------------------------------------
    hr("1. deepagents.create_deep_agent signature")
    import deepagents

    cda = try_import("deepagents", "create_deep_agent").get("create_deep_agent")
    if cda is not None:
        sig = inspect.signature(cda)
        params = list(sig.parameters)
        print(f"  signature: create_deep_agent{sig}")
        print(f"  params: {params}")
        expected = {
            "model",
            "tools",
            "system_prompt",
            "middleware",
            "subagents",
            "backend",
            "interrupt_on",
            "response_format",
            "state_schema",
            "context_schema",
            "checkpointer",
            "store",
        }
        present = set(params)
        missing = sorted(expected - present)
        if missing:
            rec_div(f"create_deep_agent missing expected kwargs: {missing}")
        else:
            rec_note("all expected create_deep_agent kwargs present")
        if "instructions" in present:
            rec_div("create_deep_agent still exposes 'instructions' (expected removed)")
        else:
            rec_note("'instructions' kwarg absent (as expected)")
        extra = sorted(present - expected - {"kwargs", "args"})
        if extra:
            rec_note(f"additional create_deep_agent params beyond expected: {extra}")
    if hasattr(deepagents, "async_create_deep_agent"):
        rec_div("deepagents exposes async_create_deep_agent (expected absent)")
    else:
        rec_note("async_create_deep_agent absent (as expected)")
    public = sorted(n for n in dir(deepagents) if not n.startswith("_"))
    print(f"  deepagents public names: {public}")

    # ---- 2. DeepAgentState + StateBackend location ---------------------------------
    hr("2. DeepAgentState + StateBackend location")
    try_import("deepagents", "DeepAgentState")
    found_backend = False
    for modname in ("deepagents.backends", "deepagents.backend", "deepagents"):
        try:
            mod = importlib.import_module(modname)
        except Exception:  # noqa: BLE001
            continue
        if hasattr(mod, "StateBackend"):
            print(f"  ok: StateBackend found in {modname}")
            rec_note(f"StateBackend importable from {modname}")
            found_backend = True
            break
    if not found_backend:
        rec_div("StateBackend not found in deepagents.backends / .backend / top-level")
        # try to discover where backends live
        try:
            be = importlib.import_module("deepagents.backends")
            be_names = sorted(n for n in dir(be) if not n.startswith("_"))
            print(f"  deepagents.backends names: {be_names}")
        except Exception as exc:  # noqa: BLE001
            print(f"  (deepagents.backends import failed: {exc})")

    # ---- 3. langchain middleware ---------------------------------------------------
    hr("3. langchain.agents.middleware")
    mw = try_import(
        "langchain.agents.middleware",
        "AgentMiddleware",
        "ModelCallLimitMiddleware",
        "ToolCallLimitMiddleware",
        "SummarizationMiddleware",
        "hook_config",
    )
    for cls_name in ("ModelCallLimitMiddleware", "ToolCallLimitMiddleware"):
        cls = mw.get(cls_name)
        if cls is not None:
            sig = inspect.signature(cls.__init__)
            print(f"  {cls_name}.__init__{sig}")
            p = set(sig.parameters)
            for expected_kw in ("thread_limit", "run_limit", "exit_behavior"):
                if expected_kw not in p:
                    rec_div(f"{cls_name}.__init__ missing {expected_kw!r}")

    am = mw.get("AgentMiddleware")
    if am is not None:
        hook_names = [
            "before_agent",
            "before_model",
            "wrap_model_call",
            "wrap_tool_call",
            "after_model",
            "after_agent",
        ]
        for h in hook_names:
            sync_ok = hasattr(am, h)
            async_ok = hasattr(am, "a" + h)
            print(f"  AgentMiddleware.{h}: sync={sync_ok} async(a{h})={async_ok}")
            if not sync_ok:
                rec_div(f"AgentMiddleware has no hook {h!r}")
            if not async_ok:
                rec_div(f"AgentMiddleware has no async hook 'a{h}'")
        # wrap_tool_call signature
        for m in ("wrap_tool_call", "awrap_tool_call"):
            if hasattr(am, m):
                print(f"  AgentMiddleware.{m}{inspect.signature(getattr(am, m))}")

    # ToolCallRequest object
    tcr = None
    for modname in (
        "langchain.agents.middleware",
        "langchain.agents.middleware.types",
        "langchain.agents.middleware_agent",
    ):
        try:
            mod = importlib.import_module(modname)
        except Exception:  # noqa: BLE001
            continue
        if hasattr(mod, "ToolCallRequest"):
            tcr = mod.ToolCallRequest
            print(f"  ok: ToolCallRequest importable from {modname}")
            rec_note(f"ToolCallRequest importable from {modname}")
            break
    if tcr is None:
        rec_div("ToolCallRequest not found in the expected middleware modules")
    else:
        fields = getattr(tcr, "__annotations__", {})
        dataclass_fields = getattr(tcr, "__dataclass_fields__", None)
        shown = list(dataclass_fields) if dataclass_fields else list(fields)
        print(f"  ToolCallRequest fields: {shown}")
        if "tool_call" not in shown:
            rec_div("ToolCallRequest has no 'tool_call' field (PolicyMiddleware depends on it)")
        else:
            rec_note("ToolCallRequest.tool_call present (PolicyMiddleware reads .tool_call dict)")

    # ---- 4. usage metadata callbacks -----------------------------------------------
    hr("4. langchain_core.callbacks usage-metadata")
    try_import(
        "langchain_core.callbacks",
        "get_usage_metadata_callback",
        "UsageMetadataCallbackHandler",
    )

    # ---- 5. langgraph types + errors -----------------------------------------------
    hr("5. langgraph.types / langgraph.errors")
    try_import("langgraph.types", "Command", "interrupt")
    try_import("langgraph.errors", "GraphRecursionError")

    # ---- 6. AIMessage / ToolMessage usage_metadata ---------------------------------
    hr("6. AIMessage / ToolMessage usage_metadata + cache detail")
    msgs = try_import("langchain_core.messages", "AIMessage", "ToolMessage")
    ai_cls = msgs.get("AIMessage")
    if ai_cls is not None:
        ai = ai_cls(
            content="x",
            usage_metadata={
                "input_tokens": 10,
                "output_tokens": 2,
                "total_tokens": 12,
                "input_token_details": {"cache_read": 4, "cache_creation": 3},
            },
        )
        um = ai.usage_metadata
        print(f"  AIMessage.usage_metadata = {um}")
        itd = (um or {}).get("input_token_details", {})
        for k in ("cache_read", "cache_creation"):
            if k in itd:
                rec_note(f"input_token_details.{k} accepted ({itd[k]})")
            else:
                rec_div(f"input_token_details missing {k!r}")

    # ---- 7. smoke graph + bound-tool enumeration -----------------------------------
    hr("7. smoke graph via fake chat model + bound-tool enumeration")
    fake_cls = None
    fake_modname = "langchain_core.language_models.fake_chat_models"
    try:
        fm = importlib.import_module(fake_modname)
        for candidate in ("GenericFakeChatModel", "FakeMessagesListChatModel", "FakeChatModel"):
            if hasattr(fm, candidate):
                fake_cls = getattr(fm, candidate)
                print(f"  fake chat model class: {fake_modname}.{candidate}")
                rec_note(f"fake chat model used: {candidate}")
                break
    except Exception as exc:  # noqa: BLE001
        rec_div(f"cannot import {fake_modname}: {exc}")

    # NOTE: a bare GenericFakeChatModel raises NotImplementedError at graph.invoke, because
    # the agent factory calls model.bind_tools(...) (the graph always binds built-ins) and the
    # fake does not implement it. The graph-tier tests must use a fake that overrides
    # bind_tools to return self. We do that here so the smoke invoke actually exercises a turn.
    graph = None
    if cda is not None and fake_cls is not None:
        from langchain_core.messages import AIMessage

        class _BindableFake(fake_cls):  # type: ignore[valid-type,misc]
            """A fake chat model that tolerates bind_tools (returns self) — the fake recipe."""

            def bind_tools(self, tools: Any, **kwargs: Any) -> Any:  # noqa: ANN401
                return self

        model: Any = None
        for kwargs in ({"messages": iter([AIMessage(content="hello from fake")])},
                       {"responses": [AIMessage(content="hello from fake")]}):
            try:
                model = _BindableFake(**kwargs)
                break
            except Exception:  # noqa: BLE001
                continue
        if model is None:
            rec_div("could not construct the fake chat model with known kwargs")
        else:
            rec_note("graph-tier fake must override bind_tools()->self; a bare "
                     "GenericFakeChatModel raises NotImplementedError at invoke (fake recipe)")
            try:
                from deepagents.backends import StateBackend

                graph = cda(model=model, tools=[], backend=StateBackend())
                print(f"  create_deep_agent(model=fake, tools=[], backend=StateBackend()) "
                      f"-> {type(graph).__name__}")
            except Exception as exc:  # noqa: BLE001
                rec_div(f"create_deep_agent build failed: {exc!r}")

    if graph is not None:
        # (a) enumerate bound tool names — probe several recipes, record the one that works.
        tool_names: list[str] = []
        recipe = ""
        try:
            nodes = graph.get_graph().nodes
            print(f"  compiled graph nodes: {list(nodes)}")
        except Exception as exc:  # noqa: BLE001
            print(f"  (graph.get_graph() failed: {exc})")

        # Recipe A: graph.nodes['tools'].bound.tools_by_name
        try:
            tnode = graph.nodes["tools"]
            for attrpath in ("bound.tools_by_name", "tools_by_name"):
                obj: Any = tnode
                ok = True
                for part in attrpath.split("."):
                    if hasattr(obj, part):
                        obj = getattr(obj, part)
                    else:
                        ok = False
                        break
                if ok and hasattr(obj, "keys"):
                    tool_names = sorted(obj.keys())
                    recipe = f"graph.nodes['tools'].{attrpath}.keys()"
                    break
        except Exception as exc:  # noqa: BLE001
            print(f"  (recipe A failed: {exc})")

        # Recipe B: walk the ToolNode attributes for a tools_by_name dict anywhere.
        if not tool_names:
            try:
                tnode = graph.nodes["tools"]
                for name in dir(tnode):
                    val = getattr(tnode, name, None)
                    is_name_dict = (
                        isinstance(val, dict)
                        and val
                        and all(isinstance(k, str) for k in val)
                        and any(hasattr(v, "name") or callable(v) for v in val.values())
                    )
                    if is_name_dict:
                        tool_names = sorted(val.keys())
                        recipe = f"graph.nodes['tools'].{name}.keys()"
                        break
            except Exception as exc:  # noqa: BLE001
                print(f"  (recipe B failed: {exc})")

        if tool_names:
            print(f"  BOUND TOOLS ({recipe}): {tool_names}")
            rec_note(f"bound-tool enumeration recipe: {recipe}")
            rec_note(f"bound tools: {tool_names}")
            expected_builtins = {"write_todos", "ls", "read_file", "write_file",
                                 "edit_file", "glob", "grep"}
            missing_builtins = sorted(expected_builtins - set(tool_names))
            if missing_builtins:
                rec_div(f"expected built-ins missing from bound tools: {missing_builtins}")
            surplus = sorted(set(tool_names) - expected_builtins)
            if surplus:
                rec_note(f"tools beyond the 7 core built-ins (boot inventory assertion): {surplus}")
            # 'task' was anticipated by the plan (SubAgentMiddleware); 'execute' was NOT.
            if "execute" in tool_names:
                rec_div("deepagents binds a DEFAULT 'execute' shell-string tool "
                        "(command=; supports ';'/'&&') — unanticipated by the plan. It is inert "
                        "with StateBackend (not a SandboxBackendProtocol, returns an error at "
                        "call time) but is still BOUND and visible to the model. Boot must exclude "
                        "it from the graph and/or deny it in base.yaml alongside task/"
                        "compact_conversation; the inventory assertion will otherwise fail.")
            if "compact_conversation" not in tool_names:
                rec_note("'compact_conversation' is NOT bound by the default stack in this "
                         "version (plan assumed it 'can be' bound); the deny rule is harmless "
                         "future-proofing.")
        else:
            rec_div("could not enumerate bound tool names via any known recipe")

        # (b) attempt invoke with the bind_tools-tolerant fake
        try:
            result = graph.invoke({"messages": [("user", "hi")]})
            msg_count = len(result.get("messages", []))
            last = result["messages"][-1].content
            print(f"  graph.invoke ok: {msg_count} messages; final={last!r}")
            rec_note("graph.invoke({'messages':[('user','hi')]}) succeeds with a "
                     "bind_tools-tolerant fake model")
        except Exception as exc:  # noqa: BLE001
            rec_div(f"graph.invoke raised {type(exc).__name__}: {exc}")

    # ---- 8. ToolCallLimitMiddleware(tool_name=...) ---------------------------------
    hr("8. ToolCallLimitMiddleware(tool_name=...) per-tool instance")
    tcl = mw.get("ToolCallLimitMiddleware")
    if tcl is not None:
        try:
            inst = tcl(tool_name="run_command", run_limit=30, exit_behavior="continue")
            print(f"  ok: ToolCallLimitMiddleware(tool_name='run_command', ...) -> {inst!r}")
            rec_note("ToolCallLimitMiddleware accepts per-tool tool_name=")
        except Exception as exc:  # noqa: BLE001
            rec_div(f"ToolCallLimitMiddleware(tool_name=...) failed: {exc!r}")

    # ---- summary -------------------------------------------------------------------
    hr("SUMMARY")
    print(f"  notes: {len(notes)}")
    print(f"  DIVERGENCES: {len(divergences)}")
    for d in divergences:
        print(f"    - {d}")


if __name__ == "__main__":
    main()
