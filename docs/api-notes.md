# API-reality notes (P0 spike)

Introspection of the **installed** pinned libraries, verifying the assumptions in the
research brief / PLAN.md against reality. Regenerate with:

```sh
uv run python scripts/api_spike.py
```

Installed versions (all pins resolved exactly as specified):

| package | pinned | installed |
|---|---|---|
| deepagents | `==0.6.12` | 0.6.12 |
| langchain | `==1.3.14` | 1.3.14 |
| langgraph | `==1.2.9` | 1.2.9 |
| langchain-core | (transitive) | 1.4.9 |
| langchain-anthropic | `>=1.4.7,<2` | 1.4.8 |

Spike result: **17 confirmations, 1 divergence.**

---

## ⚠️ DIVERGENCES (read first)

### D1 — deepagents binds a default `execute` shell-string tool (security-relevant, affects T5/T8)

The default `create_deep_agent(...)` stack binds **nine** tools, not the seven the plan
anticipated. The bound set is:

```
edit_file, execute, glob, grep, ls, read_file, task, write_file, write_todos
```

- `task` was anticipated (from `SubAgentMiddleware`) and the plan already handles it
  (deny rule + inventory assertion).
- **`execute` was NOT anticipated.** It is a `StructuredTool` whose description is
  *"Executes a shell command in an isolated sandbox environment"* — it takes a **`command`
  string** and explicitly supports `;` and `&&` chaining. This is exactly the shell-string
  execution surface the entire plan is designed to delete (PLAN.md §1, decision 1:
  "argv-only — no shell string, no shell parser"). It is provided by the deepagents
  `FilesystemMiddleware`.

**Mitigating reality:** with `backend=StateBackend()` (the plan's chosen backend) the
`execute` tool is **inert**. `StateBackend` is not a `SandboxBackendProtocol`
(`mro = StateBackend → BackendProtocol → ABC → object`), and `execute`'s own docstring says
it "is only available if the backend supports execution … otherwise the tool will return an
error message." So it cannot actually run a shell command against the P1 backend. **But it
is still bound and advertised to the model**, which is both a prompt-surface liability and a
direct trigger for the plan's boot-time tool-inventory assertion.

**Required follow-ups (later tasks):**
- **T8** (`agent.py`): the tool-inventory assertion's allowed set must account for `execute`
  — preferably by *preventing it from being bound at all* rather than allow-listing it. The
  likely lever is configuring/omitting the `FilesystemMiddleware`, or the new
  `permissions=[FilesystemPermission…]` kwarg on `create_deep_agent` (see C1). If it cannot
  be unbound, the assertion set becomes `{run_command, write_todos, ls, read_file,
  write_file, edit_file, glob, grep}` + explicitly-denied `{task, compact_conversation,
  execute}`.
- **T3** (`config/policy/base.yaml`): add an explicit `effect: deny` rule for tool_name
  `execute`, alongside the existing `task` / `compact_conversation` denies.
- **T4/T5** bypass corpus: add an `execute` deny case.

Note: `compact_conversation` is **not** bound by the default stack in this version (the plan
assumed it "can be" bound by the summarizer). `SummarizationMiddleware` is present in the
`wrap_model_call` chain but does not expose a manual-compaction tool here. The planned deny
rule for `compact_conversation` is therefore harmless future-proofing, not currently load-bearing.

---

### D1-followup (P5c) — `task` becomes an active, policy-scoped tool (the log-summarizer subagent)

P5c reverses the D1 "remove `task`" posture: `task` is now **bound as an active tool** because
`build_agent` passes ONE named subagent — a haiku log-summarizer — to `create_deep_agent(subagents=[…])`.
So `EXPECTED_ACTIVE` gains `"task"` and the tolerated-but-denied set shrinks to `{execute}`.
Three deepagents facts, verified against the installed 0.6.12 / langchain 1.3.14 (probes in the
`agent.py` docstring + `test_gateway.py`):

- **Target encoding.** The `task` `StructuredTool` (`_build_task_tool`) routes on a required
  **`subagent_type`** str arg (its `TaskToolSchema` is `{description, subagent_type}`). The engine
  scopes `task` on `ctx.args["subagent_type"]`: base.yaml `no-arbitrary-subagents`
  (`subagent_type_not_in: [log-summarizer]`) denies every other/absent target, and the engine
  synthetically allows the one name (`__subagent_allowed__`, like the FS built-ins) — base.yaml
  declares no `tool_family`, so an allow rule cannot live there.
- **Tool-less subagent.** A **raw `SubAgent` spec** gets deepagents' default
  `Todo/Filesystem/Summarization/PatchToolCalls` middleware prepended (so it would bind
  `ls/read_file/…/execute`). A **`CompiledSubAgent`** — a langchain `create_agent(model, tools=[])`
  runnable — is wired **as-is**, so the log-summarizer has NO tools node at all (cannot reach
  `run_command`/`ssh_run`/`execute`; nothing to police inside it). This is why we ship it compiled.
- **Accounting contextvar propagates.** `get_usage_metadata_callback()` registers an *inheritable*
  configure-hook on a contextvar, and deepagents invokes the subagent synchronously **inside** the
  parent `task` tool call — i.e. within the gateway's `with get_usage_metadata_callback()` scope. So
  the subagent's (haiku) model calls land in the run's authoritative aggregate with no change
  outside `agent.py` needed. `test_log_summarizer_subagent_spend_lands_in_authoritative` exercises
  this with scripted fakes for BOTH the main and subagent models (authoritative > state by exactly
  the haiku spend).

Upgrade gate: `task` is bound on every build (a named subagent is always passed), so a future
deepagents change to profile/subagent matching degrades to "the general-purpose subagent re-exposed"
— still policy-denied — rather than an inventory crash. Re-verify the three facts above on any
deepagents bump.

---

## Confirmations (assumptions that held)

### 1. `create_deep_agent` signature ✅

`from deepagents import create_deep_agent` works. Full signature (abbreviated types):

```python
create_deep_agent(
    model: str | BaseChatModel | None = None,
    tools: Sequence[BaseTool | Callable | dict] | None = None,
    *,
    system_prompt: str | SystemMessage | None = None,
    middleware: Sequence[AgentMiddleware] = (),
    subagents: Sequence[SubAgent | CompiledSubAgent | AsyncSubAgent] | None = None,
    skills: list[str] | None = None,
    memory: list[str] | None = None,
    permissions: list[FilesystemPermission] | None = None,
    backend: BackendProtocol | Callable[[ToolRuntime], BackendProtocol] | None = None,
    interrupt_on: dict[str, bool | InterruptOnConfig] | None = None,
    response_format: ... | None = None,
    state_schema: type[DeepAgentState] | None = None,
    context_schema: type[ContextT] | None = None,
    checkpointer: None | bool | BaseCheckpointSaver = None,
    store: BaseStore | None = None,
    debug: bool = False,
    name: str | None = None,
    cache: BaseCache | None = None,
) -> CompiledStateGraph[...]
```

- All twelve expected kwargs are present: `model, tools, system_prompt, middleware,
  subagents, backend, interrupt_on, response_format, state_schema, context_schema,
  checkpointer, store`.
- `instructions=` is **absent** (as expected — old removed API). ✅
- `async_create_deep_agent` is **absent** from the package (as expected). ✅
- Everything after `tools` is **keyword-only** (note the `*`). `model` and `tools` are the
  only positional-or-keyword params.
- `checkpointer` accepts `bool` as well as a `BaseCheckpointSaver` (deepagents can auto-build
  one). Plan usage (`None` in P1, `AsyncSqliteSaver` in P2) is unaffected.

**C1 — additional undocumented kwargs (informational):** the installed signature also has
`skills`, `memory`, `permissions`, `debug`, `name`, `cache`. The plan explicitly defers
`skills`/`memory` in v1 — they exist as no-op-by-default kwargs, so simply not passing them
is correct. `permissions: list[FilesystemPermission]` is the most interesting: it is the
likely knob for constraining the filesystem/`execute` surface (see D1). deepagents public
exports include `FilesystemPermission`, `FilesystemMiddleware`, `SubAgentMiddleware`,
`MemoryMiddleware`, `RubricMiddleware`, `DeepAgentState`, `backends`.

### 2. `DeepAgentState` + `StateBackend` locations ✅

- `from deepagents import DeepAgentState` ✅ (top-level export).
- `from deepagents.backends import StateBackend` ✅ (exactly the location the plan assumes;
  direct instantiation `StateBackend()` works — the deprecated factory form is not needed).

### 3. `langchain.agents.middleware` ✅ (critical for T6/T7)

All importable from `langchain.agents.middleware`: `AgentMiddleware`,
`ModelCallLimitMiddleware`, `ToolCallLimitMiddleware`, `SummarizationMiddleware`,
`hook_config`, and `ToolCallRequest`.

Limit middleware `__init__` signatures (both **keyword-only**):

```python
ModelCallLimitMiddleware(*, thread_limit: int | None = None,
                         run_limit: int | None = None,
                         exit_behavior: Literal['end', 'error'] = 'end')

ToolCallLimitMiddleware(*, tool_name: str | None = None,
                        thread_limit: int | None = None,
                        run_limit: int | None = None,
                        exit_behavior: ExitBehavior = 'continue')
```

- Both expose `thread_limit` / `run_limit` / `exit_behavior` as expected. ✅
- **Note for T6/T8:** `ModelCallLimitMiddleware.exit_behavior` is `Literal['end', 'error']`
  — it does **not** accept `'continue'`. The plan uses `exit_behavior="end"` for it, which is
  valid. `ToolCallLimitMiddleware.exit_behavior` is a broader `ExitBehavior` and defaults to
  `'continue'` (the plan uses `"continue"`), valid.
- `ToolCallLimitMiddleware(tool_name="run_command", run_limit=30, exit_behavior="continue")`
  constructs cleanly — per-tool instances work (plan §3.1's `run_command` shell-call limit). ✅

`AgentMiddleware` hook methods — **all six present in both sync and async (`a`-prefixed)
forms**: ✅

```
before_agent / abefore_agent      wrap_model_call / awrap_model_call
before_model / abefore_model      wrap_tool_call  / awrap_tool_call
after_model  / aafter_model       after_agent     / aafter_agent
```

**`wrap_tool_call` / `awrap_tool_call` signatures (T7 depends on this):**

```python
def wrap_tool_call(self, request: ToolCallRequest,
                   handler: Callable[[ToolCallRequest], ToolMessage | Command[Any]]
                   ) -> ToolMessage | Command[Any]: ...

async def awrap_tool_call(self, request: ToolCallRequest,
                          handler: Callable[[ToolCallRequest], Awaitable[ToolMessage | Command[Any]]]
                          ) -> ToolMessage | Command[Any]: ...
```

`ToolCallRequest` (importable directly from `langchain.agents.middleware`) is a dataclass
with fields: **`tool_call`, `tool`, `state`, `runtime`**. `request.tool_call` is present —
this is the dict T7's `PolicyMiddleware` parses (`argv` lives in `tool_call["args"]`). ✅

### 4. Usage-metadata callbacks ✅

`from langchain_core.callbacks import get_usage_metadata_callback,
UsageMetadataCallbackHandler` — both present. This is the gateway-level authoritative
accounting mechanism (plan §3.4). ✅

### 5. langgraph types / errors ✅

- `from langgraph.types import Command, interrupt` ✅
- `from langgraph.errors import GraphRecursionError` ✅

### 6. `AIMessage` / `ToolMessage` usage_metadata + cache tiers ✅

`from langchain_core.messages import AIMessage, ToolMessage`. An `AIMessage` constructed with

```python
usage_metadata={"input_tokens": 10, "output_tokens": 2, "total_tokens": 12,
                "input_token_details": {"cache_read": 4, "cache_creation": 3}}
```

round-trips intact: `input_token_details.cache_read` and `input_token_details.cache_creation`
are both accepted. This is the exact shape `models/pricing.py` (T1) needs for cache-tier-aware
USD. ✅

### 7. Smoke graph + bound-tool enumeration ✅ (recipe for T8)

- Fake chat model: `langchain_core.language_models.fake_chat_models.GenericFakeChatModel`
  constructs with `messages=iter([...])`.
- **T8 gotcha (important):** a *bare* `GenericFakeChatModel` makes `graph.invoke(...)` raise
  `NotImplementedError` — the agent factory always calls `model.bind_tools(final_tools, ...)`
  (the graph binds built-ins even when you pass `tools=[]`), and the fake does not implement
  `bind_tools`. **The graph-tier tests must use a fake that overrides `bind_tools` to return
  `self`.** With that override, `create_deep_agent(model=fake, tools=[],
  backend=StateBackend()).invoke({"messages": [("user", "hi")]})` runs one turn and returns a
  2-message state. Recipe:

  ```python
  class BindableFake(GenericFakeChatModel):
      def bind_tools(self, tools, **kwargs):
          return self  # fake ignores tools

  model = BindableFake(messages=iter([AIMessage(content="...")]))
  ```

- **Bound-tool enumeration recipe (T8 boot assertion needs this):**

  ```python
  tool_names = sorted(graph.nodes["tools"].bound.tools_by_name.keys())
  ```

  Compiled-graph node names for reference: `['__start__', 'model', 'tools',
  'TodoListMiddleware.after_model', 'PatchToolCallsMiddleware.before_agent', '__end__']`.
  The `tools` node is a `ToolNode`; `.bound.tools_by_name` is the `{name: tool}` dict.
- Enumerated default tool set: see **D1** above (`execute` is the surprise).

### 8. `ToolCallLimitMiddleware(tool_name=...)` ✅

Per-tool instances construct cleanly (covered in §3). ✅

---

## Cheat-sheet of verified import paths (for later tasks)

```python
from deepagents import create_deep_agent, DeepAgentState, FilesystemPermission
from deepagents.backends import StateBackend
from langchain.agents.middleware import (
    AgentMiddleware, ModelCallLimitMiddleware, ToolCallLimitMiddleware,
    SummarizationMiddleware, hook_config, ToolCallRequest,
)
from langchain_core.callbacks import get_usage_metadata_callback, UsageMetadataCallbackHandler
from langchain_core.messages import AIMessage, ToolMessage
from langgraph.types import Command, interrupt
from langgraph.errors import GraphRecursionError
```
