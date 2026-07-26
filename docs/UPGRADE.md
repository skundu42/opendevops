# Upgrading the pinned trio (deepagents / langchain / langgraph)

`deepagents==0.6.12`, `langchain==1.3.14`, `langgraph==1.2.9` are pinned **exactly** and move
**only together, through this gate**: the trio bumps only on a branch passing all four
verification tiers. These are beta-era libraries: the safety core reaches into a handful of
**private / emergent** behaviours that a minor bump can silently change. This document is the
procedure + the exact landmines to re-verify.

The eval harness (`tests/replay/`) exists precisely so this upgrade is *mechanical and safe*: it
runs the real policy/audit/budget stack against golden trajectories with `$0` LLM/cluster cost, and
its mechanical audit gates (`tests/replay/audit_gates.py`) are reused by CI. A bump that keeps
`uv run pytest -q` green has, by construction, preserved every behaviour listed below.

---

## Procedure

1. **Branch.** Never bump on `main`/an integration branch.
   ```sh
   git switch -c chore/bump-trio-<versions>
   ```
2. **Bump the three pins together** in `pyproject.toml` (`dependencies`), keeping them exact
   (`==`). Do not bump one without the others — they are a co-versioned set. Bump
   `langchain-anthropic` only if the new langchain requires it (it is a `>=,<2` range).
3. **Relock and sync.**
   ```sh
   uv lock && uv sync --all-extras
   ```
4. **Regenerate the API-reality notes and diff them** — this is the fastest signal that a private
   surface moved:
   ```sh
   uv run python scripts/api_spike.py     # rewrites docs/api-notes.md
   git diff docs/api-notes.md
   ```
   Any change to the "DIVERGENCES" / import-path / signature sections is a landmine hit — cross-ref
   the table below before touching anything else.
5. **Run all four verification tiers** (see `guides/development.md`). The first three are local and free:
   ```sh
   uv run pytest -q                       # unit + graph-deterministic + replay/golden
   uv run ruff check src tests
   uv run mypy src
   ```
   Then the **integration** tier (nightly / pre-release): kind cluster + live model on the `ci`
   budget profile (capped by `CostCapMiddleware`).
6. **Walk the landmine checklist below.** A green suite covers most of it, but a few items
   (`tool_choice` precedence, jump-to-end shape) are *emergent* behaviours a passing test may not
   pin tightly — re-verify them by hand.
7. **Only merge if all four tiers are green.** That is the upgrade gate.

OIDC and telemetry dependencies are not part of the pinned trio, but their upgrades are still
security-sensitive. After changing Authlib/httpx, run `tests/unit/test_dashboard_auth.py` and an
integration login against a disposable issuer to re-verify discovery, state, nonce, PKCE and ID
token validation. After changing OpenTelemetry packages, boot once with and once without
`OTEL_EXPORTER_OTLP_ENDPOINT`; exporter failure must remain non-fatal and model/tool execution must
be unchanged.

---

## Landmine checklist (re-verify on every bump)

Each row: the private/emergent behaviour, where it lives, and how to know it still holds. "Guard"
means a test already fails loudly if it breaks; "manual" means re-verify by hand.

### deepagents internals

| # | Landmine | Where | Re-verify |
|---|---|---|---|
| D1 | **Harness-profile matching**: `task` is dropped and `execute` is hidden from the model request via `HarnessProfile(excluded_tools=…, excluded_middleware=…, general_purpose_subagent=GeneralPurposeSubagentProfile(enabled=False))`, registered with `register_harness_profile`. The profile is matched against the model **object**. | `agent.py` `_register_harness_profiles`, `_register_profile_once`; imports `GeneralPurposeSubagentProfile, HarnessProfile, register_harness_profile` from `deepagents`. | Guard: `tests/graph/test_graph_inventory.py` + boot `_assert_tool_inventory`. If profile matching changes, `task` gets re-exposed (tolerated by the assertion) rather than crashing — but confirm the inventory test still passes and `execute` is still excluded from the model request. |
| D2 | **`deepagents._models` private helpers** `get_model_identifier` / `get_model_provider` derive the profile key for a *pre-built* model (so an injected fake also gets the summarizer excluded). | `agent.py` `_model_profile_key` (function-local import of `deepagents._models`). | Manual: `uv run python -c "from deepagents._models import get_model_identifier, get_model_provider"`. If the module/functions move, `_model_profile_key` returns `None` and the fake build would run **two** summarizers — caught by graph-tier accounting tests, but re-point the import. |
| D3 | **Summarizer replace-by-name trick**: `create_summarization_middleware` builds the default; `_DeepAgentsSummarizationMiddleware.name` returns the public alias `"SummarizationMiddleware"` **only for the exact base class** and its own `__name__` for a subclass. We subclass it (`_HaikuSummarizationMiddleware`) and exclude the base by that alias. | `agent.py` `_build_summarizer`, `_HaikuSummarizationMiddleware`, `_SUMMARIZER_NAME="SummarizationMiddleware"`; imports from `deepagents.middleware.summarization`. | Manual: `create_summarization_middleware(model, backend).name == "SummarizationMiddleware"` and a subclass instance's `.name == "_HaikuSummarizationMiddleware"`. If the alias string or the subclass-name behaviour changes, the swap either collides (duplicate name) or double-runs — graph-tier summarizer tests should catch it; re-derive `_SUMMARIZER_NAME`. |
| D4 | **`create_file_data` / `file_data_to_string`** FileData shape + content round-trip. The truncation spill writes `create_file_data(scrubbed)` into the `files` channel; the staging bridge reads `file_data_to_string(files[path])` and hashes it. Both must agree so a staged-manifest sha256 recorded at exec time equals what the dry-run hook computes. | `tools/run_command.py` (`create_file_data`), `tools/staging.py` (`file_data_to_string`), both from `deepagents.backends.utils`. | Guard: `tests/graph/test_graph_dry_run.py` + `tests/replay/test_golden_trajectories.py::test_deploy_verify_rollback` (the second apply is *allowed* only because the dry-run recorded a matching sha). If FileData internals change, these turn the deploy scenario's second apply into a `require-dry-run-before-real-apply` deny — a red test, not a silent hole. |
| D5 | **`create_deep_agent` signature + middleware ordering**: everything after `tools` is keyword-only; user middleware is appended *after* deepagents' required middleware, and PolicyMiddleware (last in our list) is the innermost tool-call wrap. The replay harness relies on being able to append one more innermost middleware. | `agent.py` `build_agent` (`create_deep_agent(model=…, middleware=…, …)`); `tests/replay/conftest.py` monkeypatches `agent_mod.create_deep_agent` to extend the list. | Guard: whole replay tier (proves PolicyMiddleware still decides/audits with the replay wrap innermost). Manual: re-diff the signature in `docs/api-notes.md §1`. |
| D6 | **Bound-tool + reducer-channel introspection**: `graph.nodes["tools"].bound.tools_by_name` and `graph.channels[...]` being `BinaryOperatorAggregate` (`langgraph.channels.binop`). | `agent.py` `_bound_tool_names`, `_assert_reducer_channels`. | Guard: `_assert_tool_inventory` / `_assert_reducer_channels` run on **every** `build_agent` (so every graph/replay test). A shape change fails boot loudly. |

### langchain / langchain-anthropic internals

| # | Landmine | Where | Re-verify |
|---|---|---|---|
| L1 | **Tool-invoke context-copy**: langchain runs the tool coroutine in a **copied** context (`tool.ainvoke`), so a `ContextVar` the tool sets does **not** propagate back to the middleware. Exec-meta therefore rides the *return channel* (`ToolMessage.additional_kwargs[EXEC_META_KEY]`), which the replay middleware also uses. | `tools/run_command.py` (`_exec_tool_message`, `EXEC_META_KEY`), `policy/middleware.py` `_pop_exec_meta`, `tests/replay/replay_middleware.py`. | Guard: every graph/replay test that asserts an `execution` audit event exists (the event only fires if the meta survives the boundary). If langchain starts preserving child→parent contextvar writes, the return channel still works — no action needed, but the comment can be relaxed. |
| L2 | **`model_kwargs={"tool_choice": {"type":"auto","disable_parallel_tool_use":True}}` reaches the request** — an *emergent* consequence of the pinned dict-merge precedence in langchain / langchain-anthropic `bind_tools`, **not** a guaranteed contract. | `models/registry.py` `_DISABLE_PARALLEL_TOOL_USE_KWARGS` (+ the long comment citing the probe). | **Manual** — a passing test may not pin this. Re-run the registry probe cited in `models/registry.py` (bind tools, inspect the outgoing request's `tool_choice`). It is made non-load-bearing by `SingleToolCallMiddleware` (`policy/guard.py`) + the `tool_results_cache`, so a regression degrades to "parallel calls possible but still collapsed", not a safety hole — but note it in the bump PR. |
| L3 | **jump-to-end shape**: budget stop-loss returns `{"jump_to": "end", …}` from a hook decorated `@hook_config(can_jump_to=["end"])`. | `budget/middleware.py` `_jump_to_end`, `CostCapMiddleware` / `DailyBudgetMiddleware`. | **Manual + guard**: `tests/graph/test_graph_budget.py` exercises a trip, but the *shape* of the jump is a langchain v1 contract. If a cap trips but the run does not route to `end`, re-check the return dict + `can_jump_to`. |
| L4 | **`AgentMiddleware.awrap_tool_call` / `ToolCallRequest`**: dataclass fields `tool_call, tool, state, runtime` + `.override(...)`. PolicyMiddleware rewrites via `.override`; ReplayToolMiddleware reads `request.state["files"]` and `request.tool_call["args"]["argv"]`. | `policy/middleware.py`, `tests/replay/replay_middleware.py`. | Guard: whole policy + replay tiers. Manual: re-diff `docs/api-notes.md §3`. |
| L5 | **Usage-metadata callback**: `get_usage_metadata_callback()` aggregates `{model_name: usage}` only when a call carries **both** `usage_metadata` and a model name; cache-tier keys `input_token_details.{cache_read,cache_creation}`. | `gateway/local.py` `_price_aggregate` / `_usage_aggregate`; `models/pricing.py`. | Guard: `tests/unit/test_gateway.py` accounting tests (scripted messages set `response_metadata={"model_name": …}`). |

### langgraph internals

| # | Landmine | Where | Re-verify |
|---|---|---|---|
| G1 | **interrupt / resume shapes**: `interrupt(payload)` raises `GraphInterrupt` on the first pass and **returns** the resume value on resume; resume is `Command(resume={"decisions":[{"type","args"?,"message"?,"approver"?}]})`; the suspended `ainvoke` result / `astream` final `values` frame carries `__interrupt__=[Interrupt(value=<payload>, …)]`. `GraphInterrupt` subclasses `GraphBubbleUp`, which PolicyMiddleware **re-raises** (must not be swallowed by fail-closed). | `policy/middleware.py` `_escalate` + the `except GraphBubbleUp: raise` carve-out; `gateway/local.py` `_extract_interrupt`, `_resume_command`; `tests/graph/test_graph_escalation.py`; `tests/replay/test_golden_trajectories.py::test_escalated_delete_approve`. | Guard: the escalation graph tier + the escalated-delete replay scenario (suspend → approve → executes exactly once, `resolution` carries the approver). If the resume envelope or `__interrupt__` shape changes, these go red. |
| G2 | **`AsyncSqliteSaver.__init__` calls `get_running_loop`** — it cannot be built in a sync constructor; it is built lazily in-loop and attached with `graph.checkpointer = saver`. | `gateway/local.py` `_ensure_checkpointer`. | Guard: any streaming/resume gateway test. Manual if the saver constructor changes. |
| G3 | **`_fileobj2output` CPython/asyncio-subprocess internal** — the executor drains buffered output from `proc._fileobj2output` via `getattr(..., None)`, degrading to empty output if the internal is gone. | `tools/executor.py` (`getattr(proc, "_fileobj2output", None)`). | Manual: not exercised by the fake-executor tests. On a Python or langgraph subprocess change, confirm real command output is still captured (integration tier / a live `run_command`). Degrades safely to empty output, never a crash. |
| G4 | **Content-bearing audit dedupe** absorbs the resume re-execution's identical re-emit while keeping a *distinct* (edited-argv) escalation. Depends on langgraph re-executing the `tools` node from its start on resume. | `audit/logger.py` dedupe key `(tool_call_id, event_type, content_sha)`; `tests/graph/test_graph_escalation.py` (double-interrupt / edit cases). | Guard: escalation graph tier asserts exactly-one `execution` per `tool_call_id` across resume. |

### the eval harness itself

| # | Landmine | Where | Re-verify |
|---|---|---|---|
| H1 | **agentevals 0.0.9 API**: `create_trajectory_match_evaluator(trajectory_match_mode="superset")` → `evaluator(outputs=…, reference_outputs=…)` returning `{"score": bool, …}`; inputs are a message list **or** `{"messages":[…]}`; superset compares **tool calls** (name + args, `tool_args_match_mode` default `"exact"`). | `tests/replay/test_golden_trajectories.py` (`_SUPERSET`). | Guard: the four golden scenarios. If agentevals bumps (it is in the `dev` extra, `==0.0.9`), re-verify the evaluator's input format and that the result dict still has a `score` key before trusting a green run. |
| H2 | **ReplayMismatch must escape fail-closed**: a fixture/scenario mismatch is raised as a `BaseException` (not `Exception`) so `PolicyMiddleware`'s `except Exception` fail-closed does **not** swallow it into a silent `policy_error` deny. | `tests/replay/replay_middleware.py` `ReplayMismatch`. | Guard: `tests/replay/test_replay_harness.py::test_off_script_call_raises_replay_mismatch`. If a future langchain/langgraph layer catches `BaseException` around the tool node, this could be masked — the recorded `ReplayToolMiddleware.mismatch` is the belt-and-suspenders. |

---

## If a landmine trips

- **A guard test goes red** → that is the system working. Read the failing assertion, consult the
  row above, and adapt the cited symbol. Do **not** loosen a boot assertion or a mechanical gate to
  make the bump pass — the whole point of the gate is that these stay tight.
- **`api_spike.py` shows a moved import** → re-point the import; if a private module
  (`deepagents._models`, `deepagents.middleware.summarization`, `deepagents.backends.utils`) is gone,
  find the new location or a public equivalent before proceeding.
- **An emergent behaviour (L2, L3) regressed but tests still pass** → note it explicitly in the bump
  PR and confirm its defense-in-depth backstop still holds (SingleToolCallMiddleware for L2, the
  gateway's authoritative accounting for a budget-shape drift).
- **Record-mode capture drifted** → `ReplayToolMiddleware(mode="record", record_path=…)` re-captures
  real kind-cluster `run_command` outputs into a fresh fixture for regenerating goldens.
