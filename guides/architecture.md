# Architecture

opendevops is **one agent graph, many frontends**. A single LangChain
[deepagents](https://github.com/langchain-ai/deepagents) graph carries the entire safety core as
middleware; every run interface (CLI, HTTP, Slack, scheduler) talks to it through one narrow
protocol. The operations dashboard is deliberately off that command path: it derives a read-only
projection from the audit ledger.

```
 Local tier (zero infra)                  Service tier (docker-compose)
 ┌──────────────┐                         ┌─────────┐ ┌───────────┐ ┌───────────┐ ┌──────────────┐
 │  CLI REPL    │                         │ CLI REPL│ │ Slack bot │ │ Scheduler │ │ Webhooks     │
 │ (in-process) │                         │ (SDK)   │ │ (bolt SM) │ │(APSched.) │ │(Alertmgr/GH) │
 └──────┬───────┘                         └────┬────┘ └────┬──────┘ └────┬──────┘ └──────┬───────┘
        │                                      └───────────┴─────┬──────┴────────────────┘
        │        AgentGateway protocol — LocalGateway │ ServerGateway (sole langgraph_sdk importer)
        ▼                                                        ▼
 ┌─────────────────────────────────────────────────────────────────────────────────────────────┐
 │  ONE CompiledStateGraph from create_deep_agent(...)                                         │
 │  middleware: CostCap · DailyBudget · ModelCallLimit · ToolCallLimit(s) · Policy(+Audit)     │
 │  tools: run_command(argv) · ssh_run · task(log-summarizer only) · deepagents virtual FS     │
 └───────────────┬─────────────────────────────────────────────────────────────────────────────┘
                 │ executor.mode=local: in-process subprocess, constructed env
                 │ executor.mode=remote: HTTP → executor service, ed25519 decision tokens (experimental)
                 ▼
        Credentials = THE boundary: per-(tool-family, environment, ro|rw) kubeconfigs /
        tokens / roles. Audit: hash-chained per-run JSONL the agent has no write path to.
```

The authenticated `/dashboard` surface reads a bounded window of those audit chains and emits a
sanitized operational projection. It never calls tools, resumes runs, or exposes argv/output. That
separation keeps monitoring from becoming a second control plane.

## The three load-bearing decisions

1. **Execution is argv-only — there is no shell.** The one execution tool is
   `run_command(argv: list[str])`, run with `shell=False`. Pipes, substitution, and heredocs do not
   exist as a surface, and interpreters (`bash`, `python`, `xargs`, `find`, `awk`, `env`, …) are
   both absent from every allowlist and explicitly hard-denied. Deleting the shell surface removes
   the entire command-injection bypass taxonomy instead of trying to parse it. The model composes
   multi-step calls and greps large outputs in the deepagents **virtual filesystem** instead.

2. **Credentials are the security boundary; policy is velocity.** The policy engine is
   advisory-grade UX; the real boundary is what credentials the executor holds. Every allow rule
   names a **channel** (`ro` | `rw`), and each `(tool-family, environment, channel)` triple maps to
   a distinct, minimally-scoped credential provisioned *before* the policy referencing it ships.
   The design invariant: **even a total policy bypass is read-only-and-no-secrets**.

3. **Policy and audit are one middleware, layered, default-deny.** `PolicyMiddleware` embeds the
   `AuditLogger` and writes a `decision` event before execution and an `execution` event after — a
   separate audit middleware would leave an ordering gap and lose the decision record if execution
   crashed. Any exception anywhere in the pipeline becomes a deny (`__fail_closed__`); no matching
   rule is also a deny.

## The gateway seam

All frontends depend only on the `AgentGateway` protocol (`src/opendevops/gateway/base.py`):
`create_thread`, `stream`, `stream_resume`, `cancel`, `daily_total`, …

- **`LocalGateway`** (`gateway/local.py`) runs the graph in-process: `astream` with wall-clock
  enforcement via `asyncio.wait_for`, and an `AsyncSqliteSaver` checkpointer so escalations can
  suspend and resume across turns.
- **`ServerGateway`** (`gateway/server.py`) speaks to a self-hosted LangGraph Server over
  `langgraph_sdk` — and it is **the only module in the codebase allowed to import `langgraph_sdk`**
  (the "SDK firewall"). If server licensing ever becomes untenable, this seam is where a
  FastAPI-embedded fallback implements the same protocol; no interface code changes.

The gateway also owns **authoritative cost accounting**: it wraps every run in
`get_usage_metadata_callback()`, which catches model calls the in-graph middleware cannot see
(the summarizer, subagents). See [budgets](budgets.md#who-counts-the-money).

## The middleware stack

Order matters; the last custom middleware is the innermost wrapper, so the policy decision sits
closest to execution:

| Middleware | Job |
|---|---|
| `CostCapMiddleware` | accumulates per-run USD from `usage_metadata`; gracefully jumps to end at 90% of cap |
| `DailyBudgetMiddleware` | global + per-principal daily USD envelopes via a pluggable `DailyCounter` (sqlite / redis) |
| `ModelCallLimitMiddleware` | hard cap on model calls per run |
| `ToolCallLimitMiddleware` (×2) | run-wide and `run_command`-specific tool-call caps |
| `PolicyMiddleware` | parse → cache check → decide → audit → execute → audit (see [policy](policy.md)) |

## Tools

| Tool | What it is |
|---|---|
| `run_command(argv, timeout_s)` | the one general execution tool; argv-only, output scrubbed + truncated, spills to virtual FS |
| `ssh_run(host, argv, …)` | structured remote exec over asyncssh; host allowlist, pinned user/key/known_hosts from config |
| `task` | deepagents subagent spawner — **restricted by policy to the single named `log-summarizer`** (haiku) |
| `write_todos`, `ls`, `read_file`, `write_file`, `edit_file`, `glob`, `grep` | deepagents virtual FS built-ins (graph state only) |

Denied outright by `config/policy/base.yaml`: the deepagents built-in shell `execute` tool,
`compact_conversation`, and any `task` target other than `log-summarizer`.

Large outputs: `run_command` truncates head+tail at `execution.output_max_chars` and writes the
**full scrubbed** text to the virtual FS (`/output/<tool_call_id>.txt`); the ToolMessage names the
path so the model uses built-in `grep` instead of re-running commands.

File-consuming commands (`kubectl apply -f`, `helm --values`, `-k`) work through the **staging
bridge**: the agent authors manifests in the virtual FS; the executor materializes them into a
per-call private tmpdir, rewrites argv to the staged paths, records each staged file's sha256 in
the audit event, and deletes the tmpdir afterwards.

## Interrupt-replay safety

LangGraph re-executes a node from its start when resuming after an `interrupt()`. Without guards, a
model turn containing `[allowed call, escalating call]` would re-run the allowed call on resume.
Two mandatory guards:

- an **execution-result cache** in graph state keyed by `tool_call_id` — `PolicyMiddleware` returns
  the cached ToolMessage on replay, so each `tool_call_id` executes at most once;
- **parallel tool calls disabled** on the main model (bound in `models/registry.py`), so the replay
  window contains at most one call.

A graph-deterministic test asserts a resume after escalation produces exactly one `execution`
audit event per `tool_call_id`.

## Boot-time assertions

The process fails to boot — loudly, by design — if reality drifts from the reviewed configuration:

- **Tool inventory**: the compiled graph's bound tools must exactly match the expected set; any
  surplus tool (e.g. a new deepagents built-in appearing after a dependency bump) is a boot error.
- **Pricing**: every model referenced in `models.yaml agents:` must resolve in `pricing:`.
- **Policy loader lints**: schema validity, unique rule ids, credential coverage for every allow
  rule's pack, overlay restrictions, unreachable-rule detection ([policy](policy.md#loader-lints)).
- **Config coverage gates**: a configured pack whose tool family has no credential refuses to boot.

## Executor: local and remote

`executor.mode=local` (default, the reviewed production path): `run_command` subprocesses run
in-process with a **constructed, never inherited** environment — `PATH`, `HOME`, no-color/pager
hygiene vars, plus exactly one credential selected by the winning rule's
`(tool-family, environment, channel)`. The agent's own env (API keys, audit path) is physically
absent from every child.

`executor.mode=remote` (**experimental**): execution moves to a standalone credential-holding
service (gVisor, non-root, read-only rootfs, egress-allowlisted). The agent then holds no infra
credentials — each request carries an **ed25519-signed decision token** binding the argv,
staged-file plan, tool family, channel, run id, tool-call id and a 120 s expiry, so no code path
reaches execution without passing the policy engine. Remote mode is gated behind explicit
pre-deployment conditions — see [deployment](deployment.md#executor-service-remote-mode) and
`ops/executor/README.md`.

## Module map

| Path | Contents |
|---|---|
| `src/opendevops/agent.py` | `build_agent(cfg)` — graph assembly + boot assertions |
| `src/opendevops/state.py`, `context.py` | graph state (cost, results cache) and per-run context (principal, environment, profile) |
| `src/opendevops/policy/` | schema, loader+lints, engine, hooks, middleware ([policy](policy.md)) |
| `src/opendevops/budget/` | cost cap + daily budget middleware, counters ([budgets](budgets.md)) |
| `src/opendevops/audit/` | hash-chain logger, schema, verifier ([audit](audit.md)) |
| `src/opendevops/tools/` | `run_command`, `ssh_run`, executor, scrubber, staging bridge, signing |
| `src/opendevops/executor_service/` | the standalone remote executor service (FastAPI) |
| `src/opendevops/gateway/` | the protocol + Local/Server implementations |
| `src/opendevops/interfaces/` | CLI is `cli.py` at package root; webapp, authenticated dashboard, Slack, scheduler here ([interfaces](interfaces.md)) |
| `src/opendevops/models/` | alias→model resolution, price table |
| `config/` | `config.yaml`, `models.yaml`, `budgets.yaml`, `policy/` ([configuration](configuration.md)) |
| `ops/` | RBAC, kubeconfig generator, compose-stack configs, executor manifests, maintenance CLIs |
