# OpenDevOps — Implementation Plan

An autonomous DevOps agent built on LangChain **deepagents**, covering Kubernetes operations, server configuration over SSH, cloud provider management, and CI/CD workflows — operating **fully autonomously** under a policy engine (no human-in-the-loop as the normal path), with hard **budget controls** (LLM USD cost, steps, wall clock) and a tamper-evident audit trail.

> **Provenance.** Research and design were produced by multi-agent workflows on 2026-07-18: a 12-agent research pass (every library claim adversarially verified against PyPI, GitHub source, and official docs) and a 3-perspective design panel (MVP-first / security-first / operability-first) with synthesis and a 15-item completeness critique, all fixes integrated inline below. Traceability:
> - Research journal: `~/.claude/projects/-Users-sk-dev-opendevops/cd4f1645-4b01-4e4c-8f53-48614e98d460/subagents/workflows/wf_56f894c4-4ad/journal.jsonl`
> - Design journal: `~/.claude/projects/-Users-sk-dev-opendevops/cd4f1645-4b01-4e4c-8f53-48614e98d460/subagents/workflows/wf_6daabf17-379/journal.jsonl`

## 0. Confirmed requirements

| Dimension | Decision |
|---|---|
| Infra targets | Kubernetes (kubectl), VMs/servers via SSH, cloud provider CLIs/SDKs (AWS/GCP/Azure), CI/CD & Git platforms (GitHub) |
| Interfaces | CLI chat, HTTP API (LangGraph Server), Slack bot, scheduled/event-driven runs — phased |
| Autonomy | Policy-based full auto: automatic allow/deny/rewrite; escalation (`interrupt`) only for a small residual class |
| Policy definition | Declarative YAML rules + Python `@policy_hook` code hooks; OPA can slot in later behind the same protocol |
| Budgets | LLM token/USD caps (per-run + daily), step/recursion limits, wall-clock limits. Cloud-spend guardrails out of scope |
| Language | Python 3.11+, async end-to-end |
| LLM | Multi-provider, config-driven; Anthropic default (`claude-opus-4-8` main, `claude-haiku-4-5` for summarization/subagents) |

All APIs cited are from the verified technical brief (deepagents **0.6.12** / langchain **1.3.14** / langgraph **1.2.9**, verified 2026-07-18). Web snippets older than ~6 months describe removed APIs (`instructions=`, `interrupt_config=`, `async_create_deep_agent`) — distrust them.

---

## 1. Architecture overview

```
 Phase 1-2 (local)                        Phase 3+ (service mode)
 ┌──────────────┐                         ┌─────────┐ ┌───────────┐ ┌───────────┐ ┌──────────────┐
 │  CLI REPL    │                         │ CLI REPL│ │ Slack bot │ │ Scheduler │ │ Webhooks     │
 │ (in-process) │                         │ (SDK)   │ │ (bolt SM) │ │(APSched.) │ │(Alertmgr/GH) │
 └──────┬───────┘                         └────┬────┘ └────┬──────┘ └────┬──────┘ └──────┬───────┘
        │                                      └───────────┴─────┬──────┴────────────────┘
        │  AgentGateway protocol (gateway/base.py) — LocalGateway │ ServerGateway (only module importing langgraph_sdk)
        ▼                                                        ▼
 ┌─────────────────────────────────────────────────────────────────────────────────────────────┐
 │  ONE CompiledStateGraph from create_deep_agent(...)                                         │
 │  middleware: CostCap · DailyBudget · ModelCallLimit · ToolCallLimit(s) · Policy(+Audit)     │
 │  tools: run_command(argv) + deepagents built-ins (write_todos, ls/read/write/edit/glob/grep)│
 │  backend: StateBackend()   state: DevOpsState   context: AgentContext                       │
 │  P1-2: invoked in-process (AsyncSqliteSaver in P2) │ P3+: self-hosted LangGraph Server      │
 │                                              (Postgres+Redis, platform-injected checkpoints)│
 └───────────────┬─────────────────────────────────────────────────────────────────────────────┘
                 │ subprocess (P1-4: in-process, scrubbed env)  →  (P5: executor service,
                 ▼                                                  gVisor, signed decision tokens)
        Credentials = THE boundary: per-(tool-family, environment, ro|rw) kubeconfigs / tokens /
        IAM roles, provisioned server-side BEFORE any policy referencing them ships.
        Audit: hash-chained per-run JSONL (agent tools have no write path to it) → durable sink (P3)
```

**Core shape.** One `create_deep_agent(...)` graph, many frontends, all speaking through an `AgentGateway` protocol so the runtime can move from in-process to LangGraph Server without touching interface code *(design rationale: CLI needs zero infrastructure in phase 1, and the seam makes the later server migration a config change, not a rewrite)*.

**The three load-bearing decisions:**

1. **Execution is argv-only — no shell string, no shell parser.** `run_command(argv: list[str])` runs `subprocess` with `shell=False`. Pipes, substitution, and heredocs don't exist as a surface; the model composes multi-step calls and greps large outputs in the deepagents virtual FS. Interpreters (`bash`, `python`, `xargs`, `find`, `awk`, `env`, …) are absent from the allowlist and caught by default-deny plus an explicit interpreter hard-deny rule (belt and braces). Deleting the shell surface removes the entire bypass taxonomy (arXiv 2606.15549 shows denylist parsing is structurally fragile) instead of trying to parse it. A tree-sitter-bash pipeline remains a documented future module behind a trigger (a real workflow argv+grep cannot express), which we do not expect to fire.
2. **Credentials are the boundary; the sandbox is phased.** Policy is advisory-grade velocity/UX; the real security boundary is server-side credentials. Phase 1 ships with exactly one credential in a constructed (never inherited) env: a kubeconfig bound to a `view`-ClusterRole ServiceAccount — even a total policy bypass is read-only-no-secrets. The read/write **channel split** is the permanent skeleton: every allow rule names a channel `ro|rw`, and each `(tool-family, environment, channel)` triple maps to a distinct credential provisioned before the policy referencing it lands. The gVisor executor split arrives before any mutating credential broader than a staging namespace Role.
3. **Policy and audit are one middleware; policy is layered, default-deny.** `PolicyMiddleware` embeds the `AuditLogger` and writes a `decision` event before execution and an `execution` event after (a sibling audit middleware would leave an ordering gap and lose the decision record if execution crashes). Effects: `allow | deny | rewrite | escalate | hook`; deny-overrides; no match → deny. Escalation is a **dynamic `langgraph.types.interrupt()` inside the middleware**, not static `interrupt_on` (which would gate every call of a tool rather than the policy-selected residual class).

**Interrupt-replay safety (required for correctness).** LangGraph re-executes a node from its start on resume after `interrupt()`. If the model issued parallel tool calls `[apply (allow), delete pvc (escalate)]`, the apply would execute, the delete would interrupt, and on resume the apply would **run a second time**. Two guards, both mandatory:
- An **execution-result cache** in `DevOpsState` keyed by `tool_call_id`: `PolicyMiddleware` consults it before executing and returns the cached `ToolMessage` on replay, so each `tool_call_id` executes at most once.
- **Parallel tool calls disabled on the main model** (Anthropic: `tool_choice={"type": "auto", "disable_parallel_tool_use": True}` bound in `models/registry.py`, reinforced by a system-prompt constraint) — belt-and-braces so the replay window contains at most one call.
A graph-deterministic test asserts that a resume after escalation produces exactly one `execution` audit event per `tool_call_id`.

Everything is **async end-to-end** (sync `invoke` cannot be safely cancelled mid-node; wall-clock enforcement depends on cancellability). No subagents, no MCP, no secrets resolver in v1 — each is deferred with its integration pattern pre-decided (Phase 5).

---

## 2. Repo layout

```
/Users/sk/dev/opendevops/
├── pyproject.toml                     # uv-managed; exact pins (§5); console script `opendevops`
├── uv.lock                            # load-bearing: deepagents 0.x churn risk
├── .env.example                       # ANTHROPIC_API_KEY, LANGSMITH_* (opt), later SLACK_*/DATABASE_URI/REDIS_URI
├── langgraph.json                     # P3: {"graphs":{"devops":"./src/opendevops/agent.py:agent"},"http":{"app":"./src/opendevops/interfaces/webapp.py:app"}}
├── docker-compose.yml                 # P3: langgraph-server, postgres, redis, caddy, vector audit-shipper
├── config/
│   ├── config.yaml                    # targets, execution, audit, policy dir (§3.8)
│   ├── models.yaml                    # model aliases + price table (§3.8)
│   ├── budgets.yaml                   # caps + profiles (§3.8)
│   └── policy/
│       ├── base.yaml                  # global denies: interpreters, cred-override flags, secret reads, task/compact_conversation
│       ├── packs/kubectl-read.yaml    # P1 allowlist (helm deferred to P2 — see §3.3 helm note)
│       ├── packs/kubectl-mutate.yaml  # P2 (staging rw)
│       ├── packs/helm-read.yaml       # P2 (needs the release-secrets RBAC decision, §3.3)
│       ├── packs/gh-read.yaml         # P2
│       ├── packs/gh-write.yaml        # P5 (or P3/P4 if prod remediation is PR-based — open question 2)
│       └── envs/{staging,prod}.yaml   # per-env overlays (may only ADD denies / LOWER ceilings)
├── ops/
│   ├── k8s/agent-view-rbac.yaml       # SA + view ClusterRoleBinding + kubeconfig-gen + secrets-denied verify script
│   ├── k8s/agent-mutate-rbac.yaml     # P2: namespace-scoped Role (exact verbs/resources, no secrets/rbac)
│   ├── maintenance.py                 # P3: thread pruning, spend mirror, pg_dump; P4: escalation-timeout sweeper
│   ├── grafana/  prometheus/          # P3 dashboards + alert rules
│   └── executor/                      # P5: Dockerfile, gVisor pod spec, token verifier
├── src/opendevops/
│   ├── __init__.py
│   ├── agent.py                       # build_agent(cfg) -> CompiledStateGraph; module-level `agent` for langgraph.json
│   ├── state.py                       # DevOpsState(DeepAgentState): run_cost_usd, run_usage, budget_stop, tool_results_cache
│   ├── context.py                     # AgentContext (context_schema): principal, interface, environment, budget_profile
│   ├── prompts.py                     # system prompt + playbooks (crashloop, OOM, pending, log-RCA)
│   ├── config.py                      # pydantic-settings loaders for the three YAML files + .env
│   ├── models/registry.py             # alias -> provider:model resolution; parallel-tool-use off; boot check: every agent model priced
│   ├── models/pricing.py              # cache-tier-aware usage_metadata -> USD (§3.4)
│   ├── tools/run_command.py           # the one execution tool (argv-only) + LocalExecutor + scrubber + FS staging (§3.5)
│   ├── tools/ssh.py                   # P5: typed ssh_run via asyncssh
│   ├── policy/schema.py               # pydantic: PolicyFile, Rule, Match, Effect, Decision, ToolCallCtx
│   ├── policy/loader.py               # YAML load + lint (unique ids, coverage, overlay restrictions) + policy_version hash
│   ├── policy/engine.py               # PolicyEngine protocol + YamlRuleEngine; OPA slots in here later
│   ├── policy/hooks.py                # @policy_hook registry (async, 2s timeout, fail-closed); P2: dry-run-before-apply hook
│   ├── policy/middleware.py           # PolicyMiddleware: parse -> cache-check -> decide -> audit -> execute -> audit (§3.3)
│   ├── budget/middleware.py           # CostCapMiddleware + DailyBudgetMiddleware (§3.4)
│   ├── budget/daily.py                # DailyCounter protocol; SqliteDailyCounter (P1), RedisDailyCounter (P3)
│   ├── audit/schema.py                # AuditEvent pydantic, schema_version=1
│   ├── audit/logger.py                # AuditLogger: per-run O_APPEND JSONL, hash chain, (run_id, tool_call_id, type) dedupe
│   ├── audit/verify.py                # `opendevops audit verify` chain walker (per-run files + merged stream)
│   ├── gateway/base.py                # AgentGateway protocol (§3.7)
│   ├── gateway/local.py               # in-process impl: ainvoke/astream + asyncio.wait_for + AsyncSqliteSaver (P2)
│   ├── gateway/server.py              # P3: langgraph_sdk impl — the ONLY module importing langgraph_sdk
│   ├── observability/tracing.py       # single switch: LangSmith env vars now, Langfuse handler later
│   └── interfaces/
│       ├── cli.py                     # typer+rich REPL over the gateway (P1)
│       ├── webapp.py                  # P3: FastAPI: /webhooks/{alertmanager,github,run-complete}, /healthz, /metrics
│       ├── slack_app.py               # P4: slack-bolt AsyncSocketModeHandler
│       └── scheduler/{main.py,jobs.yaml}  # P4: APScheduler service
└── tests/
    ├── unit/policy/                   # table-driven cases incl. bypass corpus (§6)
    ├── unit/{test_pricing.py,test_audit.py,test_config.py}
    ├── graph/                         # full graph + scripted fake chat model, $0
    ├── replay/                        # ReplayToolMiddleware fixtures + live haiku, trajectory-matched
    └── integration/                   # kind + (P5) LocalStack, nightly, budget-capped
```

---

## 3. Component designs

### 3.1 Agent definition (`agent.py`)

```python
def build_agent(cfg: AppConfig, *, checkpointer=None) -> CompiledStateGraph:
    audit  = AuditLogger(cfg.audit.path)
    engine = YamlRuleEngine.load(cfg.policy.dir)          # lints + computes policy_version at load
    graph = create_deep_agent(
        model=registry.resolve(cfg.models.agents["main"]),   # "anthropic:claude-opus-4-8", parallel tool use disabled
        tools=[make_run_command(cfg.execution, cfg.targets)],
        system_prompt=SYSTEM_PROMPT,                          # playbooks + "argv only; no shell; one tool call per turn; grep big output in the FS"
        middleware=[
            # Each budget middleware computes cost independently from AIMessage.usage_metadata
            # via models/pricing.py (stateless, order-immune) — no middleware reads another's delta.
            CostCapMiddleware(pricing, cfg.budgets),          # abefore_model gate + aafter_model accumulate (in-run jump-to-end)
            DailyBudgetMiddleware(pricing, counter, cfg.budgets),
            ModelCallLimitMiddleware(run_limit=cfg.budgets.profile().model_calls, exit_behavior="end"),
            ToolCallLimitMiddleware(run_limit=cfg.budgets.profile().tool_calls, exit_behavior="continue"),
            ToolCallLimitMiddleware(tool_name="run_command",
                                    run_limit=cfg.budgets.profile().shell_calls, exit_behavior="continue"),
            PolicyMiddleware(engine, audit),                  # last custom = innermost wrap: decision closest to execution
        ],
        state_schema=DevOpsState,          # + run_cost_usd, run_usage, budget_stop, tool_results_cache (§1 replay guard)
        context_schema=AgentContext,       # principal, interface, environment, budget_profile — set per run by the gateway
        backend=StateBackend(),            # direct instantiation (factory form deprecated)
        checkpointer=checkpointer,         # None P1; AsyncSqliteSaver P2 CLI; NEVER set on LangGraph Server (platform injects)
    )
    _assert_tool_inventory(graph)          # boot-time: bound tool set == expected inventory; fail on ANY surplus tool
    return graph

agent = build_agent(load_config())         # module-level export for langgraph.json / langgraph dev
```

No subagents, no `interrupt_on`, no MCP, no `skills`/`memory` in v1. Summarization stays the deepagents default in P1 (its model calls are still metered — see §3.4 gateway accounting); P2 replaces it in place (name-match) with `create_summarization_middleware` configured on the haiku alias.

**Boot-time tool-inventory assertion.** deepagents' default stack always includes `SubAgentMiddleware`, so a `task` tool (and the summarizer's `compact_conversation`) can be bound even with `subagents=None`. A spawned subagent would carry **none of our custom middleware** (subagent middleware is per-subagent, not inherited) — an unmetered, unpoliced bypass. Three layers close it: (a) explicit `effect: deny` rules for `task` and `compact_conversation` in `base.yaml`; (b) `_assert_tool_inventory` fails the boot if the compiled graph binds any tool outside `{run_command, write_todos, ls, read_file, write_file, edit_file, glob, grep}` + the explicitly-denied set; (c) `task`/`compact_conversation` cases in the bypass corpus.

### 3.2 Tool inventory (typed signatures)

| Tool | Signature | Phase | Notes |
|---|---|---|---|
| `run_command` | `async def run_command(argv: list[str], timeout_s: int = 60, runtime: ToolRuntime) -> str` | P1 | The only execution tool. Rejects empty argv / non-str elements at the tool boundary before policy even sees it. Output scrubbed (§3.5) before it reaches the model, the virtual FS, or audit. |
| deepagents built-ins | `write_todos`, `ls`, `read_file`, `write_file`, `edit_file`, `glob`, `grep` | P1 | Virtual FS on `StateBackend`; allowed by name in policy (they touch only graph state). |
| `ssh_run` | `async def ssh_run(host: str, argv: list[str], timeout_s: int = 60, sudo: bool = False) -> str` | P5 | asyncssh 2.24.0; pinned known_hosts, per-host connection cache + `asyncio.Semaphore`, fresh channel per command, `sudo -n` + argument-pinned sudoers only. |

`run_command` behavior: output ANSI-stripped, **scrubbed** (§3.5), truncated head+tail at `output_max_chars`; when truncated, the **full** (scrubbed) text is written to the virtual FS (e.g. `/output/<tool_call_id>.txt` via `ToolRuntime` state update) and the ToolMessage names the path so the model uses built-in `grep`. Full-output sha256 always computed for the audit record. File-consuming commands (`kubectl apply -f`, `helm -f`, `-k`) work through the virtual-FS **staging bridge** (§3.5). Cloud CLIs (`aws`/`gcloud`/`az`), `gh`, `helm` need **no new code** — each new target is a policy pack + a credential (P2/P5).

### 3.3 Policy engine + YAML schema

**Pipeline** (`policy/middleware.py`, async-only `awrap_tool_call`):

```
parse (argv -> ToolCallCtx) -> execution-cache check (tool_call_id seen? return cached ToolMessage)
  -> engine.decide -> audit decision-event -> [deny | escalate | rewrite] -> handler
  -> cache result by tool_call_id -> audit execution-event
any exception anywhere -> Decision.deny(rule_id="__fail_closed__")     # fail-closed, always
```

- `ToolCallCtx = {tool_name, args, argv0, verb, flags: dict[str, str|True], positionals: list[str], environment, principal, run_id}` — verb = first non-flag token after argv0; flags parsed as `--k=v` / `--k v`. **Short flags are canonicalized to long names per binary before matching** (`-n → --namespace`, `-s → --server`, `-A → --all-namespaces`, …, from a per-binary alias table in `policy/schema.py`) so alias spellings cannot slip past flag-based rules. Structured fields only: this is exactly the input document an `OpaHttpEngine` will receive later, so OPA slots in behind the `PolicyEngine` protocol (`async def decide(ctx) -> Decision`) with zero middleware/audit changes.
- Unknown tool name → deny (`__unknown_tool__`). Built-ins allowed by name. Deny returns `ToolMessage(content=f"Denied by policy [{rule_id}]: {reason}. {hint}", tool_call_id=..., status="error")` — the model self-corrects; never raise.
- `escalate` → `langgraph.types.interrupt(payload)` shaped like deepagents' native `{"action_requests": [...], "review_configs": [...]}` so one approval UI serves everything; resume via `Command(resume={"decisions":[{"type":"approve"|"edit"|"reject",...}]})`; an approver's `edit` re-enters the full pipeline; audit dedupes on `(run_id, tool_call_id, event_type)` and the execution cache (§3.1) prevents double execution across the interrupt-node re-execution. Requires the P2 checkpointer.
- `rewrite`: all matching rewrites apply in file order, then the rewritten call re-runs parse→decide **exactly once**; second pass must yield plain `allow` or deny with `__rewrite_diverged__` (prevents rewrite loops and rewrite-into-denied).
- `hook`: `@policy_hook`-registered `async def f(ctx) -> Decision | None` under `asyncio.wait_for(..., 2.0)`; exception/timeout → deny.

**Rule schema** (`config/policy/`):

```yaml
version: 1
metadata: {name: kubectl-read, owner: sandipan.kundu@gnosis.io, updated: 2026-07-18}
flags_allowed:                              # per-pack flag allowlist: an allowed verb carrying a flag
  kubectl: [--namespace, --all-namespaces,  # not in this list is DENIED (unanticipated flags never ride through)
            --output, --selector, --context, --tail, --previous, --since, --field-selector, --show-labels]
rules:
  - id: kubectl-read-verbs
    match: {argv0: kubectl,
            verb: {in: [get, describe, logs, top, events, explain, api-resources, cluster-info, version]}}
    effect: allow
    channel: ro
    environments: [staging, prod]
  - id: kubectl-no-cred-override            # creds are pinned by the executor env, never chosen by the model
    match: {argv0: kubectl, flags_any: ["--kubeconfig", "--token", "--server", "--as", "--as-group"]}
    effect: deny                            # short aliases (-s, …) already canonicalized before matching
    reason: "credential/identity flags are pinned by the executor"
  - id: helm-no-cred-override               # same class of denies for every tool-family that can retarget
    match: {argv0: helm, flags_any: ["--kubeconfig", "--kube-context", "--kube-token", "--kube-apiserver"]}
    effect: deny
  - id: gh-no-host-override
    match: {argv0: gh, flags_any: ["--hostname"]}
    effect: deny                            # GH_HOST / GH_ENTERPRISE_TOKEN also stripped from the executor env
  - id: no-secret-reads                     # defense-in-depth; view role excludes secrets server-side too
    match: {argv0: kubectl, verb: {in: [get, describe]},
            resource_any: [secret, secrets]}  # resource matcher: splits comma lists (po,secrets) and
    effect: deny                              # matches the token prefix before "/" (secret/foo)
  - id: kubectl-context-allowlist
    match: {argv0: kubectl, flag_value_not_in: {--context: "${targets.kubernetes.allowed_contexts}"}}
    effect: deny
  - id: no-subagents-or-compaction-tools    # the task tool would spawn an unmetered, unpoliced subagent
    match: {tool_name: {in: [task, compact_conversation]}}
    effect: deny
    reason: "subagent spawning and manual compaction are disabled in this deployment"
  - id: interpreters-hard-deny              # redundant with default-deny; explicit for audit clarity
    match: {argv0: {in: [bash, sh, zsh, dash, ksh, fish, python, python3, perl, ruby, node, awk, gawk,
                         sed, xargs, find, env, eval, watch, expect, socat, nc, ncat, curl, wget,
                         ssh, scp, sudo, su, doas]}}
    effect: deny
    reason: "interpreters/exec-wrappers/net tools are not available; use direct commands"
  # P2 examples:
  - id: force-server-dry-run-first
    match: {argv0: kubectl, verb: {eq: apply}, flags_absent: ["--dry-run"]}
    effect: rewrite
    rewrite: {inject_flags: ["--dry-run=server"]}
    environments: [staging, prod]
  - id: require-dry-run-before-real-apply   # ENFORCES dry-run-first (the rewrite alone is bypassable
    match: {argv0: kubectl, verb: {eq: apply}} #  by an explicit --dry-run=none on the first attempt)
    effect: hook
    hook: dry_run_before_apply              # policy/hooks.py: allow a non-dry-run apply only if state
                                            # records a successful --dry-run=server for the SAME staged-
                                            # manifest sha256 within this run; else deny with a hint
  - id: destructive-deletes-escalate
    match: {argv0: kubectl, verb: {eq: delete}, resource_any: [pvc, persistentvolumeclaim, namespace, ns]}
    effect: escalate
    escalation: {timeout_s: 1800, on_timeout: deny}
```

**Fixed evaluation semantics** (not configurable): (1) collect all matching rules, order-independent; (2) precedence **deny > escalate > hook-result > rewrite > allow**; (3) no match → `__default_deny__`; (4) an allowed verb carrying a flag outside the pack's `flags_allowed` → deny (`__flag_not_allowed__`); (5) per-env overlays (`envs/*.yaml`) may only add rules whose effect is deny/escalate or lower ceilings — the loader rejects anything else; (6) `channel` on the winning allow selects the credential (`ro` calls can never reach `rw` creds — engine invariant). **Loader lint at startup** (hard failure): schema-valid, unique ids, every tool in the inventory named by ≥1 rule or listed under `acknowledged_default_deny:`, every allow rule's pack maps to exactly one credential entry (§3.5), unreachable-rule detection. `policy_version = sha256(sorted file contents)`, stamped on every decision and audit event. Additional invariant: the **generated ro kubeconfig contains only allowed contexts** (the context-allowlist rule cannot fire when `--context` is omitted, so the kubeconfig itself must not offer anything else).

**Helm note (P1 → P2).** Helm stores release state in Secrets (`helm.sh/release.v1`), and the upstream `view` ClusterRole excludes secrets — so `helm list/status/get` **cannot work** against the P1 read-only ServiceAccount, and would collide with the `no-secret-reads` rule and the "total bypass is read-only-no-secrets" invariant. **Decision: helm is dropped from P1**; release information is read via `kubectl get deployments/replicasets` + release annotations/labels. `packs/helm-read.yaml` ships in P2 together with an explicit RBAC decision: the documented alternative is a namespaced Role granting secrets get/list in designated app namespaces for the ro SA — accepted only with the caveat that RBAC cannot filter by secret type, weakening the no-secrets invariant, with the policy-layer `kubectl get secrets` deny as the compensating control.

### 3.4 Budget middleware suite

Defense-in-depth, every limit with an owner. **Ordering-immunity rule:** each budget middleware computes the cost of a model call *itself* from `AIMessage.usage_metadata` via the shared `models/pricing.py` (stateless) — no middleware reads a `run_cost_usd` delta another middleware produced, so `after_model`'s reverse-order execution cannot corrupt accounting.

| Limit | Mechanism | Failure behavior |
|---|---|---|
| Per-run USD | `CostCapMiddleware`: `aafter_model` accumulates into `run_cost_usd`; `abefore_model` `@hook_config(can_jump_to=["end"])` returns `{"jump_to": "end", "budget_stop": ..., "messages": [AIMessage(NOTICE)]}` at `trip_ratio` (0.9) × cap | Graceful end with explanation; ≤1-call overshoot bounded by `max_tokens` on all models |
| Daily USD | `DailyBudgetMiddleware` → `DailyCounter` protocol (`async add(scope, usd) -> float`, `async total(scope) -> float`, keyed `(scope, UTC date)`); SqliteDailyCounter (`INSERT ... ON CONFLICT DO UPDATE`) in P1, RedisDailyCounter (`INCRBYFLOAT` + `EXPIRE 48h`) in P3 | Jump-to-end mid-run; gateway refuses new runs; counter outage → fail-closed for new runs |
| Model calls | `ModelCallLimitMiddleware(run_limit, exit_behavior="end")` | Graceful end |
| Tool calls | `ToolCallLimitMiddleware(run_limit, exit_behavior="continue")` + per-tool instance for `run_command` | Error ToolMessage; model adapts |
| Super-steps | `config={"recursion_limit": profile.recursion_limit}` set by the gateway per run (langgraph's default 25 is too low for agentic loops; our profiles set 250) | `GraphRecursionError`; state survives in checkpointer |
| Wall clock | LocalGateway: `asyncio.wait_for(agent.ainvoke(...), profile.wall_clock_s)`; ServerGateway: langgraph 1.2 `run_timeout` + caller-side `client.runs.cancel` timer | Cancelled. Resumable on the same `thread_id` **from P2 onward** (requires the checkpointer; P1 has none) |
| Context growth | deepagents summarization middleware on the haiku alias (P2) | Bounds per-iteration input tokens |

**Authoritative accounting lives at the gateway (covers the summarizer).** The summarization middleware invokes its model internally; those calls never flow through our `aafter_model`, so state-based accumulation alone undercounts from P1 day one. The gateway therefore wraps **every run** with `get_usage_metadata_callback()` (from `langchain_core.callbacks`; contextvar-based, propagates to *all* model calls in the run, summarizer and future subagents included) and uses that aggregate as the **authoritative** number for the daily counter and the cap cross-check. State-based accumulation remains for the in-run jump-to-end gate (it is what `abefore_model` can see mid-run). A graph test scripts a summarization trigger and asserts the run's accounted cost includes it.

Pricing (`models/pricing.py`, no litellm dependency — we control the model list): `uncached = input_tokens - cache_read - cache_creation`; `usd = (uncached*p.input + cache_read*p.cache_read + cache_creation*p.cache_write + output_tokens*p.output) / 1e6`. Boot check: every model referenced in `models.yaml agents:` must resolve in `pricing:` or the process refuses to start — an unpriced model is an unmetered model.

**Subagent accounting (pre-decided for P5, not built sooner):** `wrap_tool_call` around `task` with `get_usage_metadata_callback()`; measured cost parks in a run-scoped contextvar and the next `abefore_model` flushes it into `run_cost_usd` and re-checks the cap; each `SubAgent["middleware"]` additionally carries its own `CostCapMiddleware` with a sub-cap (invoke-time callbacks cannot cross the Server REST boundary, so accounting must ride inside the graph).

### 3.5 Executor / sandbox (phased)

**P1–P4 (`tools/run_command.py` LocalExecutor):** `await asyncio.to_thread(subprocess.run, argv, capture_output=True, text=True, timeout=timeout_s, stdin=subprocess.DEVNULL, start_new_session=True, env=constructed)`; on timeout `os.killpg(pid, SIGKILL)`. Env is **constructed, never inherited**: `{PATH, HOME, NO_COLOR=1, PAGER=cat, AWS_PAGER="", GIT_TERMINAL_PROMPT=0, DEBIAN_FRONTEND=noninteractive}` + exactly one credential (below). The agent process's own env (Anthropic key, audit path) is physically absent from the child. `GH_HOST` / `GH_ENTERPRISE_TOKEN` are never present (complements the `--hostname` deny).

**Credential map keyed by `(tool-family, environment, channel)`.** Channel alone is too coarse: an allowed `gh` command must not receive `KUBECONFIG`, nor a `kubectl` command `GH_TOKEN`. Each policy pack declares its tool-family; the winning rule's pack selects exactly its own family's credential (`kubectl → KUBECONFIG=<env>-<ro|rw>.yaml`, `gh → GH_TOKEN=<ro|rw>`, later `aws → AWS_*` role). The policy loader asserts at startup that every allow rule's pack maps to exactly one credential entry.

**Output scrubbing (P1, not deferred).** `kubectl describe pod` / `get -o yaml` print literal env-var values, and application logs routinely contain tokens — flowing into LLM context, traces, and audit excerpts from day one. A minimal scrubber runs on every `run_command` output **before** the ToolMessage, the virtual-FS spill file, and the audit excerpt: known token formats (`AKIA[0-9A-Z]{16}`, `ghp_…`/`github_pat_…`, `xox[bap]-…`, `eyJ…` JWT triplets, PEM blocks) plus a high-entropy-string scan → `***`. This is a backstop; the hard control remains server-side denial of secret reads (RBAC + IAM Denies).

**Virtual-FS staging bridge (P2, required for `kubectl apply -f`).** The agent authors manifests in the deepagents virtual FS (graph state); a subprocess cannot see it. For allowed file-consuming flags (`-f`, `--filename`, `--values`, `-k`), the executor: materializes the referenced virtual-FS paths into a per-call private tmpdir → rewrites argv to the staged paths → records each staged file's `{path, sha256}` in the audit `execution` event (the applied manifest is exactly what audit must capture, and the sha256 is what the dry-run-before-apply hook keys on) → deletes the tmpdir after the call. Paths that don't resolve in the virtual FS → deny.

**Credentials per (environment, channel)** — provisioned in `ops/` **before** any policy referencing them ships: `sa-agent-view` → `view` ClusterRoleBinding (with a scripted `kubectl auth can-i get secrets --as=system:serviceaccount:...` check that must fail on every new cluster); P2 `sa-agent-mutate` → namespace-scoped Role enumerating exact verbs/resources (deployments, replicasets, rollouts, scale, configmaps; no secrets/rbac/CRD writes), staging only. P5 cloud: RO roles with explicit Denies on `secretsmanager:GetSecretValue`, `ssm:GetParameter*` (decrypt), `kms:Decrypt`; RW via `sts:AssumeRole(DurationSeconds=900, SourceIdentity=run_id)`.

**P5 executor split** (trigger: any mutating credential broader than the staging namespace Role): separate deployment per (env, channel), gVisor (`runtimeClassName: gvisor`), non-root, read-only rootfs, cap-drop ALL, seccomp RuntimeDefault, egress allowlist, IMDS blocked, per-call tmpfs `/work`. Agent process then holds zero infra credentials; requests carry an **ed25519 decision token** (signature over `sha256(canonical_json(argv)) + run_id + tool_call_id + channel + 120s expiry`; executor holds the public key only) so no code path reaches execution without passing the policy engine. `{{secret:NAME}}` resolver + full literal-match output scrubbing arrive with this split (secrets resolve into subprocess env only, never argv; the P1 pattern-based scrubber remains underneath).

### 3.6 Audit log

`audit/logger.py`, called from inside `PolicyMiddleware` and the budget middlewares. One JSON line per event, `O_APPEND` single-line writes, hash chain `hash = sha256(prev_hash || canonical_json(event))`. **Chains are per-run** — `audit/<run_id>.jsonl`, seeded from a signed run-header event — because LangGraph Server executes runs concurrently across workers and `prev_hash` is a read-modify-write: parallel appends to one shared file would race and permanently break verification (`O_APPEND` guarantees byte atomicity, not chain linearity). The vector shipper merges per-run files into the durable sink; `opendevops audit verify` walks each run chain and the merged stream. A P3 concurrency test runs parallel runs and asserts every chain still verifies.

Event types: `run_started` (the signed chain seed), `decision` (pre-exec), `execution` (post-exec), `escalation`, `resolution` (with approver), `budget_trip`, `policy_error`, `run_completed` (final cost + usage breakdown). Record (schema_version 1):

```json
{"event_id":"01J...ULID","ts":"...","schema_version":1,"event_type":"decision",
 "run_id":"...","thread_id":"...","trace_id":"...",
 "principal":{"interface":"cli","user":"sandipan.kundu@gnosis.io"},"environment":"staging",
 "agent_git_sha":"...","policy_version":"sha256:...","model":"anthropic:claude-opus-4-8",
 "tool":"run_command","tool_call_id":"...","args":{"argv":["kubectl","-n","web","describe","pod","api-0"]},
 "decision":{"effect":"allow","rule_id":"kubectl-read-verbs","reason":"...","channel":"ro","rewritten_argv":null},
 "execution":{"exit_code":0,"duration_ms":812,"stdout_sha256":"...","stdout_excerpt":"...","truncated":false,
              "staged_files":[{"path":"/manifests/deploy.yaml","sha256":"..."}]},
 "prev_hash":"sha256:...","hash":"sha256:..."}
```

Separation: the audit path is excluded from the executor env and unreachable from the virtual FS; P3 ships it via a vector sidecar to the durable sink (open question 4) whose bucket/table policy denies every agent role. Schema is final from P1; only the writer/shipper changes later.

### 3.7 Interfaces

All frontends depend only on `AgentGateway` (`gateway/base.py`): `create_thread`, `start_run(input, context, profile)`, `stream`, `join`, `cancel`, `resume_interrupt(decisions)`, `search_threads`, `delete_thread`. Two impls: `LocalGateway` (P1: in-process `astream(stream_mode=["updates","messages"])`, wall-clock via `wait_for`, **`AsyncSqliteSaver`** — the aiosqlite-backed saver, required by the async-everywhere rule — from P2) and `ServerGateway` (P3: langgraph_sdk; the only module importing it — our compatibility firewall and, if server licensing fails review, the seam where a FastAPI-embedded fallback implements the same protocol). The gateway also owns run-level accounting: `get_usage_metadata_callback()` per run (§3.4).

- **CLI (P1):** typer+rich REPL; renders tokens, tool calls with policy verdicts, `todos`, per-turn cost line; `/cost`, `/cancel` (Ctrl-C → gateway.cancel), P2 `/resume` + interrupt approve/edit/reject prompts. Not `dcode` — it assembles its own agent and would drop our middleware.
- **HTTP (P3):** self-hosted LangGraph Server (docker, Postgres+Redis) — its REST surface (threads/runs/stream/wait/join/cancel) *is* the API (durable queue, exactly-once, stream reattach, and cancellation are exactly the code you don't want to hand-roll; licensing risk is bounded by the gateway seam and a quota probe, see P3). Custom routes in `webapp.py` via `http.app`: `/webhooks/alertmanager` — authenticated by **static bearer token in Alertmanager's `webhook_config.authorization` plus source-network allowlisting** (Alertmanager does not sign webhooks with HMAC natively; fronting with a signing proxy is the upgrade path), dedup on alert fingerprint, incident thread `uuid5(NS_INCIDENT, fingerprint)` + `if_exists="do_nothing"`; `/webhooks/github` — **HMAC-verified** (native `X-Hub-Signature-256`); `/webhooks/run-complete` (target of `client.runs.create(webhook=...)`); `/healthz`; `/metrics` (prometheus_client in-process). Caddy in front with static bearer tokens; oauth2-proxy later. The stack must not run on a cluster the agent manages.
- **Slack (P4):** slack-bolt 1.30.0 Socket Mode (`AsyncSocketModeHandler`, no public URL). `thread_id = uuid5(NS_SLACK, f"{channel}:{thread_ts}")` so Slack-thread replies resume the agent thread; ack ≤3s with placeholder, run with `webhook=`, final answer posted by the run-complete route; escalations as Block Kit approve/edit/reject buttons → `resume_interrupt`, approver recorded in audit. Slack user → principal/profile map in `config/config.yaml`.
- **Scheduler (P4):** our own APScheduler service, never server crons (removes the license dependency and unifies cron+event triggers). Jobs in `scheduler/jobs.yaml` (`misfire_grace_time=300`, `coalesce=True`, `max_instances=1`, 60s jitter); each job: fresh thread, `budget_profile=scheduled`, webhook notification, caller-side cancel timer at `timeout_s`. First jobs: drift detection, cert expiry, backup verification, plus the `ops/maintenance.py` hygiene job (thread pruning via `client.threads.delete`, Redis→Postgres spend mirror, pg_dump).
- **Escalation-timeout sweeper (P4, in `ops/maintenance.py`, run by the scheduler):** `interrupt()` parks a run indefinitely and a caller-side cancel would leave no resolution record. The sweeper lists interrupted runs whose escalation age exceeds the rule's `timeout_s` and **resumes them with `Command(resume={"decisions":[{"type":"reject","message":"escalation timed out"}]})`**, which flows through the normal pipeline: the model receives the deny ToolMessage and a `resolution` audit event is written with `approver="__timeout__"`. This is the enforcement mechanism behind `on_timeout: deny`.

### 3.8 Config schema

`config/config.yaml`:

```yaml
targets:
  kubernetes:
    kubeconfig_ro: ~/.kube/agent-view.yaml   # generated; contains ONLY allowed contexts (§3.3 invariant)
    kubeconfig_rw: null                      # P2
    allowed_contexts: []                     # OPEN QUESTION 1 — must be filled before first run
execution: {cmd_timeout_seconds: 60, output_max_chars: 50000, env_allowlist: [PATH, HOME]}
audit: {dir: ./audit}                        # per-run chain files audit/<run_id>.jsonl (§3.6)
policy: {dir: ./config/policy}
principals: {}                               # P4: slack user id -> {principal, profile}
```

`config/models.yaml`:

```yaml
agents: {main: opus, summarizer: haiku}    # P5 adds subagent entries
aliases:
  opus: anthropic:claude-opus-4-8
  sonnet: anthropic:claude-sonnet-5
  haiku: anthropic:claude-haiku-4-5
pricing:                                   # USD per MTok
  anthropic:claude-opus-4-8:  {input: 5.00, output: 25.00, cache_read: 0.50, cache_write: 6.25}
  anthropic:claude-sonnet-5:  {input: 3.00, output: 15.00, cache_read: 0.30, cache_write: 3.75}
  anthropic:claude-haiku-4-5: {input: 1.00, output: 5.00,  cache_read: 0.10, cache_write: 1.25}
fallback_pricing: error                    # unpriced model -> refuse to boot
```

`config/budgets.yaml` (numbers are proposals — open question 5):

```yaml
trip_ratio: 0.9
fail_mode_on_counter_outage: closed
per_run:
  default:     {usd: 2.00, model_calls: 50, tool_calls: 100, shell_calls: 30,
                recursion_limit: 250, wall_clock_s: 900}
  profiles:
    interactive: {usd: 5.00, wall_clock_s: 1800}
    scheduled:   {usd: 2.00, model_calls: 40}
    incident:    {usd: 10.00, wall_clock_s: 3600}
daily: {global_usd: 50.00, per_principal_usd: 25.00}
```

Multi-provider is free: aliases accept any `provider:model` string `create_deep_agent` takes; the price table is the only thing to extend.

---

## 4. Implementation phases

**P0 — Scaffold (~0.5 day).**
Goal: green empty skeleton. Tasks: repo layout, `pyproject.toml` + `uv.lock`, `config.py` loaders for all three YAML schemas, ruff/mypy/pytest CI, `ops/k8s/agent-view-rbac.yaml` + kubeconfig-gen (allowed-contexts-only) + secrets-denied verify script. Files: pyproject, config/*, src/opendevops/{config,models}/, ops/k8s/, tests/unit/test_config.py. DoD: `uv run opendevops --help` works; CI green; verify script fails `can-i get secrets` against the target cluster.

**P1 — Read-only K8s diagnostics via CLI (~1 week). The MVP; independently useful.**
Goal: full-auto crashloop/OOM/pending/log-RCA investigations on staging with the complete safety core. Tasks: `run_command` + LocalExecutor **including the P1 output scrubber**; `policy/` (schema with flag-alias canonicalization + per-pack `flags_allowed`, loader+lint, YamlRuleEngine with allow/deny, middleware, fail-closed); `kubectl-read.yaml`, `base.yaml` (interpreter denies, cred-override denies for kubectl/helm/gh, secret-read denies with prefix/comma-aware resource matching, **`task`/`compact_conversation` denies**); boot-time tool-inventory assertion in `agent.py`; parallel-tool-use disabled in `models/registry.py`; `audit/` (per-run chain logger, verify CLI); `budget/` (pricing, CostCap, DailyBudget+Sqlite, limit factories); gateway-level `get_usage_metadata_callback()` accounting; `state.py` (incl. `tool_results_cache`), `context.py`, `agent.py`, `prompts.py` playbooks; `gateway/{base,local}.py`; `cli.py`. **Helm is not in P1** (release-secrets RBAC conflict — §3.3); release info via kubectl. Files: everything under src/ except interfaces/{webapp,slack_app,scheduler}, gateway/server.py, tools/ssh.py. DoD / verification: (a) policy unit suite green including the full bypass corpus as deny cases (§6); (b) pricing cache-tier fixtures green; (c) audit chain verifier passes and detects a tampered line; (d) graph-deterministic tests: scripted fake chat model trips the cost cap, gets a "continue" ToolMessage at the tool limit, produces exactly the expected audit events, and a scripted summarization trigger shows up in the run's accounted cost; (e) boot fails loudly when a surplus tool is bound or a model is unpriced; (f) live smoke on kind with seeded CrashLoopBackOff: correct RCA, audit shows only allow decisions, run cost < cap, Ctrl-C cancels cleanly.

**P2 — Mutations + escalation + eval harness (~1 week).**
Goal: deploy→verify→rollback on staging in full-auto with a rare escalation path. Tasks: `agent-mutate-rbac.yaml` + rw kubeconfig; `kubectl-mutate.yaml` (allow `rollout status|history|undo`, `apply`, `scale`; `channel: rw`); **virtual-FS→executor staging bridge** for `-f`/`--values`/`-k` with staged-file sha256 in audit (§3.5); `rewrite` (dry-run injection, context pinning) with convergence re-pass; **`dry_run_before_apply` `@policy_hook`** keyed on staged-manifest sha256 (§3.3) — the first shipped code hook; `escalate` via in-middleware `interrupt()` with the `tool_call_id` execution cache preventing sibling replay; **`AsyncSqliteSaver`** in LocalGateway; CLI interrupt rendering + `Command(resume=...)`; audit dedupe + escalation/resolution events; summarization middleware → haiku (name-match replacement); `helm-read.yaml` + the release-secrets RBAC decision (§3.3); `gh-read.yaml` + `GH_TOKEN` (CI-failure diagnosis is nearly free under argv design); ReplayToolMiddleware + first agentevals golden trajectories. Files: policy/{engine,middleware,hooks}, tools/run_command.py (staging), gateway/local, cli, config/policy/packs/*, ops/k8s/, tests/replay/. DoD: deploy→verify→rollback end-to-end on kind with one seeded escalation approved from the CLI; **resume-replay test: a resume after escalation produces exactly one `execution` audit event per `tool_call_id`**; an explicit `--dry-run=none` first-attempt apply is denied by the hook; trajectory suite (`create_trajectory_match_evaluator(trajectory_match_mode="superset")`) asserts dry-run-before-apply and zero denied-effect executions (checked mechanically from the audit log); this suite becomes the **pinned-trio upgrade gate**.

**P3 — Service mode: LangGraph Server + webhooks (~1 week).**
Goal: HTTP API from a second machine; alert-driven runs. Tasks: `langgraph.json`, `docker-compose.yml` (server, Postgres, Redis, Caddy, vector); quota probe (count super-steps of the top-5 workflows via the `checkpoints` stream, extrapolate monthly; >60% of verified tier quota → decide license-up vs documented FastAPI-embed fallback behind the gateway); `gateway/server.py`; `webapp.py` routes (Alertmanager bearer-token auth, GitHub HMAC) + `/metrics`; RedisDailyCounter; audit shipping (vector merges per-run chain files) to the durable sink; `ops/maintenance.py`; Grafana/Prometheus. Drop the local saver on this path (platform injects Postgres checkpointing — never pass a checkpointer to the Server). Files: langgraph.json, docker-compose.yml, gateway/server.py, interfaces/webapp.py, budget/daily.py, ops/*. DoD: `POST /threads/{id}/runs` + SSE stream and `runs/join` reattach from a second machine; Alertmanager webhook → RCA on the incident thread; `client.runs.cancel` works; daily counter survives server restart; audit lines land in the durable sink; **concurrent-runs test: parallel runs produce per-run chains that all verify**.

**P4 — Slack + scheduled runs (~3–4 days).**
Goal: chat-ops and hygiene automation. Tasks: `slack_app.py` (Socket Mode, thread mapping, ack-fast + webhook completion, Block Kit escalation buttons, principal map); `scheduler/` (APScheduler, jobs.yaml: drift, certs, backups, maintenance); **escalation-timeout sweeper** (§3.7): resumes timed-out interrupts with a reject decision, `resolution` event `approver="__timeout__"`. Files: interfaces/slack_app.py, interfaces/scheduler/, ops/maintenance.py, webapp.py (run-complete → Slack), config/config.yaml principals. DoD: alert → Slack RCA in-thread; reply in the Slack thread resumes the same agent thread; nightly job produces a report; a scheduled run hitting `escalate` pings the configured channel and resumes on approval **or is auto-denied by the sweeper at timeout with the audited `__timeout__` resolution**.

**P5 — Expansion + hardening (on demand, in value order).**
(a) Cloud read-only packs (`aws`/`gcloud`/`az` YAML + scoped roles with explicit secret-read Denies) — zero new code; (b) `ssh_run` (asyncssh); (c) first subagent (haiku log-summarizer) + the pre-decided task-wrap cost accounting (the `task` deny rule is then narrowed to named subagents only, and the tool-inventory assertion updated); (d) executor service split: gVisor container, signed decision tokens, `{{secret:NAME}}` resolver + full output scrubbing — **mandatory before any mutating credential broader than the staging namespace Role**; (e) `OpaHttpEngine` behind the existing protocol when multi-service policy sharing or non-engineer editing materializes; (f) **`gh-write.yaml` pack for PR-based remediation**: `gh run rerun`, `gh pr create`, `gh api` with a method/path allowlist (`POST` only to `/repos/{allowed}/...`), backed by a fine-grained PAT as the `rw` GitHub credential; authoring uses `gh api` contents endpoints to commit virtual-FS files, reusing the P2 staging bridge (argv-world has no `git`). **If open question 2 lands on "prod mutations only via PRs the agent opens", this pack moves up to P3/P4 as core scope.** (g) MCP only if a needed integration exists solely as an MCP server — then via a single `client_factory()` that always injects `tool_interceptors=[make_mcp_interceptor(engine, audit)]`, with a CI grep forbidding direct `MultiServerMCPClient(` construction. DoD per item: its policy pack ships with corpus deny-tests; (d) additionally proves the executor rejects an unsigned/expired/hash-mismatched request.

---

## 5. Dependency pins

```toml
[project]
name = "opendevops"
version = "0.1.0"
requires-python = ">=3.11,<4.0"
dependencies = [
  "deepagents==0.6.12", "langchain==1.3.14", "langgraph==1.2.9",   # move only together, through the P2 gate
  "langchain-anthropic>=1.4.7,<2",
  "pydantic-settings>=2.6", "pyyaml>=6", "typer>=0.15", "rich>=13",
]
[project.optional-dependencies]
p2     = ["langgraph-checkpoint-sqlite", "aiosqlite"]   # AsyncSqliteSaver (async-everywhere rule)
server = ["langgraph-sdk>=0.4,<0.5", "fastapi", "sse-starlette", "redis>=5", "prometheus-client"]
slack  = ["slack-bolt==1.30.0", "apscheduler>=3.10,<4"]
ssh    = ["asyncssh==2.24.0"]
dev    = ["pytest", "pytest-asyncio", "ruff", "mypy",
          "agentevals==0.0.9", "langgraph-cli[inmem]==0.4.31"]
[project.scripts]
opendevops = "opendevops.cli:app"
```

uv-managed; `uv.lock` committed. Server image tag pinned alongside library pins. Deliberately absent in v1: litellm (own price table), tree-sitter (no shell strings), kubernetes SDK (kubectl-via-argv suffices until a watch/structured need appears), hvac/sops (P5d).

---

## 6. Verification strategy

| Tier | What | Runs | LLM cost |
|---|---|---|---|
| Unit | Policy engine (table-driven YAML cases), pricing math, audit chain, config schemas | every push | $0 |
| Graph-deterministic | Real `create_deep_agent` graph + scripted fake chat model (`langchain_core.language_models.fake_chat_models`) + `InMemorySaver` | every push | $0 |
| Replay | ReplayToolMiddleware canned ToolMessages (record mode captures real outputs) + live haiku, trajectory-matched | nightly + pre-release | ~$1–5 |
| Integration | kind (+ LocalStack from P5a), seeded failure scenarios, live model, `ci` budget profile | nightly | capped by CostCapMiddleware |

- **Bypass corpus (CI-blocking, P1):** argv-world adaptation of the arXiv taxonomy, every case asserted deny with the expected rule_id: `["bash","-c",...]`, `["sh"]`, `["python3","-c",...]`, `["awk","BEGIN{system(...)}"]`, `["sed","-e","...e..."]`, `["find",".","-exec",...]`, `["xargs",...]`, `["env","KUBECONFIG=/x","kubectl",...]`, `["kubectl","--kubeconfig","/x",...]`, `["kubectl","-s","https://attacker.example","get","pods"]` and `["kubectl","--server=...",...]` (short-alias canonicalization), `["kubectl","--as","admin",...]`, `["kubectl","get","secrets"]`, `["kubectl","get","secret/foo"]`, `["kubectl","get","po,secrets"]` (prefix/comma resource matching), `["helm","--kubeconfig","/x","list"]`, `["gh","--hostname","evil.example","pr","list"]`, `["kubectl","--context","prod",...]` (outside allowlist), an allowed verb with a flag outside `flags_allowed`, tool_name `task`, tool_name `compact_conversation`, `["curl",...]`, `["rm","-rf","/"]`, unknown binaries, empty argv, non-string argv elements. Invariants: parse/pipeline exception ⇒ deny; unknown tool ⇒ deny.
- **Replay-safety test (P2, graph tier):** scripted model issues one allowed + one escalating call; resume after approval must yield exactly one `execution` audit event per `tool_call_id` (execution cache) and no re-run of the allowed sibling.
- **Accounting test (P1, graph tier):** scripted summarization trigger must appear in the gateway-accounted run cost (`get_usage_metadata_callback` aggregate ≥ state-accumulated cost).
- **Mechanical CI gates, no LLM judge:** (a) trajectory superset match per golden workflow (crashloop, OOM, pending, CI-failure, deploy-verify-rollback); (b) zero audit events where a denied call executed; (c) zero mutate-channel calls outside the scenario allowlist — all checked from the audit JSONL. `create_trajectory_llm_as_judge` runs advisory-only.
- **Upgrade gate:** the pinned trio moves only on a branch passing all four tiers.
- **Cross-checks (P3+):** weekly LangSmith-computed cost vs gateway-accounted cost (>5% divergence alerts — catches price-table staleness); audit-chain concurrency test (parallel runs, all per-run chains verify); Prometheus alerts on policy-denial spikes (bypass probing signal), daily spend >80%, scheduler silence >1.5× period, audit-shipper lag.
- **Manual end-to-end checklist per release:** (1) kind CrashLoopBackOff → correct RCA, only `ro` channel in audit; (2) staging deploy→verify→rollback with dry-run rewrite + hook enforcement visible in audit (staged-manifest sha256 present); (3) trigger one escalation, approve from CLI/Slack, confirm `resolution` event with approver; let one time out, confirm `approver="__timeout__"`; (4) Ctrl-C and `runs/cancel` mid-run, resume the thread (P2+); (5) exhaust a per-run cap, confirm graceful final message + `budget_trip` event; (6) `opendevops audit verify` on the live log; (7) run the secrets-denied RBAC verify script against every configured context; (8) confirm a synthetic `AKIA...` string in pod output arrives at the model as `***`.

---

## 7. Open questions for the user

Grouped by the phase they block. Everything else in this plan proceeds on stated defaults.

**Blocks P1 (first run):**
1. **Blast radius + environment inventory:** the concrete list of kube contexts for `targets.kubernetes.allowed_contexts`, their env labels (staging/prod), and whether production clusters are included read-only from day one or staging-only first.

**Shapes P2 (and P5 ordering):**
2. **Prod mutation posture:** is prod strictly read-only in v1 — mutations reach prod only via CI/CD PRs the agent opens (which pulls the `gh-write` pack forward to core scope) — or do you want prod-rw behind escalation eventually? (Staging-rw in P2 is assumed either way.)
3. **Escalation policy:** who may approve (CLI now, Slack users/groups later), is self-approval allowed, single-approver vs two-person rule for destructive ops, and routing + timeout for non-interactive runs (which channel/on-call; auto-deny after 30 min is the proposed default).
4. **Budget numbers:** confirm or adjust — $5/run interactive, $2/run scheduled, $10/run incident, $50/day global, $25/day per principal, trip at 90%; and should scheduled runs get their own daily envelope so chat-heavy days cannot starve nightly checks?

**Gates P3:**
5. **LangGraph Server licensing:** is a LANGSMITH_API_KEY / standalone-server license with its plan-dependent node-execution quota acceptable (including metering phone-home), and do you approve the fallback trigger (projected volume >60% of verified quota ⇒ license up or execute the FastAPI-embedded gateway fallback)?
6. **Trace residency:** is hosted LangSmith acceptable given traces contain cluster names, commands, and log excerpts, or should P3 stand up self-hosted Langfuse (adds Postgres+ClickHouse+Redis+S3)?
7. **Audit durable sink + retention (compliance owner):** S3 Object Lock, INSERT-only Postgres, or forwarding to existing Loki/SIEM — and required retention length.
8. **Stack placement + Postgres:** dedicated ops VM vs separate ops cluster for the compose stack (it must not run on a cluster the agent manages), and self-run Postgres container vs managed Postgres.

**Needed by P4:**
9. **Slack authorization:** which Slack users/channels map to which principals/profiles, and is any mutating action allowed from Slack in v1 or is Slack read-only + escalation-approval only?

**Answer when scheduling P5:**
10. **Secrets backend + SSH trust model:** which secrets backend is actually in use today (Vault vs SOPS vs cloud-native) for the resolver's first provider; SSH CA vs provisioning-time known_hosts pinning; feasibility of argument-pinned NOPASSWD sudoers on the VM fleet.
