# opendevops

[![CI](https://github.com/skundu42/opendevops/actions/workflows/ci.yml/badge.svg)](https://github.com/skundu42/opendevops/actions/workflows/ci.yml)

An **autonomous DevOps agent** built on LangChain [deepagents](https://github.com/langchain-ai/deepagents):
it investigates and operates Kubernetes, GitHub, cloud CLIs, and remote hosts **fully
autonomously** — no human in the loop as the normal path — under a fail-closed policy engine,
hard budget ceilings, and a tamper-evident audit trail.

```text
you › why is pod api-0 in namespace web crash-looping?
→ run_command kubectl -n web describe pod api-0
→ run_command kubectl -n web logs api-0 --previous --tail 200
The container exits with OOMKilled (exit 137): the JVM heap is configured above the
container memory limit. …
spent $0.0841 (run) / $0.34 (today)
```

## Why it's safe to let it run

- **There is no shell.** The one execution tool takes `argv: list[str]`, runs with `shell=False`,
  and interpreters (`bash`, `python`, `xargs`, `awk`, …) are hard-denied. The entire
  command-injection bypass taxonomy has no surface to exist on.
- **Credentials are the boundary, not the policy.** Every allowed action maps to a
  per-(tool-family, environment, read/write) credential, minimally scoped server-side. The design
  invariant: *even a total policy bypass is read-only and cannot read secrets*.
- **Default-deny, fail-closed policy.** Layered YAML rules + code hooks decide
  allow / deny / rewrite / escalate per call; no matching rule — or any pipeline exception — is a
  deny. Residual risky calls suspend for human approve / edit / reject.
- **Hard budgets.** Per-run and daily USD caps, model/tool/step limits, wall clocks — each
  enforced by its own mechanism, all fail-closed. An unpriced model refuses to boot.
- **Tamper-evident audit.** Every decision and execution lands in a per-run sha256 hash chain the
  agent has no write path to; `opendevops audit verify` proves integrity end-to-end.

The full reasoning lives in the [security model](guides/security-model.md).

## What it can do

| Capability | How |
|---|---|
| Kubernetes diagnostics (crashloops, OOM, pending pods, log RCA) | read-only kubectl pack against a `view`-role ServiceAccount |
| Staged mutations (deploy / scale / rollback, staging) | kubectl-mutate pack with **enforced** server-dry-run-before-apply |
| GitHub CI diagnosis + PR-based remediation | gh-read / gh-write packs, method+path-allowlisted `gh api` |
| Cloud read-only investigation (AWS / GCP / Azure) | aws/gcloud/az packs over secret-denied read-only roles |
| Remote host checks over SSH | structured `ssh_run` tool: host allowlist, pinned user/key/known_hosts |
| Chat-ops | Slack Socket Mode: threads map to agent threads, approvals as buttons |
| Scheduled operations | APScheduler service: drift detection, cert expiry, backup verification |
| Alert-driven RCA | Alertmanager/GitHub webhooks → runs on stable incident threads |

## Quickstart

```sh
git clone https://github.com/skundu42/opendevops.git && cd opendevops
uv sync --extra checkpoint --extra server --extra dev
cp .env.example .env                        # set ANTHROPIC_API_KEY

# give the agent its own read-only, secrets-denied credential:
kubectl apply -f ops/k8s/agent-view-rbac.yaml
ops/k8s/gen-kubeconfig.sh <your-context>    # → ~/.kube/agent-view.yaml, allowed contexts only
#   then list <your-context> under targets.kubernetes.allowed_contexts in config/config.yaml

uv run opendevops config check
uv run opendevops chat
```

Step-by-step, including the fail-closed boot gates you'll meet:
**[guides/getting-started.md](guides/getting-started.md)**.

## Architecture in one paragraph

One deepagents graph carries the entire safety core as middleware (cost caps → daily budgets →
call limits → policy+audit, innermost); every frontend — CLI REPL, LangGraph Server HTTP API,
Slack, scheduler — talks to it through a single `AgentGateway` protocol, so moving from
in-process to service mode is configuration, not a rewrite. Execution is argv-only into a
constructed environment holding exactly one credential; outputs are secret-scrubbed before the
model sees them; large outputs spill into the agent's virtual filesystem for grepping. An
experimental **executor service** mode moves execution (and all credentials) into a gVisor
sandbox authorized per-call by ed25519-signed policy decisions.
Details: **[guides/architecture.md](guides/architecture.md)**.

## Documentation

| | |
|---|---|
| [Getting started](guides/getting-started.md) | clone → configured → first live session |
| [Architecture](guides/architecture.md) | the one-graph design, middleware, tools, seams |
| [Configuration](guides/configuration.md) | every knob in the three YAML files |
| [Policy](guides/policy.md) | the engine, rule schema, packs, writing your own |
| [Security model](guides/security-model.md) | layered boundaries; what holds when policy fails |
| [Budgets](guides/budgets.md) | cost/step/time ceilings and their enforcement |
| [Audit](guides/audit.md) | hash-chained trails and verification |
| [Interfaces](guides/interfaces.md) | CLI, HTTP + webhooks, Slack, scheduler |
| [Deployment](guides/deployment.md) | service mode, monitoring, executor service, go-live gates |
| [Development](guides/development.md) | tests, conventions, extending the agent |

## CLI

| Command | Does |
|---|---|
| `opendevops chat` | streaming REPL (`--environment`, `--profile`, `--principal`; `/cost`, Ctrl-C cancels) |
| `opendevops config check` | validate all config; prints counts or the exact error |
| `opendevops audit verify --dir <dir>` | verify every audit hash chain; exit 1 on any tamper |
| `opendevops version` | version |

## Status

Feature-complete and extensively tested: read-only K8s diagnostics, staged mutations with
escalation, service mode, Slack + scheduler, cloud/ssh/gh-write packs, and the executor split.
Before pointing it at real infrastructure, work through the standing
[pre-go-live gates](guides/deployment.md#standing-pre-go-live-gates-all-tiers) — most notably:
`executor.mode=remote` is **experimental** (keep the default `local`), and the service stack must
never run on a cluster the agent manages.

## Contributing and development

```sh
uv sync --extra checkpoint --extra server --extra slack --extra ssh --extra dev
uv run pytest -q          # deterministic full suite, $0 LLM cost
uv run ruff check .
uv run mypy src ops
```

Contributions are welcome — see **[CONTRIBUTING.md](CONTRIBUTING.md)**, and
**[guides/development.md](guides/development.md)** for test tiers, enforced conventions
(fail-closed, SDK firewall, argv-only), and the pinned-dependency upgrade gate. Security reports:
**[SECURITY.md](SECURITY.md)**.

## License

[Apache-2.0](LICENSE)
