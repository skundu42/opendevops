# Getting started

This guide takes you from a fresh clone to a live, read-only Kubernetes diagnostics session in the
CLI REPL. The local CLI tier needs **zero infrastructure** — no server, no database, no Slack app.

## Prerequisites

- Python **3.11+** and [uv](https://docs.astral.sh/uv/)
- `kubectl` on your `PATH`, with admin-ish access to the cluster(s) you want the agent to read
  (needed once, to provision the agent's own scoped ServiceAccount)
- An **Anthropic API key** for live runs
- Optional for a safe sandbox: [kind](https://kind.sigs.k8s.io/) to run everything against a
  throwaway local cluster

## 1. Install

```sh
git clone https://github.com/skundu42/opendevops.git
cd opendevops
npm ci
npm run frontend:build
uv sync --extra checkpoint --extra server --extra dev
```

Extras, and when you need them:

| Extra | Brings in | Needed for |
|---|---|---|
| `checkpoint` | `langgraph-checkpoint-sqlite`, `aiosqlite` | escalation / resume (the CLI checkpointer) |
| `server` | `langgraph-sdk`, `fastapi`, `redis`, … | service mode + parts of the test suite |
| `slack` | `slack-bolt`, `apscheduler` | Slack chat-ops + the scheduler service |
| `ssh` | `asyncssh` | the `ssh_run` remote-exec tool |
| `dev` | `pytest`, `ruff`, `mypy`, `agentevals`, … | running tests |

## 2. Environment

```sh
cp .env.example .env
```

For the local CLI, only `ANTHROPIC_API_KEY` is required. The other entries in `.env.example`
belong to service mode. The model key is used by the agent process only — it is **never**
passed into the environment of any subprocess the agent runs (the executor constructs child
environments from scratch; see the [security model](security-model.md)).

Optionally set `LANGSMITH_TRACING=true` + `LANGSMITH_API_KEY` for tracing.

## 3. Provision the agent's read-only credential

The agent never uses your kubeconfig. It gets its own ServiceAccount bound to the built-in `view`
ClusterRole (which excludes Secrets), and a **generated kubeconfig that contains only the contexts
you explicitly allow**:

```sh
# once per target cluster:
kubectl apply -f ops/k8s/agent-view-rbac.yaml

# build ~/.kube/agent-view.yaml containing ONLY the named contexts,
# each rewired to authenticate as the agent's ServiceAccount:
ops/k8s/gen-kubeconfig.sh kind-kind        # replace with your context name(s)
```

Verify the credential really cannot read Secrets — this must print `no`:

```sh
kubectl auth can-i get secrets --as=system:serviceaccount:opendevops:sa-agent-view
```

## 4. Allow the contexts in config

Edit `config/config.yaml` and list the same context(s):

```yaml
targets:
  kubernetes:
    kubeconfig_ro: ~/.kube/agent-view.yaml
    allowed_contexts: [kind-kind]
```

An empty `allowed_contexts` is a deliberate **fail-closed boot gate** — the CLI refuses to start a
chat until you have made an explicit blast-radius decision.

## 5. Validate and run

```sh
uv run opendevops config check
# config OK: 1 contexts allowed, 3 budget profiles, 3 priced models

uv run opendevops chat
```

`chat` options:

| Option | Default | Meaning |
|---|---|---|
| `--environment` | `staging` | policy environment overlay (`staging` \| `prod`) |
| `--profile` | `interactive` | per-run budget profile (see [budgets](budgets.md)) |
| `--principal` | OS user | who the run is attributed to (audit + per-principal daily budget) |

In the REPL:

- assistant text streams as it arrives; tool calls render as `→ run_command kubectl get pods …`
- policy denials show in red with the winning rule id
- a per-turn cost line shows run and daily spend; `/cost` shows session/day totals on demand
- `/quit` (or `/exit`, `/q`) exits; **Ctrl-C cancels the current run** without killing the REPL
- if a call hits an `escalate` rule, a red approval panel appears and you choose
  `approve / edit / reject` — see [interfaces](interfaces.md#escalations-in-the-cli)

Try: `why is pod api-0 in namespace web crash-looping?`

## 6. Inspect the audit trail

Every run wrote a hash-chained JSONL file under `./audit/`:

```sh
uv run opendevops audit verify --dir ./audit
```

This walks every per-run chain and fails loudly on any tampered, reordered, or dropped line. See
the [audit guide](audit.md).

## Troubleshooting — boot refusals are features

The process **refuses to start** rather than run in a degraded state. The common gates:

| Symptom | Cause | Fix |
|---|---|---|
| `no kubernetes contexts are allow-listed` | `targets.kubernetes.allowed_contexts: []` | steps 3–4 above |
| config INVALID: unpriced model | a model in `models.yaml agents:` has no `pricing:` entry | add the price row (an unpriced model is an unmetered model) |
| pack refuses to boot (credential coverage) | a policy pack is present but its tool family has no credential configured (e.g. `gh-read.yaml` with `targets.github.token_env: null`) | configure the credential env var name, or remove the pack |
| `budgets.daily.backend: redis` without `redis_url` | daily counter misconfigured | set `redis_url` or use the default `sqlite` |
| boot fails on tool inventory | the compiled graph bound a tool outside the expected set | this is the tamper guard doing its job; see [architecture](architecture.md#boot-time-assertions) |

## Where next

- [Architecture](architecture.md) — how the one-graph, many-frontends design fits together
- [Policy](policy.md) — read `config/policy/` and write your first pack
- [Configuration](configuration.md) — every knob in the three YAML files
- [Deployment](deployment.md) — service mode (HTTP API, webhooks, authenticated dashboard,
  monitoring)
