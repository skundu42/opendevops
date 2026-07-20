# Development

## Setup

```sh
uv sync --extra checkpoint --extra server --extra slack --extra ssh --extra dev
```

Everyday commands:

```sh
uv run pytest -q               # full suite (deterministic, $0 LLM cost)
uv run ruff check .            # lint (line length 100, isort, bugbear, …)
uv run mypy src ops            # strict-ish typing (disallow_untyped_defs)
uv run opendevops --help
```

CI (`.github/workflows/ci.yml`) runs exactly ruff → mypy → pytest on every push and PR.

## Test tiers

| Tier | Where | What it proves | LLM cost |
|---|---|---|---|
| Unit | `tests/unit/` | policy engine (table-driven + the **bypass corpus**), pricing math, audit chains, config schemas, executor firewall, manifests | $0 |
| Graph-deterministic | `tests/graph/` | the *real* compiled graph driven by a scripted fake chat model: budget trips, escalation resume, replay safety, audit event exactness | $0 |
| Replay | `tests/replay/` | recorded tool outputs + golden trajectories through the real policy/audit/budget stack; the mechanical audit gates | $0 (live-model mode optional) |
| Integration | kind cluster, nightly | seeded failure scenarios end-to-end with a live model | budget-capped |

Two testing ideas worth knowing before you change anything:

- **The audit log is the oracle.** `tests/replay/audit_gates.py` checks trajectories mechanically
  from the audit JSONL: no denied call ever executed, no mutate-channel call outside the
  scenario's allowlist, dry-run recorded before every real apply, exactly one execution per
  `tool_call_id` across interrupt resumes.
- **Deny tests name their rule.** Corpus cases assert the *specific* rule id that fired, not just
  "denied" — so a refactor that changes which layer catches a bypass is visible.

## Conventions (enforced, not aspirational)

- **Fail closed.** Any policy-pipeline exception is a deny. Missing credentials, unpriced models,
  uncovered packs, unset webhook secrets, and counter outages refuse to boot/serve rather than
  degrade. Preserve this property in anything you add.
- **SDK firewall.** `src/opendevops/gateway/server.py` is the **only** module that may import
  `langgraph_sdk` (`tests/unit/test_executor_firewall.py` enforces related boundaries). Interfaces
  depend on the `AgentGateway` protocol only.
- **argv-only.** No code path may construct a shell string from model input. New execution
  surfaces must be structured tools with their own policy family.
- **Name-not-value.** Config files carry env var *names*; values live in the environment
  ([configuration](configuration.md#the-name-not-value-convention)).
- **Audit-order invariant.** The `decision` event is written before execution, `execution` after,
  by the same middleware. Don't split them.
- **Async end-to-end.** Sync `invoke` cannot be cancelled mid-node; wall-clock enforcement
  depends on cancellability.

## The pinned trio

`deepagents`, `langchain`, and `langgraph` are pinned **exactly** and move only **together**,
through the gate documented in [`docs/UPGRADE.md`](../docs/UPGRADE.md) — these are beta-era
libraries and the safety core touches a handful of private/emergent behaviors (tool binding,
middleware hook order, interrupt replay) that a minor bump can silently change. `uv.lock` is
load-bearing; the upgrade procedure is: branch, bump the trio, run all four tiers, read
UPGRADE.md's landmine list against the diff.

`docs/api-notes.md` records the introspection of the installed libraries (regenerate with
`uv run python scripts/api_spike.py`) — check it when an upstream API question comes up before
reaching for the source.

## Adding capability, in the intended order

A new *target* (another CLI tool family) usually needs **zero new Python**:

1. policy pack + base.yaml denies ([policy guide](policy.md#writing-a-new-pack));
2. credential config + provisioning ([security model](security-model.md#credentials-the-real-boundary));
3. corpus deny-tests;
4. if file-consuming flags are involved, extend the staging-bridge flag list deliberately.

A new *tool* (like `ssh_run`) is a bigger event: structured signature, its own policy family and
parsing, executor/credential wiring, scrubbing, audit fields, corpus — use `tools/ssh_run.py` as
the template.

A new *interface* implements against `AgentGateway` only, and inherits policy, budgets, audit,
and escalation for free — use `interfaces/slack_app.py` as the template.

## Docs map

| Document | Contents |
|---|---|
| `guides/` | this documentation set |
| [`docs/DEPLOY.md`](../docs/DEPLOY.md) | service-mode runbook (superset of the [deployment guide](deployment.md)'s bring-up) |
| [`docs/UPGRADE.md`](../docs/UPGRADE.md) | the pinned-trio upgrade gate + landmine list |
| [`docs/api-notes.md`](../docs/api-notes.md) | verified API-reality notes for the pinned libraries |
| `ops/executor/README.md` | executor-service manifests + the remote-mode pre-deployment gates |
