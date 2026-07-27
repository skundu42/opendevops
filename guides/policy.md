# The policy engine

Every tool call the model makes passes through `PolicyMiddleware`
(`src/opendevops/policy/middleware.py`). The engine is **default-deny, fail-closed, layered**:
global denies in `base.yaml`, allows only in per-tool-family packs, per-environment overlays that
can only tighten.

## The decision pipeline

```
parse (argv → ToolCallCtx)
  → execution-cache check (tool_call_id already executed? return cached ToolMessage)
  → engine.decide(ctx)
  → audit `decision` event
  → effect handler: allow | deny | rewrite | escalate | hook
  → execute (only on allow)
  → cache result by tool_call_id
  → audit `execution` event

any exception, anywhere  →  deny (rule_id="__fail_closed__")
```

A deny is returned to the model as an error ToolMessage —
`Denied by policy [rule-id]: reason. hint` — so the model self-corrects; the pipeline never raises.

### What the engine sees: `ToolCallCtx`

argv is parsed into structured fields **before** any rule matching:

| Field | Meaning |
|---|---|
| `tool_name` | `run_command`, `ssh_run`, `task`, a built-in, … |
| `argv0` | the binary (`kubectl`, `gh`, `aws`, …) |
| `verb` | first non-flag token after argv0 (`get`, `apply`, `pr`, …) |
| `flags` | `--k=v` / `--k v` parsed into a dict; **short flags canonicalized to long names per binary** (`-n` → `--namespace`, `-s` → `--server`, `-A` → `--all-namespaces`) so alias spellings cannot slip past flag rules |
| `positionals` | non-flag tokens after the verb |
| `environment`, `principal`, `run_id` | run context |

`aws` / `gcloud` / `az` are *subcommand binaries*: `aws secretsmanager get-secret-value` parses
with `verb=secretsmanager` and the action as `positionals[0]`, which is what lets secret-material
actions be pinned at their exact position.

This structured context is deliberately the same input document an OPA engine would receive —
`OpaHttpEngine` can slot in behind the `PolicyEngine` protocol later with zero middleware changes.

## Rule anatomy

```yaml
# from config/policy/packs/kubectl-read.yaml
version: 1
metadata: {name: kubectl-read, owner: opendevops, updated: "2026-07-18"}
tool_family: kubectl              # binds this pack's allows to the kubectl credential

flags_allowed:                    # per-binary flag allowlist, enforced AFTER an allow matches:
  kubectl:                        # an allowed verb carrying any flag not listed here is DENIED
    - --namespace                 # (__flag_not_allowed__). Note --watch is deliberately absent.
    - --all-namespaces
    - --output
    # ...

rules:
  - id: kubectl-read-verbs
    match:
      argv0: kubectl
      verb: {in: [get, describe, logs, top, events, explain, api-resources,
                  api-versions, cluster-info, version, auth]}
    effect: allow
    channel: ro                   # selects the read-only credential; ro can never reach rw creds
    environments: [staging, prod]
```

### Matchers

| Matcher | Matches |
|---|---|
| `argv0: kubectl` / `argv0: {in: [...]}` | the binary |
| `verb: {eq: apply}` / `verb: {in: [...]}` | the parsed verb |
| `flags_any: ["--kubeconfig", ...]` | any of these flags present (post-canonicalization) |
| `flags_absent: ["--dry-run"]` | none of these flags present |
| `flag_value_not_in: {"--context": "${targets.kubernetes.allowed_contexts}"}` | a flag whose value is outside a config-interpolated allowlist |
| `resource_any: [secret, secrets]` | resource tokens — splits comma lists (`po,secrets`) and matches the prefix before `/` (`secret/foo`) |
| `first_positional: {in: [...]}` | the token right after the verb (pins e.g. `aws <service> <action>` actions) |
| `tool_name: task` | non-`run_command` tools |
| `subagent_type_not_in: [log-summarizer]` | `task` targets outside the allowlist (missing/malformed ⇒ match ⇒ deny) |

### Effects

| Effect | Behavior |
|---|---|
| `allow` | execute; the rule's `channel` selects the credential |
| `deny` | error ToolMessage with rule id + reason + hint |
| `rewrite` | mutate argv (e.g. inject `--dry-run=server`), then re-run parse→decide **exactly once**; the second pass must land on plain allow, else deny (`__rewrite_diverged__`) — no rewrite loops, no rewrite-into-denied |
| `escalate` | suspend the run via `interrupt()` for human approve / edit / reject; an approver's `edit` re-enters the full pipeline |
| `hook` | run a registered `@policy_hook` async function under a 2 s timeout; exception or timeout ⇒ deny |

### Fixed evaluation semantics (not configurable)

1. Collect **all** matching rules, order-independent.
2. Precedence: **deny > escalate > hook-result > rewrite > allow**.
3. No match → deny (`__default_deny__`).
4. An allowed verb carrying a flag outside the pack's `flags_allowed` → deny (`__flag_not_allowed__`).
5. Environment overlays (`envs/*.yaml`) may only **add deny/escalate rules or lower ceilings** —
   the loader rejects anything else.
6. The winning allow's `channel` selects the credential; `ro` calls can never reach `rw`
   credentials (engine invariant).

## The layers on disk

```
config/policy/
├── base.yaml            # global denies only — no tool_family, no allows
├── packs/               # allows, one file per tool family
│   ├── kubectl-read.yaml    kubectl-mutate.yaml    helm-read.yaml
│   ├── gh-read.yaml         gh-write.yaml
│   ├── aws-read.yaml        aws-write.yaml
│   ├── gcloud-read.yaml     gcloud-write.yaml
│   ├── az-read.yaml         az-write.yaml
│   └── ssh.yaml
└── envs/
    ├── staging.yaml     # may only ADD denies/escalations or LOWER ceilings
    └── prod.yaml
```

### What `base.yaml` denies, and why

- **Interpreters / exec-wrappers / net tools** (`bash`, `python3`, `awk`, `sed`, `xargs`, `find`,
  `env`, `curl`, `ssh`, `sudo`, …): would re-open the arbitrary-exec surface the argv-only design
  deletes. Redundant with default-deny — kept explicit for audit clarity.
- **Credential/identity overrides**: `kubectl --kubeconfig/--token/--server/--as`,
  `helm --kube-*`, `gh --hostname`, `aws --endpoint-url`,
  `gcloud --account/--impersonate-service-account/--configuration`, `az --subscription`.
  Credentials are pinned by the executor env; the model may never retarget identity or endpoint.
  (Region/project selection is *not* identity — `aws --region`, `gcloud --project` stay allowed.)
- **Secret-material reads**, even though they are "reads": `kubectl get/describe secrets`,
  `aws get-secret-value` / KMS `decrypt` / SSM `--with-decryption` / session-token and
  registry-credential actions, `gcloud secrets versions access` / `auth print-*-token` /
  SA `keys`, `az … secret|keys|credential`. These are the compensating control **on top of** the
  credential's own server-side IAM/RBAC denies, not a substitute for them.
- **`kubectl --context` outside `targets.kubernetes.allowed_contexts`** — with the generated
  kubeconfig (which contains only allowed contexts) as the backstop when `--context` is omitted.
- **Subagents and compaction**: every `task` target except the named `log-summarizer`;
  `compact_conversation`; and the deepagents built-in shell `execute` tool.

## Code hooks

For decisions that need *state*, not just argv shape, packs can invoke registered hooks
(`src/opendevops/policy/hooks.py`, `builtin_hooks.py`). The flagship: **dry-run-before-apply** —

1. a `rewrite` rule injects `--dry-run=server` into any `kubectl apply` lacking it;
2. a `hook` rule allows a *real* apply only if graph state records a successful server dry-run for
   the **same staged-manifest sha256** within this run — otherwise deny with a hint.

The rewrite alone would be bypassable by an explicit `--dry-run=none` first attempt; the hook is
the enforcement. Hooks run under `asyncio.wait_for(..., 2.0)`; timeout or exception ⇒ deny.

Cloud write packs (`aws-write` / `gcloud-write` / `az-write`) use a hybrid: curated scale/update
actions **allow** on `channel: rw` when `--dry-run` is present, and **escalate** when it is absent
(escalate > allow). Production non-dry-run rw still goes through the typed capability grant
(`aws_deploy` / `gcp_deploy` / `azure_deploy`).

## Loader lints

`YamlRuleEngine.load()` (`policy/loader.py`) hard-fails the boot on: schema violations, duplicate
rule ids, an env overlay containing allows/rewrites, an allow rule whose pack maps to no configured
credential (**credential coverage** — an allow can never outrun its credentials), any inventoried
tool named by no rule and not listed under `acknowledged_default_deny:`, and unreachable rules.
`policy_version = sha256(sorted file contents)` is stamped on every decision and audit event.

## Writing a new pack

1. Create `config/policy/packs/<family>-<ro|rw>.yaml` with `tool_family`, `flags_allowed`, and
   allow rules that name a `channel` and `environments`.
2. Add credential/identity-override denies for the new binary to `base.yaml` (every binary that can
   retarget gets the same class of denies).
3. Configure the credential in `config/config.yaml` (`targets.<family>...`) — env var **names**,
   never values. Without it the pack refuses to boot.
4. Provision the credential itself minimally scoped (read-only role with explicit secret-read
   Denies; see [security model](security-model.md)).
5. Add deny cases to the bypass corpus (`tests/unit/policy/test_corpus*.py`): identity overrides,
   secret reads, flag smuggling, and the family's own sharp edges.

## Testing

The **bypass corpus** (`tests/unit/policy/test_corpus*.py`) is CI-blocking: an argv-world
adaptation of the shell-bypass taxonomy where every case asserts *deny with the expected rule id* —
`["bash","-c",…]`, `["env","KUBECONFIG=/x","kubectl",…]`, `["kubectl","-s","https://attacker",…]`
(short-alias canonicalization), `["kubectl","get","po,secrets"]` (comma/prefix resources), flag
smuggling past `flags_allowed`, `task`/`compact_conversation`, empty argv, non-string argv, and
more. Invariants tested directly: pipeline exception ⇒ deny; unknown tool ⇒ deny.

Run just the policy suite:

```sh
uv run pytest tests/unit/policy -q
```
