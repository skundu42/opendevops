# Security model

The design assumes the model **will** eventually emit a harmful or manipulated command — via
hallucination, prompt injection from tool output, or plain error — and asks: *what is the blast
radius when every softer layer fails?*

## The layers, outermost first

| Layer | Control | Fails how |
|---|---|---|
| 1. Credentials (the boundary) | per-(family, env, channel) minimally-scoped credentials, provisioned server-side | this is the layer that must hold |
| 2. No shell | argv-only execution, `shell=False`, no interpreters | removes the surface, nothing to fail |
| 3. Constructed env | child env built from scratch; agent secrets physically absent | nothing to leak |
| 4. Policy engine | default-deny, fail-closed, layered YAML + hooks | velocity/UX layer, assumed bypassable |
| 5. Output scrubbing | token patterns + entropy scan → `***` before model/FS/audit | backstop, not the control |
| 6. Audit | hash chains plus an independently protected WORM/SIEM sink | detection, not prevention |

The invariant that anchors everything: **a capability grant never creates authority**. It can only
unlock an `rw` path already constrained by a reviewed policy rule, parsed target allowlist and
minimally scoped credential. The default cloud credentials remain read-only and secrets-denied.
Production Kubernetes writes require a separate `rw` identity whose namespace/resource scope is
the final boundary even if the model, approval workflow, and policy layer all fail.

## Credentials: the real boundary

- Every allow rule names a **channel** (`ro` | `rw`); each `(tool-family, environment, channel)`
  triple maps to exactly one credential. A `kubectl` call can never receive `GH_TOKEN`; an `ro`
  call can never reach `rw` credentials (engine invariant + loader lint).
- Credentials are provisioned **before** the policy pack referencing them ships, minimally scoped:
  - k8s ro: ServiceAccount + `view` ClusterRoleBinding; verify per cluster that
    `kubectl auth can-i get secrets --as=system:serviceaccount:opendevops:sa-agent-view` → `no`.
  - k8s rw: namespace-scoped Role enumerating exact verbs/resources (deployments, replicasets,
    rollouts, scale, configmaps; **no** secrets/RBAC/CRD writes), with a separate credential for
    each enabled environment.
  - cloud ro: roles with explicit **Denies** on `secretsmanager:GetSecretValue`,
    `ssm:GetParameter*` (decrypt), `kms:Decrypt` — the policy-layer secret-read denies are the
    compensating control on top, never a substitute.
  - GitHub: fine-grained PATs; the write PAT is distinct from the read PAT and scoped to the
    `targets.github.write_repos` allowlist (empty allowlist ⇒ every write default-denies).
- The model can never *choose* a credential: identity/endpoint flags (`--kubeconfig`, `--token`,
  `--as`, `--server`, `--hostname`, `--endpoint-url`, `--impersonate-service-account`,
  `--subscription`, …) are hard-denied, and the executor env contains exactly one credential set.

## Execution hygiene

`run_command` subprocesses (`executor.mode=local`) run with a **constructed, never inherited**
environment: `PATH`, `HOME`, output-hygiene vars (`NO_COLOR`, `PAGER=cat`, `AWS_PAGER=""`,
`GIT_TERMINAL_PROMPT=0`, …) plus the one selected credential. `ANTHROPIC_API_KEY`, the audit path,
and everything else in the agent's own environment are physically absent from every child.
`stdin` is `/dev/null`; timeouts kill the whole process group.

`ssh_run` is structured, not shell: an allowlisted host + remote argv; user, key, port, and a
pinned `known_hosts` file come from config (`targets.ssh`). Host-key verification is always on — a
missing `known_hosts_path` makes the tool refuse rather than disable checking.

## Secrets

- **Into the agent**: config files carry env var **names**, never values
  ([configuration](configuration.md#the-name-not-value-convention)). A `{{secret:NAME}}` reference
  must be a standalone argv entry; it declares `NAME` in the subprocess environment and is removed
  before execution. Embedded expansion is rejected because commands run without a shell.
- **Out of the infrastructure**: secret-material reads are denied at the policy layer *and* by the
  credential's own RBAC/IAM ([policy](policy.md#what-baseyaml-denies-and-why)).
- **Through tool output**: a scrubber runs on every `run_command` output **before** it reaches the
  model, the virtual FS spill file, or the audit excerpt — known token formats (AWS `AKIA…`,
  GitHub `ghp_`/`github_pat_`/`gho_`…, Slack `xox…`, JWTs, PEM blocks, Anthropic/OpenAI keys) plus
  a high-entropy scan, replaced with `***`. Full-output sha256 is computed for audit regardless.

## The executor split (`mode=remote`)

For any mutating credential broader than a staging-namespace Role, execution moves out of the
agent process entirely into a standalone **executor service**: one Deployment per
`(environment, channel)`, gVisor runtime, non-root, read-only rootfs, all capabilities dropped,
tmpfs workdir, default-deny NetworkPolicies with IMDS blocked.

The agent then holds **no infra credentials** — only an ed25519 **private signing key**. Every
execution request carries a **decision token**: a signature over the argv hash, staged-file plan,
tool family, channel, run id, tool-call id, and a 120 s expiry. The service holds only the
**public** key and rejects unsigned, expired, or hash-mismatched requests — so no code path
reaches execution without passing the policy engine.

> **Status:** production-capable with a complete `executor.urls` map. `mode=remote` is opt-in.
> The token binds `environment` and `channel` (plus `host` for `ssh_run`); each service pod
> asserts `OPENDEVOPS_EXECUTOR_ENV` / `OPENDEVOPS_EXECUTOR_CHANNEL` and rejects mismatches with
> 403. The agent routes per `(env, channel)` and does not hold infra or SSH credentials. See
> `ops/executor/README.md`. `mode=local` remains the default single-process path.

## Structural guards

- **Blast-radius rule (hard)**: the service stack must **never** run on a Kubernetes cluster the
  agent itself manages — a compromised run could otherwise reach its own control plane.
- **Boot-time tool inventory**: the compiled graph's bound tools must exactly match the reviewed
  set; a dependency bump that binds a new tool is a boot failure, not a silent new capability.
- **Subagent containment**: a deepagents subagent would carry none of the policy/budget middleware,
  so `task` is denied for every target except the single named haiku `log-summarizer` (whose
  usage is metered through the gateway callback).
- **SDK firewall**: only `gateway/server.py` may import `langgraph_sdk`; the executor service image
  must never install it.
- **Interrupt-replay guards**: the per-`tool_call_id` execution cache + disabled parallel tool
  calls ensure an approval resume can never re-execute an already-executed sibling call
  ([architecture](architecture.md#interrupt-replay-safety)).
- **Dangerous-action loop guards**: each `rw` execution transactionally consumes an expiring
  capability grant and enforces global/per-grant totals, per-run totals, identical-action limits,
  failure stop-loss and cooldown. Concurrent workers share the same SQLite transaction boundary.
- **Fail-closed everywhere**: policy exceptions deny; unknown tools deny; hook timeouts deny; a
  daily-counter outage refuses new runs; unset webhook secrets return 503 (never "auth
  disabled"); unpriced models, uncovered packs, and empty context allowlists refuse to boot.

## Escalation and humans

Rules with `effect: escalate` suspend the run for human approve / edit / reject — in the CLI
inline, in Slack as Block Kit buttons, and for non-interactive runs an **escalation-timeout
sweeper** auto-rejects after the rule's `timeout_s` with an audited `approver="__timeout__"`
resolution ([interfaces](interfaces.md)). Every resolution records the approver in the audit
chain.

Production browser control uses OpenID Connect authorization code flow with state, nonce and PKCE.
The application validates ID-token signature, exact issuer, audience, expiry, issued-at and nonce.
It maps provider claims to non-hierarchical `viewer`, `operator`, `approver` and `admin` roles.
Sessions and login transactions are server-side; the browser has only an opaque, revocable,
short-lived cookie and every state-changing route requires CSRF.

Dashboard chat is limited to `operator` and `admin`. Every thread read, turn and cancellation
requires exact issuer/subject ownership; the gateway receives that same stable principal for audit
and budget attribution. The transcript store contains user prompts, assistant responses and only
sanitized lifecycle labels. It never receives raw tool arguments, tool output or escalation
payloads. This store is operational data—not a hash-chain authenticity record—so retention,
backup access and deletion policy must treat it as potentially sensitive.

Every content-free control event records the stable OIDC issuer + subject. The gateways also refuse
production approve/edit decisions when that identity matches the run requester; the grant ledger
refuses requester self-approval before a separate administrator activation. Static-token dashboard
auth is an explicit local-development mode, not a deployed identity system.

## Detection

The audit trail ([audit](audit.md)) is hash-chained per run, written by the middleware itself, and
excluded from every path the agent can reach (not in the executor env, not in the virtual FS; the
durable sink's bucket/table policy denies every agent role). Prometheus alerting includes a
policy-denial-spike rule — repeated denials are a bypass-probing signal, not noise.

## Known limits, stated plainly

- Policy is **not** the boundary; treat every pack as bypassable when reasoning about risk.
- The scrubber is pattern-based; an exotic secret format can slip it. The hard control is
  server-side denial of secret reads.
- `mode=remote` requires a complete `executor.urls` map and pod identity env vars; production
  currently often still uses the local executor with carefully scoped credentials.
- The control ledger and dashboard chat transcript default to SQLite. Set
  `control_plane.backend: postgres` (with `database_url_env`) for multi-replica service mode.
- AWS, GCP and Azure packs remain read-only. A deploy capability type exists in change control,
  but no grant can override the absent/denied mutation rules or create cloud `rw` credentials.
- Grant target strings record the reviewed change scope; executable target enforcement remains in
  the policy pack's parsed allowlists and credential scope.
