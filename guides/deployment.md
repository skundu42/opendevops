# Deployment

Three tiers, in order of infrastructure required:

| Tier | What runs | When |
|---|---|---|
| CLI (local) | everything in one process, sqlite state | [getting started](getting-started.md) — the default |
| Service mode | self-hosted LangGraph Server stack via docker-compose | HTTP API, webhooks, Slack, scheduler |
| Executor service | standalone credential-holding execution service on k8s | production-capable with full `executor.urls` |

> **Blast-radius rule (hard):** the service stack must **not** run on a Kubernetes cluster the
> agent itself manages. Use a dedicated ops VM or a separate ops cluster — otherwise a
> compromised or buggy run could reach its own control plane.

## Service mode (docker-compose)

The stack (`docker-compose.yml`):

| Service | Role |
|---|---|
| `langgraph-server` | the prebuilt agent graph + webhook app; durable run queue, exactly-once, SSE streaming |
| `postgres` | the server's queue + checkpoint store |
| `redis` | the server's task queue **and** the shared `RedisDailyCounter` |
| `caddy` | the only ingress — API bearer gate plus pass-through to application-authenticated dashboard routes on `:8123`; terminate TLS upstream in production |
| `vector` | tails per-run audit chains, merges them into the durable spool |
| `prometheus` + `grafana` | metrics, alert rules, the provisioned ops dashboard |
| `agent-state` volume | capability/control ledger plus private chat transcripts; encrypt and back it up |

### Bring-up

```sh
# 1. download the versioned, source-free deployment bundle
curl -fLO \
  https://github.com/skundu42/opendevops/releases/download/v0.1.2/opendevops-deploy-0.1.2.tar.gz
tar -xzf opendevops-deploy-0.1.2.tar.gz
cd opendevops-0.1.2

# 2. secrets — copy the template, then fill every required blank:
#    GATEWAY_TOKEN, ANTHROPIC_API_KEY, LANGSMITH_API_KEY,
#    POSTGRES_PASSWORD, GRAFANA_ADMIN_PASSWORD
#    Local development: DASHBOARD_TOKEN
#    Production OIDC: OIDC_CLIENT_ID, OIDC_CLIENT_SECRET
cp .env.example .env

# 3. validate, pull, start, smoke-test
docker compose config -q
docker compose pull
docker compose up -d
curl -sf http://localhost:8123/healthz
curl -s -H "Authorization: Bearer $GATEWAY_TOKEN" \
  http://localhost:8123/assistants/search -X POST -d '{}'
# The shipped local config signs in with DASHBOARD_TOKEN.
```

The bundle pins `ghcr.io/skundu42/opendevops:0.1.2`, supports `linux/amd64` and `linux/arm64`, and
preconfigures the daily counter for the Compose Redis service. Verify `SHA256SUMS` from the same
GitHub release before running it. Contributors can build the checked-in `Dockerfile` locally and
override `LANGGRAPH_IMAGE`; release consumers do not need Python, uv, Node.js, or the source tree.
The image does not bundle every infrastructure vendor CLI. Add only the `kubectl`, `helm`, `gh`,
`aws`, `gcloud`, or `az` clients for the policy families the deployment enables, preferably in the
credential-isolated executor image. Missing executables fail closed instead of silently degrading.

The server container publishes no host port — Caddy on `:8123` is the sole ingress. Keep the
gateway bearer on the machine-to-machine LangGraph API; the dashboard has its own OIDC session
boundary.

The three `/webhooks/*` application routes bypass Caddy's gateway bearer because external senders
cannot supply it; the app still requires its configured HMAC or route-specific bearer credential.
The `/dashboard*` routes also bypass the API bearer at Caddy because the application validates
OIDC and manages opaque server-side sessions. All remaining server API and metrics routes stay
gateway-token protected.

### Operator dashboard

`/dashboard` provides identity-scoped operator chat, merges verified audit chains with live
run/queue/worker/approval telemetry, and exposes RBAC-controlled cancellation, approval resolution,
capability-grant configuration and session revocation. Chat turns use the same gateway and stream
assistant/sanitized lifecycle events over SSE; raw tool arguments and output never reach the chat
transcript. The separate run-detail API contains correlation, timing, policy and cost metadata but
never prompts, responses, command arguments, output, or credential values.

Chat transcripts live in `control_plane.database` on the `agent-state` volume, are private to the
exact issuer/subject and default to 30-day idle retention. Treat the volume as potentially
sensitive: encrypt it at rest, restrict backup access, align
`server.dashboard_chat_retention_days` with policy, and restore it with the control ledger.

The shipped configuration uses `static` authentication and
`server.dashboard_cookie_secure: false` for a localhost smoke test only. A deployed configuration
must use `dashboard_auth_mode: oidc`, exact issuer and redirect URI, explicit role mappings,
`dashboard_session_backend: redis`, `dashboard_session_redis_url: redis://redis:6379/2`, a short
session lifetime, and `dashboard_cookie_secure: true` behind HTTPS. Set `OIDC_CLIENT_ID` and
`OIDC_CLIENT_SECRET` in the server environment. State, nonce and PKCE transactions are one-time and
server-side; ID tokens are signature/issuer/audience/time/nonce validated. Browser cookies are
opaque `HttpOnly`, `SameSite=Strict` handles, and administrators can immediately revoke every
session for an issuer/subject.

Map provider groups to separate `operator` and `approver` roles. Production rejects an approval or
edited approval from the same issuer/subject that requested the run or grant. `admin` can perform
both duties and should be a tightly controlled break-glass role.

### Two URLs, one server

`config.yaml server.url` (`:8123`) is the **external** URL every outside consumer uses, through
Caddy's bearer gate. But the webhook app runs *inside* the server container, and its own gateway
must reach the server API on the container's loopback (`:8000`) — nothing listens on `:8123`
in-process. `OPENDEVOPS_SELF_URL` (set on the service, default `http://localhost:8000`) overrides
`server.url` for that in-process gateway only. Without it, webhooks would return 202 but their
background runs would fail at connect — fail-safe, but the alert→RCA flow would not complete.

### Checkpointing note

Never configure a local checkpointer on this path — the platform injects Postgres checkpointing.
(`LocalGateway`'s sqlite saver is for the CLI tier only; the code already respects this split.)

### Audit shipping

Vector merges `audit/*.jsonl` into the spool volume by default. Pick the real durable sink with
the compliance owner (S3 + Object Lock, or Loki/SIEM — blocks are ready to uncomment in
`ops/vector/vector.yaml`), with the bucket/table policy denying every agent role. Verify shipped
chain structure with `uv run opendevops audit verify --dir <spool>` ([audit](audit.md#verifying)).

### Licensing quota probe

The self-hosted server runs under a LangSmith license with a node-execution quota. Project your
consumption before committing:

```sh
uv run python -m ops.quota_probe probe --url http://localhost:8123 --monthly-quota <quota>
```

A projection **>60% of quota** is the documented trigger to license up **or** switch to the
FastAPI-embedded gateway fallback — the `ServerGateway` seam exists precisely so that fallback is
a bounded change.

### Hygiene

```sh
uv run python -m ops.maintenance prune-threads --url http://localhost:8123 --older-than-days 30
uv run python -m ops.maintenance spend-report --json
uv run python -m ops.maintenance pg-dump --database-uri "$DATABASE_URI" --out-path /backup/db.dump
```

`prune-threads` never deletes a busy or pending-escalation thread. In production these run under
the [scheduler](interfaces.md#scheduler).

### Monitoring

Grafana (`:3000`, admin password from `GRAFANA_ADMIN_PASSWORD`) ships with the
"opendevops — service ops" dashboard: runs, denials, daily spend, shipper lag. Prometheus alert
rules (`ops/prometheus/alerts.yml`) cover policy-denial spikes (bypass probing), daily spend
>80%, scheduler silence >1.5× period, and audit-shipper lag. Some series are pre-provisioned for
components that ship later and simply don't fire until then (see the header comment in
`alerts.yml`).

The authenticated application dashboard at `:8123/dashboard` is the run-level companion. It
publishes the defined run-success, queue-latency, policy-latency, executor-error, audit-lag and
budget-utilization SLIs. Set `OTEL_EXPORTER_OTLP_ENDPOINT` to export OTLP/HTTP traces and metrics
for gateway, webhook, scheduler, model, policy and executor operations; run, thread, tool-call,
model-call and application trace identifiers are attached where available.

## Executor service (remote mode)

> **Status:** production-capable when `executor.mode=remote` and `executor.urls` covers
> `staging`/`prod` × `ro`/`rw`. `executor.mode=local` remains the default single-process path.

`ops/executor/` contains hardened manifests for the standalone execution service: an isolated
namespace (Pod Security `restricted`), one Deployment per `(environment, channel)` — each holding
exactly one credential set — with gVisor, non-root, read-only rootfs, dropped capabilities, tmpfs
workdir, and default-deny NetworkPolicies (only the agent may reach `POST /execute`; egress
allowlisted with IMDS blocked). Every manifest property is asserted by
`tests/unit/test_executor_manifests.py` without a live cluster.

On this path the agent holds only the ed25519 **private** signing key; each request carries a
signed decision token binding `environment`, `channel`, and (for `ssh_run`) `host`
([security model](security-model.md#the-executor-split-moderemote)). The service holds the
**public** key, asserts `OPENDEVOPS_EXECUTOR_ENV` / `OPENDEVOPS_EXECUTOR_CHANNEL`, holds its
family/channel credential env (and the SSH key on `ro` pods when SSH is enabled), and
`{{secret:NAME}}` values — sourced from a Secret/CSI driver, never baked into images. The image
installs the package + `fastapi` (+ `ssh` extra when using `ssh_run`) — **never** the `server`
extra (`langgraph-sdk` must not exist there; SDK firewall).

**Gates (closed):**

1. the signed token binds **environment** (and `host` for ssh) alongside the channel;
2. each service pod asserts its own `(environment, channel)` identity and 403s mismatched tokens;
3. the agent routes via `executor.urls[environment][channel]`;
4. `ssh_run` routes through the same `POST /execute` path (`tool_family=ssh`).

**Multi-replica / transport:** set `executor.spent_token_backend: redis` before scaling any
executor Deployment above one replica. Optional `executor.tls` configures agent mTLS; optional
`executor.signing_keys` selects per-(env, channel) private keys (each pod's `verify_key_env`
holds the matching public key).

## Standing pre-go-live gates (all tiers)

Environment/ops work owed before the first live run against real infrastructure, independent of
code:

- fill `targets.kubernetes.allowed_contexts` (empty fail-closed boot gate) and generate the
  scoped kubeconfig(s);
- run the RBAC apply + secrets-denied verification against **every** configured cluster;
- scoped-role IAM docs before enabling any cloud credentials; e2e sshd tier before live `ssh_run`;
- keep requester, approver and administrator OIDC groups operationally separate; scope the
  `gh-write` PAT before enabling it;
- back up and monitor the `agent-state` volume; a multi-replica deployment currently requires a
  shared single-writer volume for the SQLite control ledger;
- choose the audit durable sink + retention with the compliance owner;
- the blast-radius rule: stack placement off any managed cluster.
