# Deployment

Three tiers, in order of infrastructure required:

| Tier | What runs | When |
|---|---|---|
| CLI (local) | everything in one process, sqlite state | [getting started](getting-started.md) — the default |
| Service mode | self-hosted LangGraph Server stack via docker-compose | HTTP API, webhooks, Slack, scheduler |
| Executor service | standalone credential-holding execution service on k8s | **experimental** — see gates below |

> **Blast-radius rule (hard):** the service stack must **not** run on a Kubernetes cluster the
> agent itself manages. Use a dedicated ops VM or a separate ops cluster — otherwise a
> compromised or buggy run could reach its own control plane.

## Service mode (docker-compose)

The stack (`docker-compose.yml`):

| Service | Role |
|---|---|
| `langgraph-server` | the agent graph + webhook app, built **from this repo**; durable run queue, exactly-once, SSE streaming |
| `postgres` | the server's queue + checkpoint store |
| `redis` | the server's task queue **and** the shared `RedisDailyCounter` |
| `caddy` | the only ingress — API bearer gate plus pass-through to application-authenticated dashboard routes on `:8123`; terminate TLS upstream in production |
| `vector` | tails per-run audit chains, merges them into the durable spool |
| `prometheus` + `grafana` | metrics, alert rules, the provisioned ops dashboard |
| `agent-state` volume | capability-grant/control-event ledger; back it up with the audit store |

### Bring-up

```sh
# 1. build the server image (bakes the graph from langgraph.json)
uv run langgraph build -t opendevops-langgraph:latest

# 2. secrets — in the environment or a .env next to docker-compose.yml:
#    GATEWAY_TOKEN, ANTHROPIC_API_KEY, LANGSMITH_API_KEY,
#    POSTGRES_PASSWORD, GRAFANA_ADMIN_PASSWORD
#    Local development: DASHBOARD_TOKEN
#    Production OIDC: OIDC_CLIENT_ID, OIDC_CLIENT_SECRET

# 3. switch the daily counter to the shared backend (config/budgets.yaml):
#    daily: {backend: redis, redis_url: redis://redis:6379/0}

# 4. validate, start, smoke-test
docker compose config -q
docker compose up -d
curl -sf http://localhost:8123/healthz
curl -s -H "Authorization: Bearer $GATEWAY_TOKEN" \
  http://localhost:8123/assistants/search -X POST -d '{}'
# The shipped local config signs in with DASHBOARD_TOKEN.
```

The server container publishes no host port — Caddy on `:8123` is the sole ingress. Keep the
gateway bearer on the machine-to-machine LangGraph API; the dashboard has its own OIDC session
boundary.

The three `/webhooks/*` application routes bypass Caddy's gateway bearer because external senders
cannot supply it; the app still requires its configured HMAC or route-specific bearer credential.
The `/dashboard*` routes also bypass the API bearer at Caddy because the application validates
OIDC and manages opaque server-side sessions. All remaining server API and metrics routes stay
gateway-token protected.

### Operator dashboard

`/dashboard` merges verified audit chains with live run/queue/worker/approval telemetry and exposes
RBAC-controlled cancellation, approval resolution, capability-grant configuration and session
revocation. The run-detail API contains correlation, timing, policy and cost metadata but never
prompts, responses, command arguments, output, or credential values. Updates use SSE.

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

> **Status: EXPERIMENTAL — not production-deployable as shipped.** `executor.mode=local` is the
> reviewed production path. Read this section as the roadmap it documents.

`ops/executor/` contains hardened manifests for the standalone execution service: an isolated
namespace (Pod Security `restricted`), one Deployment per `(environment, channel)` — each holding
exactly one credential set — with gVisor, non-root, read-only rootfs, dropped capabilities, tmpfs
workdir, and default-deny NetworkPolicies (only the agent may reach `POST /execute`; egress
allowlisted with IMDS blocked). Every manifest property is asserted by
`tests/unit/test_executor_manifests.py` without a live cluster.

On this path the agent holds only the ed25519 **private** signing key; each request carries a
signed decision token ([security model](security-model.md#the-executor-split-moderemote)). The
service holds the **public** key, its family/channel credential env, and `{{secret:NAME}}`
values — sourced from a Secret/CSI driver, never baked into images. The image installs the
package + `fastapi` only — **never** the `server` extra (`langgraph-sdk` must not exist there;
SDK firewall).

**Pre-deployment gates** (all must close before any `mode=remote` production run — full detail in
`ops/executor/README.md`):

1. the signed token must bind the **environment** alongside the channel;
2. each service pod must assert its own `(environment, channel)` identity and 403 mismatched
   tokens;
3. the agent must route per-(env,channel) — a routing map, not today's single `executor.url`;
4. `ssh_run` must route through the service too (or the deployment explicitly accepts that the
   agent keeps holding the SSH key).

Until then, a mis-routed `staging-rw` token would verify and run on the `prod-rw` pod — which is
exactly the class of failure the split exists to prevent. Keep `mode: local`.

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
