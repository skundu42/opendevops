# Service-mode deployment runbook

The stack in `docker-compose.yml` turns the agent into an HTTP service: a self-hosted **LangGraph
Server** (Postgres queue + checkpointer, Redis) fronted by **Caddy** (bearer-token gate), with the
audit trail shipped by **Vector** to a durable sink and **Prometheus + Grafana** for operability.

This is a stub — enough to stand the stack up and know the decisions still owed to the compliance /
platform owners. It is not a hardened production guide.

> **Blast-radius rule (hard):** this stack MUST NOT run on a Kubernetes cluster the agent itself
> manages (see `guides/security-model.md`). Run it on a dedicated ops VM or a separate ops
> cluster. Otherwise a compromised or buggy run could reach its own control plane.

## 1. Download a release

The `langgraph-server` service pulls the versioned image that already contains the graph,
application, dependencies, and compiled TypeScript dashboard.

```sh
curl -fLO \
  https://github.com/skundu42/opendevops/releases/download/v0.1.0/opendevops-deploy-0.1.0.tar.gz
tar -xzf opendevops-deploy-0.1.0.tar.gz
cd opendevops-0.1.0
cp .env.example .env
```

The bundle pins `ghcr.io/skundu42/opendevops:0.1.0` and preconfigures its shared Redis daily
counter. Check the release `SHA256SUMS` before starting it. Building from source remains available
to contributors through the checked-in `Dockerfile`, but is not required for deployment.
The application image deliberately omits infrastructure vendor CLIs. Add only the clients for
enabled policy families to a derived runtime or credential-isolated executor image; the agent
fails closed when an expected executable is absent.

## 2. Secrets (environment / .env next to docker-compose.yml)

| Variable | Purpose |
|---|---|
| `GATEWAY_TOKEN` | the static bearer token Caddy requires (and gateways/Alertmanager present) |
| `DASHBOARD_TOKEN` | local-development dashboard login only; leave unset in OIDC deployments |
| `OIDC_CLIENT_ID` | production dashboard OIDC client identifier |
| `OIDC_CLIENT_SECRET` | production dashboard OIDC client secret |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | optional OTLP/HTTP collector endpoint for traces and metrics |
| `LANGSMITH_API_KEY` | LangGraph Server license / tracing key (pass-through) |
| `ANTHROPIC_API_KEY` | model key for live runs |
| `POSTGRES_PASSWORD` | Postgres superuser password |
| `GRAFANA_ADMIN_PASSWORD` | Grafana admin login |

Every webhook secret in `config/config.yaml` is a **name** of an env var, never a value — set the
named vars in the server's environment (see `config.yaml server:` and `webapp.py`).

## 3. Shared daily counter (RedisDailyCounter)

For service mode, flip the daily counter to the shared Redis backend so every Server worker
accumulates ONE daily envelope (and it survives a restart). In `config/budgets.yaml`:

```yaml
daily:
  global_usd: 50.00
  per_principal_usd: 25.00
  backend: redis
  redis_url: redis://redis:6379/0    # the compose stack's redis service (DB 0; the server uses DB 1)
```

The default (`backend: sqlite`) is correct for the single-process CLI / `langgraph dev` tier and is
what ships; only service mode needs `redis`. `budgets.daily.backend: redis` without `redis_url`
fails to boot (fail-closed).

## 4. Bring it up

```sh
docker compose -f docker-compose.yml config -q     # validate (no pull)
docker compose -f docker-compose.yml up -d
curl -sf http://localhost:8123/healthz             # liveness passes Caddy unauthenticated
curl -s -H "Authorization: Bearer $GATEWAY_TOKEN" http://localhost:8123/assistants/search -X POST -d '{}'
# The shipped local config signs in with DASHBOARD_TOKEN.
```

The API is reachable only through Caddy on `:8123` (matching `config.yaml server.url`); the server
container publishes no host port. The machine API keeps Caddy's bearer gate; dashboard identity is
validated by the application.

The dashboard routes bypass Caddy's API bearer and enforce authentication in the application.
The shipped `static` mode exchanges `DASHBOARD_TOKEN` for an opaque local-development session.
Production must configure `server.dashboard_auth_mode: oidc`, an exact issuer/redirect URI,
explicit group-to-role mappings, Redis sessions on `redis://redis:6379/2`, a short session lifetime
and `dashboard_cookie_secure: true` behind TLS. The authorization-code flow uses state, nonce and
PKCE; login succeeds only after signature, issuer, audience, time and nonce validation.

Keep `operator`, `approver` and `admin` provider groups separate. Production approve/edit actions
from the same issuer/subject as the requester are rejected, and grant activation is a separate
administrator transition. Sessions are server-side, immediately revocable, and protected by
session-bound CSRF on every mutation.

Configure a dedicated production write identity at
`targets.kubernetes.kubeconfig_rw_by_environment.prod`. The legacy `kubeconfig_rw` field is a
staging-only fallback and is deliberately refused for production.

**Two URLs, one server (in-container loopback vs external Caddy).** `config.yaml server.url`
(`:8123`) is the *external* URL — the address a human/CLI/second machine driving `ServerGateway`
from OUTSIDE uses, through Caddy's bearer gate. But the webhook app (`webapp.py`) runs *inside* the
`langgraph-server` container, so its own gateway must reach the server's API *directly* on the
container's loopback port (`8000`) — `:8123` is Caddy's host-published port on a **different**
container and nothing listens on it in-process. The webhook gateway is therefore pointed at
`OPENDEVOPS_SELF_URL` (default `http://localhost:8000`, set on the `langgraph-server` service),
which overrides `server.url` for that in-process gateway *only*; every external consumer still uses
`server.url`. This loopback path bypasses Caddy and its bearer, so it needs no API key. Without it,
an Alertmanager/GitHub webhook would return `202` but its background RCA run would fail at connect
(fail-safe — no bypass, no unaudited action — but the "Alertmanager webhook → RCA" flow would not
complete).

## 5. Audit shipping + durable sink

Vector tails the per-run chains (`/audit/*.jsonl`) and MERGES them, byte-for-byte, into a durable
sink. The **default** is a local spool volume (`/spool/audit-merged-<date>.jsonl`), whose store the
agent's own IAM/RBAC role cannot reach (see `guides/audit.md`). Choose the real durable target with the
compliance owner and uncomment the relevant block in `ops/vector/vector.yaml`:

- **S3 with Object Lock** (WORM retention), bucket policy denying every agent role; or
- **Loki / SIEM** forwarding (INSERT-only), labelled by `run_id`.

Verify shipped chain structure: `uv run opendevops audit verify --dir <spool>`. The command
auto-detects each `*.jsonl` file's shape — a Vector-merged day-file (`audit-merged-<date>.jsonl`,
carrying many interleaved runs) is **regrouped by `run_id`** and each run's subsequence verified as
an independent hash chain; a plain per-run `<run_id>.jsonl` file is verified as a single chain. The
same command therefore works on both a per-run audit dir and the spool. Regrouping is sound because
the spool preserves every line verbatim and never reorders lines *within* a run (each per-run source
file is single-writer and Vector ships in append order). A tampered, reordered, or dropped line in
any run's subsequence fails the file, naming the offending `run_id` and line.

The Compose `agent-state` volume holds the capability-grant/control-event ledger and private
dashboard chat transcripts. Encrypt it, restrict backup access, and back it up alongside the audit
store. Chat defaults to 30-day idle retention. The database is SQLite and therefore requires a
shared single-writer durable volume when the application has multiple replicas.

## 6. Licensing quota probe

Before committing to the licensed Server long-term, project monthly node-execution consumption:

```sh
uv run python -m ops.quota_probe probe \
  --url http://localhost:8123 --monthly-quota <your-verified-tier-quota>
```

A projection **> 60% of quota** is the documented trigger to either license up or execute the
FastAPI-embedded gateway fallback (bounded by the `ServerGateway` seam).

## 7. Hygiene jobs (`ops/maintenance.py`)

```sh
uv run python -m ops.maintenance prune-threads --url http://localhost:8123 --older-than-days 30
uv run python -m ops.maintenance spend-report --json
uv run python -m ops.maintenance pg-dump --database-uri "$DATABASE_URI" --out-path /backup/db.dump
```

`prune-threads` never deletes a `busy` or `interrupted` (pending-escalation) thread. In production
these run under the scheduler service (see `guides/interfaces.md`).

## 8. Monitoring

Grafana (`:3000`) is provisioned with the Prometheus datasource and the `opendevops — service ops`
dashboard (runs, denials, daily spend, shipper lag). Alert rules live in `ops/prometheus/alerts.yml`
Some series are **pre-provisioned** for the scheduler service / a spend exporter and simply do
not fire until those components run — see the header comment in `alerts.yml`.

The application dashboard at `:8123/dashboard` adds identity-scoped operator chat and complements
Grafana with live run, queue, worker, retry/cancellation and pending-approval state plus verified
audit truth. Chat returns user/assistant content only to the owning issuer/subject and never sends
raw tool arguments or output. The separate run detail correlates `run_id`, `thread_id`,
`tool_call_id`, model-call and trace identifiers and shows content-free timing/cost progression.
It scans a bounded audit window and does not return prompts, responses, command arguments,
subprocess output, or credential values.

Set `OTEL_EXPORTER_OTLP_ENDPOINT` to export OTLP/HTTP traces and metrics for gateway, webhook,
scheduler, model, policy and executor operations. The dashboard projects the run-success,
queue-latency, policy-latency, executor-error, audit-lag and budget-utilization SLIs. Updates are
delivered over SSE; the full audit window is only re-sent when its digest changes.
