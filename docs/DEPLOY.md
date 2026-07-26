# Service-mode deployment runbook

The stack in `docker-compose.yml` turns the agent into an HTTP service: a self-hosted **LangGraph
Server** (Postgres queue + checkpointer, Redis) fronted by **Caddy** (bearer-token gate), with the
audit trail shipped by **Vector** to a durable sink and **Prometheus + Grafana** for operability.

This is a stub — enough to stand the stack up and know the decisions still owed to the compliance /
platform owners. It is not a hardened production guide.

> **Blast-radius rule (hard):** this stack MUST NOT run on a Kubernetes cluster the agent itself
> manages (see `guides/security-model.md`). Run it on a dedicated ops VM or a separate ops
> cluster. Otherwise a compromised or buggy run could reach its own control plane.

## 1. Build the server image

The `langgraph-server` service runs an image built from this repo (it bakes the graph from
`langgraph.json`); everything else pulls upstream images.

```sh
uv run langgraph build -t opendevops-langgraph:latest
```

## 2. Secrets (environment / .env next to docker-compose.yml)

| Variable | Purpose |
|---|---|
| `GATEWAY_TOKEN` | the static bearer token Caddy requires (and gateways/Alertmanager present) |
| `DASHBOARD_TOKEN` | operator sign-in token exchanged for a short-lived signed dashboard session |
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
# Open http://localhost:8123/dashboard and sign in with DASHBOARD_TOKEN.
```

The API is reachable only through Caddy on `:8123` (matching `config.yaml server.url`); the server
container publishes no host port. Upgrade path for auth: front Caddy with oauth2-proxy (OIDC/SSO) —
see `ops/caddy/Caddyfile`.

The dashboard routes bypass Caddy's API bearer and enforce authentication in the application.
Login exchanges `DASHBOARD_TOKEN` for an HMAC-signed, time-limited `HttpOnly`,
`SameSite=Strict` cookie scoped to `/dashboard`; missing secret configuration returns 503. The
shipped `dashboard_cookie_secure: false` supports this local HTTP smoke test only. Set
`server.dashboard_cookie_secure: true` whenever TLS is enabled, and add OIDC/SSO plus network
restriction for a shared production installation.

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

The application dashboard at `:8123/dashboard` complements Grafana with a run-level,
audit-derived view: recent outcomes and cost, integrity state, policy decisions, sanitized event
timeline, and integration posture. It scans a bounded audit window and does not return command
arguments, subprocess output, or credential values.
