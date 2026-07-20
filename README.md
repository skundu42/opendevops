# opendevops

Autonomous DevOps agent built on LangChain **deepagents**, operating under a policy
engine with hard budget controls and a tamper-evident audit trail.

See `PLAN.md` for the full design. This repository is at the **P0 scaffold** stage:
package skeleton, config loaders, CI, RBAC ops files, and an API-reality spike.

## Quickstart

```sh
uv sync --extra p2 --extra server --extra dev
uv run opendevops --help
uv run opendevops config check
uv run pytest
```

## Service mode (P3)

`docker-compose.yml` stands up the self-hosted LangGraph Server (Postgres + Redis) behind Caddy,
with audit shipping (Vector) and Prometheus + Grafana. See **`docs/DEPLOY.md`** for the runbook.

> The service stack MUST NOT run on a Kubernetes cluster the agent itself manages (blast-radius
> rule, PLAN §3.7).
