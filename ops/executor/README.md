# Executor service deployment

Hardened k8s manifests for the standalone executor **service** — the holder of the
`run_command` infra credentials, `ssh_run` SSH key, and `{{secret:NAME}}` values on the remote
executor path. One Deployment per **(environment, channel)** so each pod carries exactly one
credential set.

> **Status:** production-ready when `executor.mode=remote` and `executor.urls` is fully
> populated for `staging`/`prod` × `ro`/`rw`. The agent holds only the ed25519 **private**
> signing key (no kube/gh/cloud credentials, no SSH key, no secret values). Each request
> carries a decision token that binds `environment`, `channel`, and (for ssh) `host`; each
> pod asserts `OPENDEVOPS_EXECUTOR_ENV` / `OPENDEVOPS_EXECUTOR_CHANNEL` and rejects mismatches
> with 403 before execution.

## What the agent holds on the remote path

On `mode=remote`, both `run_command` and `ssh_run` route through signed `POST /execute` to the
URL selected from `executor.urls[environment][channel]` (`ssh_run` always uses channel `ro`).
The agent process holds **only** the ed25519 private signing key. Credential env vars and the
SSH private key live exclusively on the matching executor pods.

## Files
- `namespace.yaml` — the isolated `opendevops-executor` namespace (Pod Security `restricted`).
- `deployment-{staging,prod}-{ro,rw}.yaml` — the four hardened Deployments. Each runs
  `uvicorn opendevops.executor_service.service:build_app_from_env --factory`. Hardening (all
  asserted by `tests/unit/test_executor_manifests.py`, no live cluster): `runtimeClassName: gvisor`,
  `runAsNonRoot`, `readOnlyRootFilesystem`, `capabilities.drop: [ALL]`, `seccompProfile:
  RuntimeDefault`, and a `medium: Memory` (tmpfs) `emptyDir` mounted at `/work`.
  Each Deployment sets `OPENDEVOPS_EXECUTOR_ENV` and `OPENDEVOPS_EXECUTOR_CHANNEL` for pod
  identity self-check at boot and on every request.
- `networkpolicy.yaml` — default-deny INGRESS except from the agent workload (only the agent may
  reach `POST /execute`), and default-deny EGRESS except DNS + an allowlisted CIDR with IMDS
  (`169.254.169.254/32`) and link-local blocked. RECOMMENDED transport hardening: **mTLS** between
  the agent and the service (e.g. a service mesh) — the signed token binds integrity at the app
  layer; mTLS adds transport-level authentication. Cert management is out of scope here (doc-only).

## Wiring
- Each pod's env must supply: the ed25519 **public** verify key (env var named by
  `executor.verify_key_env`), the credential env for its family/channel (KUBECONFIG / GH_TOKEN /
  cloud vars — see `config.py` targets), SSH key material on **ro** pods when `targets.ssh` is
  enabled, and the `{{secret:NAME}}` values (prefixed by `executor.secret_env_prefix`). Source
  these from a Secret / CSI driver, never bake them.
- The agent Deployment holds ONLY the ed25519 **private** signing key (`executor.signing_key_env`)
  and the full `executor.urls` map pointing at the four service endpoints.
- Narrow the `0.0.0.0/0` egress base to concrete API/endpoint CIDRs before deploy; keep the
  `except` IMDS entry regardless.

## Closed pre-deployment gates

1. **Bind `environment` into the signed token** (with `channel`, and `host` for `ssh_run`).
2. **The service asserts its own identity** — each pod reads `OPENDEVOPS_EXECUTOR_ENV` /
   `_CHANNEL` at boot and rejects any token whose bound `environment`/`channel` differs → 403.
3. **The client routes per (env,channel)** — `executor.urls` replaces the former single
   `executor.url`.
4. **`ssh_run` routes through the service** — `tool_family=ssh` on `POST /execute`; agent does
   not hold the SSH key.

Shared ed25519 keypair across pods (one private on agent, one public on all services). Per-route
keys remain a possible future hardening.

## Dependencies
The service needs `cryptography` (ed25519), `httpx`, and `fastapi` — all already resolved + pinned
in `uv.lock` (no new dependency, no lock change). For `ssh_run`, the service image must also
include the `ssh` extra (`asyncssh`). The image installs the package plus the pinned
`fastapi`; do NOT install the `server` extra here — it pulls `langgraph-sdk`, which the executor
service must never import (SDK firewall).
