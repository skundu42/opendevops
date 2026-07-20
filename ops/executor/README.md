# Executor service deployment (P5d)

Hardened k8s manifests for the standalone executor **service** — the holder of the
`run_command` infra credentials + `{{secret:NAME}}` values on the remote executor path. One
Deployment per **(environment, channel)** so each pod carries exactly one credential set.

> **Status: EXPERIMENTAL — not production-deployable as shipped.** `executor.mode=remote` is
> opt-in and non-default (`local`, the in-process executor reviewed for P0–P3, is the default and
> the production path). The remote path executes correctly against a **single** service pod, but
> the per-(env,channel) isolation topology these manifests describe is **not yet fully wired** — see
> **Pre-deployment gates** below. Do not run `mode=remote` in production until every gate is closed.

## What the agent holds on the remote path (precise boundary)

On `mode=remote`, `run_command` executions (kubectl / helm / gh ro+rw / aws / gcloud / az) route
through the service, so the **agent process holds none of those credentials** — only the ed25519
**private** signing key (+ `executor.url`). **Exception:** `ssh_run` is a *separate structured tool*
that does **not** route through the executor service — it connects from the agent with the
config-pinned SSH key. So when `targets.ssh` is configured, the agent additionally holds the **SSH
private key** even on `mode=remote`. Routing `ssh_run` through the service (so the agent holds
*zero* infra credentials) is a recorded follow-up gate below.

## Files
- `namespace.yaml` — the isolated `opendevops-executor` namespace (Pod Security `restricted`).
- `deployment-{staging,prod}-{ro,rw}.yaml` — the four hardened Deployments. Each runs
  `uvicorn opendevops.executor_service.service:build_app_from_env --factory`. Hardening (all
  asserted by `tests/unit/test_executor_manifests.py`, no live cluster): `runtimeClassName: gvisor`,
  `runAsNonRoot`, `readOnlyRootFilesystem`, `capabilities.drop: [ALL]`, `seccompProfile:
  RuntimeDefault`, and a `medium: Memory` (tmpfs) `emptyDir` mounted at `/work`.
- `networkpolicy.yaml` — default-deny INGRESS except from the agent workload (only the agent may
  reach `POST /execute`), and default-deny EGRESS except DNS + an allowlisted CIDR with IMDS
  (`169.254.169.254/32`) and link-local blocked. RECOMMENDED transport hardening: **mTLS** between
  the agent and the service (e.g. a service mesh) — the signed token binds integrity at the app
  layer; mTLS adds transport-level authentication. Cert management is out of scope here (doc-only).

## Wiring (out of scope for the manifests themselves)
- Each pod's env must supply: the ed25519 **public** verify key (env var named by
  `executor.verify_key_env`), the credential env for its family/channel (KUBECONFIG / GH_TOKEN /
  cloud vars — see `config.py` targets), and the `{{secret:NAME}}` values (prefixed by
  `executor.secret_env_prefix`). Source these from a Secret / CSI driver, never bake them.
- The agent Deployment holds ONLY the ed25519 **private** signing key (`executor.signing_key_env`)
  and `executor.url`. **Topology gap (see gates):** a single `executor.url` cannot address the four
  per-(env,channel) pods — one run legitimately mixes `ro` (reads) and `rw` (a staging mutation), so
  per-(env,channel) routing on the client is required; today all traffic goes to one URL.
- Narrow the `0.0.0.0/0` egress base to concrete API/endpoint CIDRs before deploy; keep the
  `except` IMDS entry regardless.

## Pre-deployment gates (MUST close before any `mode=remote` production run)

The decision token today binds `(argv, staged-file plan, tool_family, channel, run_id,
tool_call_id, exp)` — but **not the environment**, and the service performs **no (env,channel)
self-check** (the `OPENDEVOPS_EXECUTOR_ENV` / `OPENDEVOPS_EXECUTOR_CHANNEL` env vars in the
Deployments are currently read by no code). As shipped, a mis-routed or MITM'd `staging`-`rw`
decision would verify and run on the `prod`-`rw` pod with **prod** credentials — defeating the
"no prod mutation path" invariant. Remote mode is therefore gated on ALL of:

1. **Bind `environment` into the signed token** (`signing.py` payload) alongside `channel`.
2. **The service asserts its own identity** — each pod reads its configured `(environment, channel)`
   (consume `OPENDEVOPS_EXECUTOR_ENV`/`_CHANNEL`) and rejects any token whose bound
   `environment`/`channel` differs → 403, before executing.
3. **The client routes per (env,channel)** — the agent selects the correct per-(env,channel) service
   URL for each decision (replace the single `executor.url` with a routing map), so a `rw` staging
   mutation and a `ro` read in the same run reach different pods.
4. **`ssh_run` routes through the service** (or ssh deployments explicitly accept that the agent
   holds the SSH key — documented above), so the "agent holds zero infra credentials" claim is
   literally true for every configured tool.

Until (1)–(3) land, keep `mode=local` (the default) in production. The local path is fully
reviewed and carries no remote-topology risk.

## Dependencies
The service needs `cryptography` (ed25519), `httpx`, and `fastapi` — all already resolved + pinned
in `uv.lock` (no new dependency, no lock change). The image installs the package plus the pinned
`fastapi`; do NOT install the `server` extra here — it pulls `langgraph-sdk`, which the executor
service must never import (SDK firewall).

