# Remote executor production gates — design

Date: 2026-07-27  
Status: approved for implementation  
Scope: close the four pre-deployment gates in `ops/executor/README.md`

## Decisions

| Topic | Choice |
|---|---|
| Routing config | Replace `executor.url` with required `executor.urls.{staging,prod}.{ro,rw}` — fail boot if incomplete |
| SSH path | Same `POST /execute`; `tool_family=ssh`; route to `(environment, ro)` |
| Signing keys | One shared ed25519 keypair across all pods |
| Token binding | Add `environment` and `host` (`null` for `run_command`) |

## Architecture

1. **Token** — signed payload binds `argv_sha256`, `staging_sha256`, `run_id`, `tool_call_id`, `channel`, `tool_family`, `environment`, `host`, `exp`.
2. **Service identity** — pod reads `OPENDEVOPS_EXECUTOR_ENV` / `OPENDEVOPS_EXECUTOR_CHANNEL` at boot; missing or invalid → refuse start. After signature verify, mismatch with pod identity → 403, no exec.
3. **Client routing** — `RemoteExecutor` selects `urls[environment][channel]` per decision. `ssh_run` always uses channel `ro`.
4. **SSH remote** — agent keeps host allowlist check; does **not** hold the SSH key. Service resolves `targets.ssh` credentials and runs `SshExecutor`. Connection failures → 502; agent maps to the existing refusal string (no exec meta).

## Out of scope (at gates landing)

- Postgres control ledger / Vault SecretSource / multi-provider LLMs (later sub-projects; landed separately)

## Follow-up (done)

- Per-(env,channel) signing keys + shared Redis spent-token cache + agent mTLS —
  see `2026-07-31-production-hardening-design.md`

## Test plan

- Unit: signing binds/rejects wrong `environment` and `host`
- Unit: service 403 on identity mismatch; never executes (spy)
- Unit: config rejects remote without full `urls` map; rejects leftover `url`
- Unit/integration: remote round-trip with `urls` map; `ssh_run` remote path does not call `resolve_ssh_credential` on agent
- Manifests/docs: README gates marked closed; config comments updated
