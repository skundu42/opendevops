# Production hardening — design

Date: 2026-07-31

Status: implementing

Scope: close deferred seams from remote-executor, vault, postgres, and model-provider specs.

## Decisions

| Topic | Choice |
|---|---|
| Spent-token store | `executor.spent_token_backend`: `memory` (default) \| `redis`; Redis `SET NX EX` keyed `executor:spent:{run_id}:{tool_call_id}` |
| mTLS | Agent-side `executor.tls` (`ca_file`, `cert_file`, `key_file`) → `httpx.AsyncClient(verify=, cert=)`; server TLS remains mesh/sidecar |
| Signing keys | Keep shared `signing_key_env`; optional `signing_keys.{staging,prod}.{ro,rw}` env-var NAMES; service still uses per-pod `verify_key_env` |
| Vault auth | `vault.auth`: `token` \| `approle` \| `kubernetes`; login then KV read; token cached on the source instance |
| In-graph pricing | `price_message` re-keys from AIMessage metadata; Haiku summarizer wraps model invoke and flushes USD into `run_cost_usd` + daily counter |
| Doc hygiene | Correct stale “cloud packs remain read-only” claims; cloud write packs + `credential_env_rw` are first-class |

## Out of scope

- Automatic SQLite → Postgres migration tooling
- Per-call pricing inside the log-summarizer *subagent* graph (still covered by LocalGateway callback; ServerGateway benefits from compaction pricing above)
- Cert issuance / rotation automation (operators mount PEMs or use a mesh)

## Test plan

- Unit: Redis spent store claim/replay; memory parity; 503 on store outage
- Unit: Vault AppRole + Kubernetes login (mocked HTTP)
- Unit: remote requires signing_keys map without shared key; per-route key selection
- Unit: tls client builds with cert pair; incomplete pair rejected
- Unit: price_message prefers reported model; summarizer pending flush shape
- Docs: security-model + README cloud-write wording aligned with shipped packs
