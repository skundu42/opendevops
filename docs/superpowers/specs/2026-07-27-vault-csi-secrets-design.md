# Vault / CSI SecretSource — design

Date: 2026-07-27  
Status: implementing

## Decisions

- `executor.secret_source`: `env` | `file` | `vault`
- **file** (CSI): read `{{secret:NAME}}` from `{secret_file_dir}/{NAME}` (trimmed); missing → fail-closed
- **vault**: HashiCorp KV v2 via HTTP; `vault.addr_env`, `vault.token_env`, `vault.mount`, `vault.path_prefix`; secret at `{mount}/data/{path_prefix}/{NAME}`, field `value` (or whole string data)
- Factory `build_secret_source(cfg)` used by local `run_command` and remote executor service

## Out of scope

- Writing secrets

## Follow-up (done)

- Vault AppRole / Kubernetes auth — see `2026-07-31-production-hardening-design.md`
