# Postgres control ledger + chat store — design

Date: 2026-07-27  
Status: implementing

## Decisions

- `control_plane.backend`: `sqlite` (default) | `postgres`
- Postgres URL from env named by `control_plane.database_url_env` (value never in YAML)
- Same backend serves **both** capability ledger and dashboard chat (shared durable store)
- SQLite path (`control_plane.database`) unchanged for local/dev
- Placeholder style in app SQL stays `?`; postgres backend rewrites to `%s`
- `ORDER BY rowid` → `ORDER BY expires_at DESC` / `ORDER BY sequence DESC` (portable)
- Multi-replica: postgres + process lock; critical rw consume uses `FOR UPDATE` on postgres

## Out of scope

- Automatic migration from existing SQLite files to Postgres (operator dump/restore)
- Shared Redis spent-token cache for remote executor
