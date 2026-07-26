# Interfaces

Four run frontends, one agent, plus one read-only operations dashboard. Each run frontend depends
only on the `AgentGateway` protocol
([architecture](architecture.md#the-gateway-seam)), so they behave identically whether the graph
runs in-process (CLI) or behind the LangGraph Server (everything else).

## CLI REPL

```sh
uv run opendevops chat [--environment staging|prod] [--profile <name>] [--principal <who>]
```

- Streams assistant text as it arrives; tool calls render as `→ run_command …` lines; denials in
  red with the rule id; a per-turn cost line.
- `/cost` — session and daily spend; `/quit` `/exit` `/q` — leave.
- **Ctrl-C cancels the in-flight run** via the gateway (audited, graceful) without killing the
  REPL.
- Other subcommands: `opendevops version`, `opendevops config check`,
  `opendevops audit verify --dir <dir>`.

### Escalations in the CLI

When a call matches an `escalate` rule the run suspends and a red panel shows the exact argv, the
rule id, and the reason. You choose:

- `approve` — the call executes as-is;
- `edit` — you supply a corrected argv, which **re-enters the full policy pipeline** (an edit can
  still be denied);
- `reject` — the model receives a deny ToolMessage and adapts.

Every resolution is audited with the approver. A **non-interactive** session (stdin not a tty)
auto-rejects escalations rather than hanging.

## HTTP service mode

Stand up the [docker-compose stack](deployment.md) and the LangGraph Server's own REST surface
becomes the API — threads, runs, SSE streaming, `join` reattach, cancellation — fronted by Caddy
with a static bearer token. The `ServerGateway` drives it from any machine:

```sh
curl -s -H "Authorization: Bearer $GATEWAY_TOKEN" \
  http://ops-host:8123/assistants/search -X POST -d '{}'
```

Custom routes (mounted by the server from `interfaces/webapp.py`):

| Route | Auth | Purpose |
|---|---|---|
| `POST /webhooks/alertmanager` | static bearer token (+ optional source-IP allowlist) | alert → RCA run on a **stable incident thread** (thread id derived from the alert fingerprint; duplicate alerts join the same thread) |
| `POST /webhooks/github` | HMAC (`X-Hub-Signature-256`) | CI-failure diagnosis runs |
| `POST /webhooks/run-complete` | bearer token | target of server-side run-completion webhooks; posts final answers back to Slack |
| `GET /dashboard` | signed dashboard session | operational dashboard shell |
| `GET /dashboard/api/snapshot` | signed dashboard session | bounded, redacted audit-derived telemetry |
| `GET`, `POST /dashboard/login` | sign-in token on POST | exchange the configured token for a signed session |
| `POST /dashboard/logout` | signed dashboard session | clear the browser session |
| `GET /healthz` | none | liveness |
| `GET /metrics` | none (network-internal) | Prometheus |

A route whose configured secret env var is unset returns **503** — fail-closed, never
"auth disabled". Webhook-initiated runs use the `server.webhook_environment` policy overlay and
the `incident` budget profile pattern.

## Operations dashboard

The service-mode dashboard at `/dashboard` is an audit-led control room for answering: what ran,
where, under whose authority, what it cost, and which policy decisions shaped the result. It
shows:

- run counts and success rate, audit-recorded spend, denials and escalations;
- seven-day run and spend activity;
- recent run status, principal, environment, model/tool counts and cost;
- a policy-decision breakdown and a sanitized event timeline;
- runtime mode plus integration-configuration posture.

Its data source is the hash-chained JSONL audit directory, not an additional analytics database.
Reads are bounded to the newest 200 files and 16 MiB per file. Corrupt or incomplete chains are
surfaced as operational state rather than hidden. The API deliberately excludes command argv,
stdout/stderr and credential values; integration posture reports only configured/unconfigured
counts.

Set `server.dashboard_token_env` to the **name** of a strong token environment variable. Login
compares the submitted value in constant time and returns a short-lived, signed `HttpOnly`,
`SameSite=Strict` cookie. Missing configuration fails closed. Set
`server.dashboard_cookie_secure: true` behind HTTPS, rotate the token like any operator
credential, and add OIDC/SSO at the ingress for multi-user production installations.

## Slack chat-ops

`interfaces/slack_app.py` — slack-bolt **Socket Mode** (outbound websocket, no public URL).
Requires the `slack` extra and `slack.bot_token_env` / `slack.app_token_env` configured
([configuration](configuration.md#slack-scheduler-principals)).

- **Thread mapping**: the agent thread id is derived deterministically from
  `channel:thread_ts`, so replying in a Slack thread resumes the same agent conversation.
- **Fast ack**: messages are acknowledged within 3 s with a placeholder; the run executes
  asynchronously and the final answer is posted by the run-complete webhook.
- **Escalations** arrive as Block Kit approve / edit / reject buttons; the resolution (with the
  approving Slack principal) flows through the same `resume_interrupt` path and audit events as
  the CLI.
- **Authorization**: `principals:` in `config.yaml` maps Slack user ids to
  `{principal, profile}`; unmapped users are not served. Runs are attributed (audit +
  per-principal daily budget) to the mapped principal.

> Go-live gate: approver dedupe is not yet enforced — any mapped principal can approve an
> escalation, including the requester. Recorded in the standing pre-deploy gates.

## Scheduler

`interfaces/scheduler/` — our own APScheduler service (never LangGraph Server crons: no license
dependency, one mechanism for cron + event triggers). Jobs live in `scheduler/jobs.yaml`:

```yaml
jobs:
  - id: drift-detection
    trigger: {cron: "0 * * * *"}        # or {interval: {minutes: 5}}
    command: >-                          # the task text a fresh scheduled run executes
      Detect configuration drift ... Do not remediate — read-only investigation.
    timeout_s: 600
    environment: staging

  - id: escalation-sweep
    trigger: {interval: {minutes: 5}}
    job_type: escalation-sweep           # a registered non-agent runner (no LLM turn)
    timeout_s: 300
```

- A job is either an **agent job** (`command:` — a prompt run on a fresh thread under the
  `scheduled` profile, attributed to the `scheduler.principal`) or a **non-agent job**
  (`job_type: hygiene | escalation-sweep`, runners in `ops/maintenance.py`).
- Fixed knobs applied to every job (not configurable per job): `misfire_grace_time=300`,
  `coalesce=true`, `max_instances=1`, 60 s jitter — run a briefly-missed job, collapse backlogs,
  never overlap a job with itself, and de-synchronize the fleet from the cron edge.
- Shipped jobs: hourly drift detection, daily cert-expiry and backup verification, daily hygiene
  (thread pruning, spend mirror, pg_dump), and the 5-minute escalation sweep.
- The schema is validated fail-closed at boot: unknown keys or malformed triggers refuse to start.

### The escalation-timeout sweeper

`interrupt()` parks a run indefinitely, and a plain cancel would leave no resolution record. The
sweeper lists suspended escalations older than their rule's `timeout_s` and **resumes them with a
reject decision** — so the model receives the deny ToolMessage, adapts, and a `resolution` audit
event is written with `approver="__timeout__"`. This is the enforcement behind
`escalation: {on_timeout: deny}` in policy rules, and it is what makes `escalate` rules safe for
unattended (scheduled/webhook) runs.
