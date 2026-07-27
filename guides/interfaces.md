# Interfaces

Four run frontends, one agent, plus an OIDC/RBAC operations control plane. Each run frontend depends
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
  `opendevops audit verify --dir <dir>`, and the `opendevops config *-grant` lifecycle.

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
| `GET /dashboard` | opaque server-side session | operational dashboard shell |
| `GET`, `POST /dashboard/api/chat/threads` | operator/admin; POST uses CSRF | list or create identity-scoped investigations |
| `GET /dashboard/api/chat/threads/{thread_id}` | owning operator/admin | bounded private transcript |
| `POST /dashboard/api/chat/threads/{thread_id}/messages` | owning operator/admin + CSRF | stream an agent turn over SSE |
| `POST /dashboard/api/chat/threads/{thread_id}/cancel` | owning operator/admin + CSRF | cancel the active chat run |
| `GET /dashboard/api/snapshot` | viewer+ | bounded audit + live control-plane snapshot |
| `GET /dashboard/api/events` | viewer+ | SSE audit changes and live run/queue/worker/approval state |
| `GET /dashboard/api/runs/{run_id}` | viewer+ | correlated run, trace, model, policy, tool and integrity detail |
| `POST /dashboard/api/runs/{run_id}/cancel` | operator/admin + CSRF | cancel a correlated run |
| `POST /dashboard/api/approvals/{thread_id}` | approver/admin + CSRF | approve/edit/reject a suspended run |
| `GET`, `POST /dashboard/api/config/proposals` | viewer / operator+ | list or propose typed capability grants |
| `POST /dashboard/api/config/proposals/{id}/approve` | approver/admin + CSRF | approve; production enforces requester separation |
| `POST /dashboard/api/config/proposals/{id}/activate` | admin + CSRF | activate an approved grant |
| `POST /dashboard/api/config/proposals/{id}/revoke` | admin + CSRF | immediately revoke a grant |
| `POST /dashboard/api/sessions/revoke` | admin + CSRF | revoke every session for issuer + subject |
| `GET /dashboard/oidc/login`, `GET /dashboard/oidc/callback` | OIDC | state + nonce + PKCE login flow |
| `POST /dashboard/logout` | session + CSRF | revoke the current session |
| `GET /healthz` | none | liveness |
| `GET /metrics` | none (network-internal) | Prometheus |

A route whose configured secret env var is unset returns **503** — fail-closed, never
"auth disabled". Webhook-initiated runs use the `server.webhook_environment` policy overlay and
the `incident` budget profile pattern.

## Operations dashboard

The service-mode dashboard at `/dashboard` includes an agent command channel plus an audit-led
control room. An operator or admin can ask about connected infrastructure in a durable LangGraph
thread. Each turn uses `principal=oidc:{issuer}#{subject}`, `interface=http`, the selected
`staging`/`prod` policy environment, and the normal gateway budget and safety core. Concurrent turns
on one thread are refused. An interrupted turn becomes read-only until an approver resolves it in
Live control; production requester/approver separation is unchanged.

Chat threads and their bounded transcripts are private to an exact issuer/subject pair and expire
after the configured retention period. The browser receives assistant text plus sanitized tool
lifecycle and policy-denial labels over the POST response's SSE stream. Raw tool arguments,
stdout/stderr, escalation arguments, and credentials are neither sent to the chat UI nor stored in
its transcript. The content-free control ledger records thread/run lifecycle attribution without
copying prompts or responses.

The control room answers what is running, what is queued, which approvals are waiting, where an
action ran, under whose authority, what it cost, and which policy decisions shaped the result. It
shows:

- active LangGraph/gateway runs, queue and worker state, retries/errors and pending approvals;
- run counts and success rate, audit-recorded spend, denials and escalations;
- seven-day run and spend activity;
- recent run status, OIDC/service principal, environment, model/tool counts and cost;
- run-detail correlation by `run_id`, `thread_id`, `tool_call_id` and `trace_id`;
- content-free model timing/token/cost progression, policy decisions and tool timing;
- versioned dangerous-capability proposals with a Propose → Approve → Activate wizard
  (loop limits, reason, and actor metadata on each card);
- runtime mode plus integration-configuration posture (cloud read/write credential counts;
  values never returned).

Persisted truth comes from the hash-chained JSONL audit directory; live state comes from the
gateway/LangGraph SDK and the web control projection. The browser receives changes over SSE
instead of polling the entire audit window. Reads are bounded to the newest 200 files and 16 MiB
per file. Corrupt or incomplete chains are surfaced, not hidden. Audit and run-detail APIs
deliberately exclude command argv, prompt/response content, stdout/stderr and credential values;
chat content is returned only through the identity-owned chat routes described above.

Production uses `server.dashboard_auth_mode: oidc` with an exact issuer, registered redirect URI,
client env names and explicit role mappings. Sessions are opaque, server-side, short-lived and
revocable; state-changing calls require CSRF. Static-token mode gives the local developer all four
roles and must not be used as a deployed authentication system.

RBAC is intentionally non-hierarchical around approval: `operator` can chat, cancel and propose but
cannot approve; `approver` can approve but cannot initiate agent turns; `admin` is the
emergency/full-control role. Every login, chat run, approval, cancellation, session revocation,
dashboard detail view and configuration transition is written to the hash-linked control-event
ledger with issuer + subject.

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

Production approval separation is enforced inside both gateway implementations before the
suspended context is removed. A requester may reject their own request, but may not approve or edit
it into an authorized production action.

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
