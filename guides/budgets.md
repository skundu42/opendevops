# Budgets and cost control

An autonomous agent with no human in the loop needs hard resource ceilings, each with a distinct
enforcement mechanism. Configuration lives in `config/budgets.yaml`
([reference](configuration.md#configbudgetsyaml)); enforcement lives in `src/opendevops/budget/`
and the gateway.

## Every limit and its owner

| Limit | Enforced by | On breach |
|---|---|---|
| Per-run USD | `CostCapMiddleware` — accumulates cost after every model call; before the next call, jumps to end at `trip_ratio` (0.9) × cap | graceful end with an explanatory final message + `budget_trip` audit event; overshoot bounded by one call's `max_tokens` |
| Daily USD (global + per-principal) | `DailyBudgetMiddleware` → `DailyCounter`, keyed `(scope, UTC date)` | jump-to-end mid-run; the gateway refuses **new** runs for the rest of the day |
| Model calls / run | `ModelCallLimitMiddleware` | graceful end |
| Tool calls / run (all tools + `run_command` specifically) | `ToolCallLimitMiddleware` ×2 | error ToolMessage — the model adapts and wraps up |
| Graph super-steps | `recursion_limit` per budget profile (default 250) | `GraphRecursionError`; state survives in the checkpointer |
| Wall clock | `LocalGateway`: `asyncio.wait_for` around the run; `ServerGateway`: server `run_timeout` + caller-side cancel timer | run cancelled; resumable on the same thread |
| Context growth | deepagents summarization middleware on the haiku alias | bounds per-iteration input tokens |

Two design rules make the suite robust:

- **Ordering immunity**: every budget middleware computes cost *itself* from each
  `AIMessage.usage_metadata` via the shared stateless pricing module — no middleware reads a
  delta another produced, so middleware execution order cannot corrupt accounting.
- **Fail closed**: a daily-counter outage (`fail_mode_on_counter_outage: closed`) refuses new
  runs rather than running unmetered.

## Who counts the money

Two accounting paths, deliberately:

1. **In-graph accumulation** (graph state) — what the cost-cap gate can see mid-run; drives the
   jump-to-end decision.
2. **Gateway-level aggregation** — the gateway wraps every run with
   `get_usage_metadata_callback()`, a contextvar-based aggregate that catches **all** model calls
   in the run, including the summarizer's internal calls and the `log-summarizer` subagent, which
   never pass through our middleware hooks. This aggregate is **authoritative**: it feeds the
   daily counter and the REPL's cost lines.

A graph test scripts a summarization trigger and asserts the run's accounted cost includes it —
the gap between the two paths is exactly why both exist.

## Pricing

`src/opendevops/models/pricing.py` — no external pricing dependency; the price table in
`models.yaml` is the source of truth:

```
uncached = input_tokens - cache_read - cache_creation
usd = (uncached·input + cache_read·cache_read + cache_creation·cache_write + output_tokens·output) / 1e6
```

Cache-tier aware (cache reads are ~10× cheaper than fresh input; cache writes ~25% dearer).
**Boot check**: every model referenced in `models.yaml agents:` must resolve in `pricing:`, or
the process refuses to start — an unpriced model is an unmetered model.

## Budget profiles

A run is started under a profile (`--profile` in the CLI; per-job in the scheduler; Slack via the
principal map). Profiles overlay `per_run.default`:

| Profile | Intent | Shipped values |
|---|---|---|
| `default` | baseline | $2.00, 50 model calls, 100 tool calls, 30 shell calls, 250 steps, 15 min |
| `interactive` | human at the keyboard | $5.00, 30 min |
| `scheduled` | unattended cron runs | $2.00, 40 model calls |
| `incident` | alert-driven RCA | $10.00, 60 min |

## Daily counters

`DailyCounter` is a protocol with two backends (`budget/daily.py`):

- **sqlite** (default): durable local file, correct for the single-process CLI tier.
- **redis**: `INCRBYFLOAT` + expiry — required for service mode so every server worker accumulates
  into **one** daily envelope that survives restarts. Selecting `backend: redis` without a
  `redis_url` fails the boot.

Scopes: `global` and per-principal — so one chat-heavy user (or the scheduler principal) exhausts
their own envelope before the global one.

## Observing spend

- REPL: a per-turn `spent $… (run) / $… (today)` line, plus `/cost`.
- Service mode: spend metrics on the Grafana dashboard; a Prometheus alert fires at >80% of the
  daily envelope ([deployment](deployment.md#monitoring)).
- `uv run python -m ops.maintenance spend-report --json` for a machine-readable mirror.
- Weekly cross-check (service tier): LangSmith-computed cost vs gateway-accounted cost; >5%
  divergence alerts — it catches price-table staleness.
