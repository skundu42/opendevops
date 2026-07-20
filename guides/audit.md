# The audit trail

Every run produces a **tamper-evident, hash-chained JSONL file** written by the policy/budget
middleware itself — not by anything the model can influence. The trail answers, verifiably:
*what did the agent decide, what did it execute, who approved what, and what did it cost?*

## Chain design

- One file per run: `audit/<run_id>.jsonl`, appended with single-line `O_APPEND` writes.
- Each event carries `prev_hash` and `hash = sha256(prev_hash || canonical_json(event))`, seeded
  from a signed `run_started` header event.
- **Chains are per-run, deliberately**: the server executes runs concurrently across workers, and
  `prev_hash` is a read-modify-write — parallel appends to one shared file would race and
  permanently break verification. Per-run files make each chain single-writer; a concurrency test
  runs parallel runs and asserts every chain still verifies.
- Dedupe on `(run_id, tool_call_id, event_type)` keeps interrupt-resume replays from double-writing
  events.

## Event types

| Type | Written when |
|---|---|
| `run_started` | chain seed: principal, interface, environment, model, `agent_git_sha`, `policy_version` |
| `decision` | before any execution — the parsed argv and the winning rule/effect/channel |
| `execution` | after execution — exit code, duration, stdout sha256 + excerpt, staged-file sha256s |
| `escalation` | a call suspended for human review |
| `resolution` | the review outcome, with the **approver** (or `__timeout__`) |
| `budget_trip` | a cap forced the run to wind down |
| `policy_error` | a pipeline exception (which also denied the call) |
| `run_completed` | final cost + usage breakdown |

A `decision` record looks like:

```json
{"event_id":"01J...","ts":"...","schema_version":1,"event_type":"decision",
 "run_id":"...","thread_id":"...","trace_id":"...",
 "principal":{"interface":"cli","user":"..."},"environment":"staging",
 "agent_git_sha":"...","policy_version":"sha256:...","model":"anthropic:claude-opus-4-8",
 "tool":"run_command","tool_call_id":"...",
 "args":{"argv":["kubectl","-n","web","describe","pod","api-0"]},
 "decision":{"effect":"allow","rule_id":"kubectl-read-verbs","channel":"ro","rewritten_argv":null},
 "prev_hash":"sha256:...","hash":"sha256:..."}
```

Useful properties: `policy_version` pins exactly which policy files produced each decision;
`rewritten_argv` records what a rewrite changed; `execution.staged_files[].sha256` records the
exact manifest an `apply -f` applied (and is what the dry-run-before-apply hook keys on).

## Verifying

```sh
uv run opendevops audit verify --dir ./audit     # per-run chain files
uv run opendevops audit verify --dir <spool>     # Vector-merged day files
```

The verifier auto-detects each file's shape: a per-run `<run_id>.jsonl` verifies as a single
chain; a merged day file (`audit-merged-<date>.jsonl`, many interleaved runs) is **regrouped by
`run_id`** and each run's subsequence verified independently. Regrouping is sound because the
spool preserves lines verbatim and never reorders within a run (each source file is single-writer
and shipped in append order). A tampered, reordered, or dropped line fails the file, naming the
offending `run_id` and line. Exit code 1 on any bad chain — CI-able.

## Separation from the agent

The audit path is excluded from every path the agent can reach:

- not present in any subprocess environment (constructed env);
- not reachable from the deepagents virtual FS (graph state only);
- in service mode, shipped by a **Vector** sidecar to a durable sink whose bucket/table policy
  denies every agent role.

## Shipping and retention (service mode)

Vector tails `audit/*.jsonl` and merges them byte-for-byte into a durable sink. The shipped
default is a local spool volume; the real target is a compliance-owner decision with two
documented options in `ops/vector/vector.yaml`:

- **S3 + Object Lock** (WORM retention), bucket policy denying every agent role;
- **Loki / SIEM** forwarding (INSERT-only), labelled by `run_id`.

Shipper lag is exported to Prometheus and alerted on ([deployment](deployment.md#monitoring)).

## Audit as a test oracle

The trail is machine-checkable, so CI uses it as ground truth (`tests/replay/audit_gates.py`):
zero events where a denied call executed; zero mutate-channel calls outside a scenario's
allowlist; exactly one `execution` event per `tool_call_id` across interrupt resumes; dry-run
recorded before every real apply. If you change agent behavior, these gates are what you must
keep green ([development](development.md#test-tiers)).
