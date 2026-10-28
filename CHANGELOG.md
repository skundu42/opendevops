# Changelog

All notable changes to this project are documented here. The project follows Semantic Versioning
and uses Git tags prefixed with `v`.

## [Unreleased]

## [0.4.0] - 2026-10-28

### Added

- Read-only GitHub repository and release inspection with `gh repo view|list` and
  `gh release view|list`, using the existing read-token scope and flag restrictions.
- `opendevops config check --json` for CI and automation, including schema failures and optional
  live probe results with a failure exit status.

### Fixed

- Scheduled and webhook runs no longer report success when the gateway returns an error or
  budget stop.
- Scheduler deadlines include thread creation and remain effective when the gateway converts
  cancellation into a result. Cancellation cleanup is bounded and cannot hide a timeout.
- Webhook body limits stop reading oversized streams even with missing or incorrect
  `Content-Length` headers.
- Live preflight reports remote executor TLS/client setup failures instead of crashing.

### Changed

- Common execution wrappers, including `timeout`, `nice`, `nohup`, `stdbuf`, `time`, and
  `busybox`, now match the explicit interpreter deny rule for clearer audit records. These
  commands were already denied by default.

See [docs/releases/v0.4.0.md](docs/releases/v0.4.0.md).

## [0.3.0] - 2026-09-04

### Added

- Slack Socket Mode and scheduler CLI services with opt-in Compose profiles.
- Packaged scheduler maintenance with atomic PostgreSQL backups before thread pruning.
- Transient, scrubbed pending-command details for dashboard approver/admin sessions.
- Aggregated configuration preflight checks and optional live server/executor probes.
- Operational metrics for policy denials, daily spend/caps, and scheduler success timestamps.
- Dependency readiness endpoint and shared Redis webhook deduplication across workers.

### Changed

- Service mode requires Redis through `REDIS_URI` or `budgets.daily.redis_url`.
- Installed policy packs require their credentials and trusted executables; remove unused packs.

See [docs/releases/v0.3.0.md](docs/releases/v0.3.0.md).

## [0.2.1] - 2026-08-11

### Fixed

- Updated PyPI trusted publishing to a metadata-v2.5-compatible action release.
- Removed a timing race from the gateway cancellation test used by the release gate.

See [docs/releases/v0.2.1.md](docs/releases/v0.2.1.md).

## [0.2.0] - 2026-08-11

### Added

- Shared Redis spent-decision store for multi-replica remote executor pods
  (`executor.spent_token_backend: redis`).
- Optional agent→executor mTLS via `executor.tls` (CA + client certificate).
- Optional per-(environment, channel) signing keys via `executor.signing_keys`.
- Vault AppRole and Kubernetes auth for `executor.secret_source: vault`.
- In-graph re-pricing for context-compaction (Haiku summarizer) and per-message model key
  resolution so CostCap / daily counters see non-main model spend.

### Fixed

- Documentation that still claimed AWS/GCP/Azure packs were read-only after curated write packs
  shipped in 0.1.2.

See [docs/releases/v0.2.0.md](docs/releases/v0.2.0.md).

## [0.1.2] - 2026-07-27

### Added

- Production-capable remote executor topology with per-(environment, channel) routing, identity
  assertion, and `ssh_run` through the executor service.
- Optional Postgres backend for the control ledger and dashboard chat store.
- Multi-provider LLM construction (OpenAI, Azure OpenAI, Google, Bedrock, OpenAI-compatible).
- File and HashiCorp Vault KV v2 secret sources for `{{secret:NAME}}`.
- Curated AWS / Google Cloud / Azure write policy packs with hybrid dry-run / escalate behavior.
- Dashboard Propose → Approve → Activate grant wizard with loop limits and richer proposal cards.

### Changed

- Remote mode requires `executor.urls` (replacing a single `executor.url`).
- Cloud write packs boot-gate on distinct `credential_env_rw` identities.

See [docs/releases/v0.1.2.md](docs/releases/v0.1.2.md).

## [0.1.1] - 2026-07-27

### Fixed

- Trusted publishing to PyPI by updating the publish action to a currently available,
  commit-pinned release.

See [docs/releases/v0.1.1.md](docs/releases/v0.1.1.md).

## [0.1.0] - 2026-07-27

### Added

- Policy-gated DevOps agent for Kubernetes, GitHub, AWS, Google Cloud, Azure, and structured SSH.
- OIDC dashboard authentication with viewer, operator, approver, and administrator roles.
- Independent production approvals, expiring capability grants, and dangerous-action loop limits.
- Authenticated dashboard chat, live run observability, SSE updates, OpenTelemetry signals, and
  hash-chained audit verification.
- CLI, HTTP, Slack, scheduler, Alertmanager, and GitHub webhook interfaces.
- Prebuilt Python wheel, source-free Compose bundle, and multi-architecture GHCR image release
  pipeline with checksums, SBOMs, and provenance.

[0.1.2]: https://github.com/skundu42/opendevops/releases/tag/v0.1.2
[0.2.1]: https://github.com/skundu42/opendevops/releases/tag/v0.2.1
[0.2.0]: https://github.com/skundu42/opendevops/releases/tag/v0.2.0
[0.1.1]: https://github.com/skundu42/opendevops/releases/tag/v0.1.1
[0.1.0]: https://github.com/skundu42/opendevops/releases/tag/v0.1.0

[0.3.0]: https://github.com/skundu42/opendevops/releases/tag/v0.3.0
[0.4.0]: https://github.com/skundu42/opendevops/releases/tag/v0.4.0
