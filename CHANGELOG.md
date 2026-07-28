# Changelog

All notable changes to this project are documented here. The project follows Semantic Versioning
and uses Git tags prefixed with `v`.

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
[0.1.1]: https://github.com/skundu42/opendevops/releases/tag/v0.1.1
[0.1.0]: https://github.com/skundu42/opendevops/releases/tag/v0.1.0
