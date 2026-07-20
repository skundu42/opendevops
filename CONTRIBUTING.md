# Contributing to opendevops

Thanks for your interest! Contributions of every kind are welcome — bug reports, docs fixes, new
policy packs, new tool families, new interfaces.

## Getting set up

```sh
git clone https://github.com/skundu42/opendevops.git && cd opendevops
uv sync --extra checkpoint --extra server --extra slack --extra ssh --extra dev
uv run pytest -q          # the whole suite is deterministic and costs $0 in LLM calls
```

## Before you open a PR

CI runs exactly these three checks — run them locally first:

```sh
uv run ruff check .
uv run mypy src ops
uv run pytest
```

## What we ask of changes

The project's value is its safety posture, so a few conventions are enforced rather than
suggested — the [development guide](guides/development.md) explains each in detail:

- **Fail closed.** Anything you add that can error must deny/refuse rather than degrade.
- **argv-only.** No code path may construct a shell string from model input.
- **SDK firewall.** Only `gateway/server.py` imports `langgraph_sdk`.
- **Policy changes ship with corpus deny-tests** that assert the exact rule id
  ([policy guide](guides/policy.md#testing)).
- **Behavior changes keep the audit-gate invariants green** (`tests/replay/audit_gates.py`).
- The pinned `deepagents`/`langchain`/`langgraph` trio moves only together, through the gate in
  [`docs/UPGRADE.md`](docs/UPGRADE.md) — don't bump it casually.

Match the surrounding code's style (ruff enforces most of it; line length 100). Add tests in the
same tier as the behavior you touch ([test tiers](guides/development.md#test-tiers)).

## Good first contributions

- New **read-only policy packs** for additional CLI tool families (usually zero new Python:
  pack + base-denies + credential config + corpus tests —
  [walkthrough](guides/policy.md#writing-a-new-pack)).
- Hardening or extending the **bypass corpus** with new deny cases.
- Docs: anything in `guides/` that confused you is a bug — file it or fix it.

## Reporting bugs

Use [GitHub issues](https://github.com/skundu42/opendevops/issues). For anything
security-sensitive, see [SECURITY.md](SECURITY.md) instead of filing a public issue.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE).
