# Security policy

opendevops is a security-posture-first project: it exists to run an autonomous agent against real
infrastructure safely. Reports about weaknesses in that posture are especially valuable.

## Reporting a vulnerability

Please **do not** open a public issue for security-sensitive reports. Instead, use
[GitHub private vulnerability reporting](https://github.com/skundu42/opendevops/security/advisories/new)
on this repository.

In scope, particularly:

- **Policy bypasses**: any argv, flag spelling, or tool-call shape that reaches execution when the
  shipped `config/policy/` rules should deny it (the bypass corpus in `tests/unit/policy/` shows
  the expected shape of such findings).
- **Credential-boundary violations**: any path by which a run can read secret material, reach a
  credential outside its `(tool-family, environment, channel)`, or influence which credential the
  executor injects.
- **Audit-integrity issues**: any way an agent-controlled input can forge, drop, or reorder audit
  chain events without `opendevops audit verify` failing.
- **Dashboard authorization or disclosure issues**: session forgery/bypass, token leakage, or any
  route that reveals command arguments, subprocess output, or credential values.
- **Scrubber escapes** with realistic secret formats, and **budget-enforcement escapes**.
- Weaknesses in the executor service's decision-token verification.

Known, documented limitations (see `guides/security-model.md#known-limits-stated-plainly` and the
gates in `ops/executor/README.md`) are not vulnerabilities — but reports that show a documented
limit is worse than described are welcome.

## Supported versions

The `main` branch. There are no maintained release branches yet.
