"""Operator tooling for the opendevops service stack (P3, T18).

Not part of the shipped wheel (``[tool.hatch.build] packages = ["src/opendevops"]``) — these are
ops-side CLIs run against a deployed stack:

* :mod:`ops.maintenance` — hygiene jobs (idle-thread pruning, spend report, pg_dump).
* :mod:`ops.quota_probe` — the LangGraph Server node-execution quota probe (license-up decision).
"""
