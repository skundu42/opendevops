"""Frontends over the AgentGateway (HTTP webapp now; Slack, scheduler later).

:mod:`opendevops.interfaces.webapp` is the T17 FastAPI app (Alertmanager + GitHub webhooks,
run-complete callback, health, Prometheus metrics) mounted into the LangGraph Server process via
``langgraph.json``'s ``http.app``. It is imported directly (``from opendevops.interfaces.webapp
import create_app``) rather than re-exported here so ``import opendevops.interfaces`` does not
force a ``fastapi`` import for consumers that only need the CLI.
"""
