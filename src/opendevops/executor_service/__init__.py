"""The standalone executor **service** (the executor split).

A small FastAPI app that is the ONLY holder of infra credentials + secret values. It verifies an
ed25519 decision token (proving the request passed the policy engine), materializes staged files
into a per-call tmpdir, builds the credential env, resolves ``{{secret:NAME}}`` into the subprocess
env (never argv), runs the argv ``shell=False``, full-scrubs the output, and returns the same
``ExecResult`` shape the in-process ``LocalExecutor`` would.

SDK firewall: this package MUST NOT import ``langgraph_sdk`` (only ``gateway/server.py`` may).
``fastapi`` / ``httpx`` are fine.
"""

from __future__ import annotations

from opendevops.executor_service.service import (
    build_app_from_env,
    create_app,
)
from opendevops.executor_service.spent import (
    MemorySpentDecisionStore,
    RedisSpentDecisionStore,
    SpentDecisionStore,
    build_spent_store,
)

__all__ = [
    "MemorySpentDecisionStore",
    "RedisSpentDecisionStore",
    "SpentDecisionStore",
    "build_app_from_env",
    "build_spent_store",
    "create_app",
]
