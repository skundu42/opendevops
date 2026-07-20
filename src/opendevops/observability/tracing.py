"""Tracing switch (T9): LangSmith via env vars now; Langfuse / Phoenix are P3 alternatives.

LangSmith is entirely env-var driven — ``LANGSMITH_TRACING=true`` plus ``LANGSMITH_API_KEY``
(and optionally ``LANGSMITH_PROJECT`` / ``LANGSMITH_ENDPOINT``) make langchain auto-emit traces
with no in-code handler wiring. So :func:`configure_tracing` is a deliberate near-no-op: it just
observes whether tracing is switched on and logs it once, giving the CLI a single, discoverable
call site. There is nothing to construct because the langchain runtime reads the env directly.

P3 alternatives (Langfuse, Arize Phoenix) DO need an explicit callback handler threaded onto the
graph config; when we add one, this is where it is built and where the gateway would pick it up.
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from opendevops.config import AppConfig

logger = logging.getLogger(__name__)


def _tracing_enabled() -> bool:
    """True iff ``LANGSMITH_TRACING`` (or the legacy ``LANGCHAIN_TRACING_V2``) is truthy in env."""
    for var in ("LANGSMITH_TRACING", "LANGCHAIN_TRACING_V2"):
        value = os.environ.get(var, "").strip().lower()
        if value in {"1", "true", "yes", "on"}:
            return True
    return False


def configure_tracing(cfg: AppConfig | None = None) -> bool:
    """Observe the LangSmith tracing switch; return whether tracing is on.

    A no-op unless ``LANGSMITH_TRACING=true`` is set in the environment (env vars are the whole
    LangSmith story per the plan). Called once from the CLI entry so the tracing decision has a
    single, logged home. ``cfg`` is accepted for forward-compatibility (a future Langfuse/Phoenix
    handler would read endpoint/keys from it) but is unused today.
    """
    del cfg  # reserved for P3 Langfuse/Phoenix handler construction
    enabled = _tracing_enabled()
    if enabled:
        project = os.environ.get("LANGSMITH_PROJECT", "default")
        logger.info("LangSmith tracing enabled (project=%s)", project)
    return enabled
