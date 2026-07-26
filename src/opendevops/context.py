"""``AgentContext`` — the langgraph runtime ``context_schema`` for a opendevops run.

A dataclass, chosen to match langgraph's ``Runtime`` example and what
``create_deep_agent(context_schema=AgentContext)`` accepts: langgraph coerces *both* a
plain ``dict`` passed as ``invoke(..., context={...})`` and an ``AgentContext`` instance into
this schema, and then exposes each field by attribute on ``runtime.context`` (verified against
the installed langgraph 1.2.9). Attribute access is exactly what ``PolicyMiddleware`` and the
budget middleware use to read ``principal`` / ``environment`` / ``run_id``.

The ``interface`` / ``environment`` literals document the accepted values; they are not
runtime-enforced by a plain dataclass (langgraph's coercion just calls
``AgentContext(**mapping)``), so an unexpected value fails a caller's type check rather than
crashing a live run.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Interface = Literal["cli", "http", "slack", "scheduled", "webhook"]
Environment = Literal["staging", "prod"]


@dataclass
class AgentContext:
    """Run-scoped static context, resolved once at the gateway and read by the middleware.

    * ``principal`` — the resolved agent principal (drives per-principal daily budget caps and
      the audit ``principal.user`` field).
    * ``interface`` — where the run originated (audit ``principal.interface``).
    * ``environment`` — the policy environment overlay to apply (``staging`` | ``prod``).
    * ``budget_profile`` — the per-run budget profile name to resolve.
    * ``run_id`` — the audit-chain / correlation id; a missing ``run_id`` makes audit
      correlation impossible, so the middleware fails closed rather than guess one.
    """

    principal: str
    interface: Interface
    environment: Environment
    budget_profile: str
    run_id: str
    trace_id: str | None = None
