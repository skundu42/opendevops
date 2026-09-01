"""AgentGateway protocol and implementations (in-process now, LangGraph Server later)."""

from __future__ import annotations

from opendevops.gateway.base import (
    AgentGateway,
    ApprovalSeparationError,
    AssistantText,
    Escalation,
    EscalationDetails,
    EscalationEvent,
    GatewayConfigError,
    GatewayError,
    GatewayRunError,
    RunEnd,
    RunEvent,
    RunResult,
    ToolCall,
    ToolResult,
    escalation_details,
)
from opendevops.gateway.local import LocalGateway
from opendevops.gateway.server import ServerGateway

__all__ = [
    "AgentGateway",
    "ApprovalSeparationError",
    "AssistantText",
    "Escalation",
    "EscalationDetails",
    "EscalationEvent",
    "GatewayConfigError",
    "GatewayError",
    "GatewayRunError",
    "LocalGateway",
    "RunEnd",
    "RunEvent",
    "RunResult",
    "ServerGateway",
    "ToolCall",
    "ToolResult",
    "escalation_details",
]
