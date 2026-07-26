"""Content-free model-call telemetry appended to the per-run audit chain."""

from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any

from langchain.agents.middleware import AgentMiddleware
from langchain.agents.middleware.types import ModelRequest, ModelResponse
from langchain_core.messages import AIMessage

from opendevops.audit.logger import AuditLogger
from opendevops.audit.schema import EventType, new_event_id
from opendevops.models.pricing import PriceTable
from opendevops.observability.otel import observe_operation, span

logger = logging.getLogger(__name__)


def _context(request: ModelRequest[Any], name: str) -> Any:
    runtime = request.runtime
    context = getattr(runtime, "context", None) if runtime is not None else None
    value = getattr(context, name, None)
    if value is None and isinstance(context, dict):
        value = context.get(name)
    return value


class ModelAuditMiddleware(AgentMiddleware[Any, Any, Any]):
    """Record timing, token usage, and cost progression without prompts or responses."""

    def __init__(
        self,
        audit: AuditLogger,
        price_table: PriceTable,
        model_key: str,
        policy_version: str,
    ) -> None:
        super().__init__()
        self._audit = audit
        self._price_table = price_table
        self._model_key = model_key
        self._policy_version = policy_version

    async def awrap_model_call(
        self,
        request: ModelRequest[Any],
        handler: Callable[[ModelRequest[Any]], Awaitable[ModelResponse[Any]]],
    ) -> ModelResponse[Any]:
        run_id = str(_context(request, "run_id") or "")
        call_id = new_event_id()
        started = time.perf_counter()
        attributes = {
            "run.id": run_id,
            "model.call.id": call_id,
            "opendevops.trace_id": str(_context(request, "trace_id") or ""),
            "gen_ai.request.model": self._model_key,
        }
        try:
            with span("opendevops.model.call", attributes):
                response = await handler(request)
        except Exception as exc:
            duration_ms = max(0, int((time.perf_counter() - started) * 1000))
            observe_operation(
                "model",
                duration_ms,
                "error",
                {"gen_ai.request.model": self._model_key},
            )
            self._append(
                request,
                run_id,
                call_id,
                duration_ms=duration_ms,
                status="error",
                usage={},
                cost_delta=0.0,
                error_type=type(exc).__name__,
            )
            raise

        usage: dict[str, int] = {}
        cost_delta = 0.0
        for message in response.result:
            if not isinstance(message, AIMessage) or not message.usage_metadata:
                continue
            metadata = message.usage_metadata
            for key in ("input_tokens", "output_tokens", "total_tokens"):
                value = metadata.get(key, 0)
                usage[key] = usage.get(key, 0) + (
                    int(value) if isinstance(value, (int, float)) else 0
                )
            try:
                cost_delta += self._price_table.cost_usd(self._model_key, metadata)
            except Exception:  # noqa: BLE001 - a pricing gap is telemetry, not a model failure
                usage["usage_missing"] = usage.get("usage_missing", 0) + 1
        duration_ms = max(0, int((time.perf_counter() - started) * 1000))
        observe_operation(
            "model",
            duration_ms,
            "ok",
            {"gen_ai.request.model": self._model_key},
        )
        self._append(
            request,
            run_id,
            call_id,
            duration_ms=duration_ms,
            status="ok",
            usage=usage,
            cost_delta=cost_delta,
        )
        return response

    def _append(
        self,
        request: ModelRequest[Any],
        run_id: str,
        call_id: str,
        *,
        duration_ms: int,
        status: str,
        usage: dict[str, int],
        cost_delta: float,
        error_type: str | None = None,
    ) -> None:
        if not run_id:
            return
        state: Any = request.state
        raw_cost = state.get("run_cost_usd")
        cost_before = float(raw_cost) if isinstance(raw_cost, (int, float)) else 0.0
        try:
            self._audit.append(
                run_id,
                EventType.model_call,
                principal={
                    "interface": str(_context(request, "interface") or "unknown"),
                    "user": str(_context(request, "principal") or "unknown"),
                },
                environment=str(_context(request, "environment") or "unknown"),
                model=self._model_key,
                policy_version=self._policy_version,
                summary={
                    "model_call_id": call_id,
                    "status": status,
                    "duration_ms": duration_ms,
                    "usage": usage,
                    "cost_before": round(cost_before, 8),
                    "cost_delta": round(cost_delta, 8),
                    "cost_after": round(cost_before + cost_delta, 8),
                    "error_type": error_type,
                },
            )
        except Exception:  # noqa: BLE001 - observability must not alter model execution
            logger.exception("could not append model-call telemetry for run %s", run_id)
