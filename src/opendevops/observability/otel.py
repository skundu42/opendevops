"""Optional OpenTelemetry traces and metrics with safe no-export defaults."""

from __future__ import annotations

import logging
import os
from contextlib import nullcontext
from typing import Any

logger = logging.getLogger(__name__)

_configured = False
_operation_duration: Any = None
_operation_count: Any = None


def configure_opentelemetry(service_name: str = "opendevops") -> bool:
    """Configure OTLP/HTTP exporters once when an endpoint is explicitly present."""
    global _configured, _operation_count, _operation_duration
    if _configured:
        return True
    if not os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"):
        return False
    try:
        from opentelemetry import metrics, trace
        from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        resource = Resource.create({"service.name": service_name})
        trace_provider = TracerProvider(resource=resource)
        trace_provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
        trace.set_tracer_provider(trace_provider)
        metrics.set_meter_provider(
            MeterProvider(
                resource=resource,
                metric_readers=[
                    PeriodicExportingMetricReader(OTLPMetricExporter())
                ],
            )
        )
        meter = metrics.get_meter("opendevops")
        _operation_duration = meter.create_histogram(
            "opendevops.operation.duration",
            unit="ms",
            description="Duration of control-plane operations.",
        )
        _operation_count = meter.create_counter(
            "opendevops.operation.count",
            unit="{operation}",
            description="Control-plane operations by component and outcome.",
        )
    except Exception:  # noqa: BLE001 - telemetry must never block the control plane
        logger.exception("OpenTelemetry exporter configuration failed")
        return False
    _configured = True
    return True


def span(name: str, attributes: dict[str, Any] | None = None) -> Any:
    """Return an active span context, or a no-op context when OTel is unavailable."""
    try:
        from opentelemetry import trace

        return trace.get_tracer("opendevops").start_as_current_span(
            name, attributes=attributes or {}
        )
    except Exception:  # noqa: BLE001 - optional dependency/no-op behavior
        return nullcontext()


def observe_operation(
    component: str,
    duration_ms: float,
    status: str,
    attributes: dict[str, Any] | None = None,
) -> None:
    """Record one low-cardinality operation without affecting the application."""
    if _operation_count is None or _operation_duration is None:
        return
    labels = {
        "opendevops.component": component,
        "opendevops.status": status,
        **(attributes or {}),
    }
    try:
        _operation_count.add(1, labels)
        _operation_duration.record(max(0.0, duration_ms), labels)
    except Exception:  # noqa: BLE001 - telemetry must never alter control flow
        logger.exception("could not record OpenTelemetry operation metrics")
