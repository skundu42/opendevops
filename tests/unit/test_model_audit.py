"""Content-free model telemetry is correlated into the run audit chain."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

from langchain.agents.middleware.types import ModelResponse
from langchain_core.messages import AIMessage

from opendevops.audit import AuditLogger
from opendevops.audit.schema import AuditEvent, EventType
from opendevops.config import load_config
from opendevops.models.pricing import PriceTable
from opendevops.observability.model_audit import ModelAuditMiddleware

REPO_ROOT = Path(__file__).resolve().parents[2]


async def test_model_call_records_timing_usage_and_cost_without_content(tmp_path: Path) -> None:
    audit = AuditLogger(tmp_path)
    audit.start_run(
        "run-model",
        principal={"interface": "http", "user": "operator"},
        environment="staging",
    )
    cfg = load_config(REPO_ROOT)
    middleware = ModelAuditMiddleware(
        audit,
        PriceTable.from_config(cfg.models),
        cfg.models.resolve("main"),
        "sha256:policy",
    )
    request = SimpleNamespace(
        state={"run_cost_usd": 0.25},
        runtime=SimpleNamespace(
            context=SimpleNamespace(
                run_id="run-model",
                principal="operator",
                interface="http",
                environment="staging",
            )
        ),
    )

    async def handler(_request: Any) -> ModelResponse[Any]:
        return ModelResponse(
            result=[
                AIMessage(
                    content="sensitive model response",
                    usage_metadata={
                        "input_tokens": 100,
                        "output_tokens": 20,
                        "total_tokens": 120,
                    },
                )
            ]
        )

    await middleware.awrap_model_call(request, handler)
    events = [
        AuditEvent.model_validate_json(line)
        for line in (tmp_path / "run-model.jsonl").read_text().splitlines()
    ]
    model_event = next(event for event in events if event.event_type is EventType.model_call)

    assert model_event.summary is not None
    assert model_event.summary["duration_ms"] >= 0
    assert model_event.summary["usage"]["input_tokens"] == 100
    assert model_event.summary["cost_before"] == 0.25
    assert "sensitive model response" not in model_event.model_dump_json()
