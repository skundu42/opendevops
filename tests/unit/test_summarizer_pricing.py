"""Invocation-local summarizer spend + awrap flush (not abefore_model)."""

from __future__ import annotations

import asyncio
from contextvars import copy_context
from typing import Any
from unittest.mock import MagicMock

import pytest
from langchain.agents.middleware.types import ExtendedModelResponse, ModelResponse
from langchain_core.messages import AIMessage
from langgraph.types import Command

from opendevops.agent import (
    _clear_pending_spend,
    _get_pending_spend,
    _HaikuSummarizationMiddleware,
    _take_pending_spend,
)
from opendevops.budget.daily import InMemoryDailyCounter
from opendevops.config import ModelPricing
from opendevops.models.pricing import PriceTable


def _middleware(*, counter: InMemoryDailyCounter | None = None) -> _HaikuSummarizationMiddleware:
    mw = object.__new__(_HaikuSummarizationMiddleware)
    mw._price_table = PriceTable(
        prices={
            "anthropic:claude-haiku-4-5-20251001": ModelPricing(
                input=1.0, output=5.0, cache_read=0.1, cache_write=1.25
            )
        }
    )
    mw._summarizer_model_key = "anthropic:claude-haiku-4-5-20251001"
    mw._price_index = None
    mw._daily_counter = counter
    return mw


def _usage_msg(*, input_tokens: int) -> AIMessage:
    return AIMessage(
        content="SUMMARY",
        usage_metadata={
            "input_tokens": input_tokens,
            "output_tokens": 0,
            "total_tokens": input_tokens,
        },
    )


def test_pending_spend_is_context_local() -> None:
    _clear_pending_spend()
    mw = _middleware()

    def _worker(tokens: int) -> float:
        _clear_pending_spend()
        mw._note_summary_usage(_usage_msg(input_tokens=tokens))
        pending = _take_pending_spend()
        assert pending is not None
        return pending.cost_usd

    a = copy_context().run(_worker, 1_000_000)
    b = copy_context().run(_worker, 2_000_000)
    assert a == pytest.approx(1.0)
    assert b == pytest.approx(2.0)
    assert _take_pending_spend() is None


@pytest.mark.asyncio
async def test_awrap_flushes_pending_into_extended_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_pending_spend()
    counter = InMemoryDailyCounter()
    mw = _middleware(counter=counter)

    async def _parent(self: Any, request: Any, handler: Any) -> ModelResponse:
        mw._note_summary_usage(_usage_msg(input_tokens=2_000_000))
        return ModelResponse(result=[AIMessage(content="main")])

    monkeypatch.setattr(
        _HaikuSummarizationMiddleware.__bases__[0],
        "awrap_model_call",
        _parent,
    )
    runtime = MagicMock()
    runtime.context = MagicMock(principal="alice")
    result = await mw.awrap_model_call(MagicMock(runtime=runtime), handler=MagicMock())
    _clear_pending_spend()

    assert isinstance(result, ExtendedModelResponse)
    assert result.command is not None
    assert result.command.update["run_cost_usd"] == pytest.approx(2.0)
    assert await counter.total("global") == pytest.approx(2.0)
    assert await counter.total("principal:alice") == pytest.approx(2.0)
    assert _take_pending_spend() is None


@pytest.mark.asyncio
async def test_pending_bucket_visible_across_asyncio_gather_child() -> None:
    """Child tasks from gather see the pre-created mutable pending bucket."""
    _clear_pending_spend()
    mw = _middleware()
    _get_pending_spend()  # parent materialises the bucket (as awrap does)

    async def _child() -> None:
        mw._note_summary_usage(_usage_msg(input_tokens=1_000_000))

    await asyncio.gather(_child())
    pending = _take_pending_spend()
    assert pending is not None
    assert pending.cost_usd == pytest.approx(1.0)


@pytest.mark.asyncio
async def test_awrap_merges_into_existing_summarization_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_pending_spend()
    mw = _middleware()

    async def _parent(self: Any, request: Any, handler: Any) -> ExtendedModelResponse:
        mw._note_summary_usage(_usage_msg(input_tokens=1_000_000))
        return ExtendedModelResponse(
            model_response=ModelResponse(result=[AIMessage(content="main")]),
            command=Command(update={"_summarization_event": {"cutoff_index": 1}}),
        )

    monkeypatch.setattr(
        _HaikuSummarizationMiddleware.__bases__[0],
        "awrap_model_call",
        _parent,
    )
    result = await mw.awrap_model_call(MagicMock(runtime=MagicMock()), handler=MagicMock())
    _clear_pending_spend()

    assert isinstance(result, ExtendedModelResponse)
    assert result.command is not None
    assert result.command.update["_summarization_event"]["cutoff_index"] == 1
    assert result.command.update["run_cost_usd"] == pytest.approx(1.0)
