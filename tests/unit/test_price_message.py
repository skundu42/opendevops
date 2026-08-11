"""Per-call price key resolution from AIMessage metadata."""

from __future__ import annotations

import pytest
from langchain_core.messages import AIMessage

from opendevops.config import ModelPricing
from opendevops.models.pricing import (
    PriceTable,
    build_price_key_index,
    price_message,
    resolve_price_key,
)


def _table() -> PriceTable:
    return PriceTable(
        prices={
            "anthropic:claude-opus-4-8": ModelPricing(
                input=5.0, output=25.0, cache_read=0.5, cache_write=6.25
            ),
            "anthropic:claude-haiku-4-5-20251001": ModelPricing(
                input=1.0, output=5.0, cache_read=0.1, cache_write=1.25
            ),
        }
    )


def test_price_message_uses_reported_model() -> None:
    table = _table()
    index = build_price_key_index(table)
    msg = AIMessage(
        content="ok",
        usage_metadata={
            "input_tokens": 1_000_000,
            "output_tokens": 0,
            "total_tokens": 1_000_000,
        },
        response_metadata={"model_name": "claude-haiku-4-5-20251001"},
    )
    cost, key, used_default = price_message(
        msg, table, default_model_key="anthropic:claude-opus-4-8", index=index
    )
    assert key == "anthropic:claude-haiku-4-5-20251001"
    assert used_default is False
    assert cost == pytest.approx(1.0)


def test_price_message_falls_back_to_default() -> None:
    table = _table()
    msg = AIMessage(
        content="ok",
        usage_metadata={
            "input_tokens": 1_000_000,
            "output_tokens": 0,
            "total_tokens": 1_000_000,
        },
        response_metadata={"model_name": "unknown-model"},
    )
    cost, key, used_default = price_message(
        msg, table, default_model_key="anthropic:claude-opus-4-8"
    )
    assert key == "anthropic:claude-opus-4-8"
    assert used_default is True
    assert cost == pytest.approx(5.0)


def test_ambiguous_bare_suffix_omitted_from_index() -> None:
    table = PriceTable(
        prices={
            "openai:gpt-4o": ModelPricing(
                input=2.5, output=10.0, cache_read=0.0, cache_write=0.0
            ),
            "azure:gpt-4o": ModelPricing(
                input=5.0, output=15.0, cache_read=0.0, cache_write=0.0
            ),
        }
    )
    index = build_price_key_index(table)
    assert "gpt-4o" not in index
    assert index["openai:gpt-4o"] == "openai:gpt-4o"
    assert index["azure:gpt-4o"] == "azure:gpt-4o"


def test_ambiguous_bare_suffix_disambiguated_by_default_provider() -> None:
    table = PriceTable(
        prices={
            "openai:gpt-4o": ModelPricing(
                input=2.5, output=10.0, cache_read=0.0, cache_write=0.0
            ),
            "azure:gpt-4o": ModelPricing(
                input=5.0, output=15.0, cache_read=0.0, cache_write=0.0
            ),
        }
    )
    index = build_price_key_index(table)
    assert (
        resolve_price_key(
            "gpt-4o", table, index=index, default_model_key="azure:gpt-4o-mini"
        )
        == "azure:gpt-4o"
    )
    msg = AIMessage(
        content="ok",
        usage_metadata={
            "input_tokens": 1_000_000,
            "output_tokens": 0,
            "total_tokens": 1_000_000,
        },
        response_metadata={"model_name": "gpt-4o"},
    )
    cost, key, used_default = price_message(
        msg, table, default_model_key="openai:gpt-4o", index=index
    )
    assert key == "openai:gpt-4o"
    assert used_default is False
    assert cost == pytest.approx(2.5)
