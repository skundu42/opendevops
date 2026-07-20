"""Tests for opendevops.models.pricing: cache-tier-aware usage_metadata -> USD."""

from __future__ import annotations

from pathlib import Path

import pytest
from langchain_core.messages import UsageMetadata

from opendevops.config import load_config
from opendevops.models.pricing import PriceTable, UnpricedModelError

REPO_ROOT = Path(__file__).resolve().parents[2]

OPUS = "anthropic:claude-opus-4-8"


@pytest.fixture
def price_table() -> PriceTable:
    cfg = load_config(REPO_ROOT)
    return PriceTable.from_config(cfg.models)


def test_exact_formula_with_cache_tiers(price_table: PriceTable) -> None:
    """input=10_000, cache_read=6_000, cache_creation=1_000, output=2_000 on opus pricing.

    opus pricing (config/models.yaml): input=5.00, output=25.00, cache_read=0.50,
    cache_write=6.25 (USD / MTok).

    uncached = 10_000 - 6_000 - 1_000 = 3_000
    usd = (3_000*5.00 + 6_000*0.50 + 1_000*6.25 + 2_000*25.00) / 1e6
        = (15_000 + 3_000 + 6_250 + 50_000) / 1e6
        = 74_250 / 1e6
        = 0.07425
    """
    usage: UsageMetadata = {
        "input_tokens": 10_000,
        "output_tokens": 2_000,
        "total_tokens": 12_000,
        "input_token_details": {"cache_read": 6_000, "cache_creation": 1_000},
    }
    usd = price_table.cost_usd(OPUS, usage)
    assert usd == 0.07425


def test_missing_input_token_details_treats_cache_as_zero(price_table: PriceTable) -> None:
    """No input_token_details ⇒ cache_read=cache_creation=0 ⇒ uncached == input_tokens."""
    usage: UsageMetadata = {
        "input_tokens": 1_000,
        "output_tokens": 500,
        "total_tokens": 1_500,
    }
    usd = price_table.cost_usd(OPUS, usage)
    expected = (1_000 * 5.00 + 500 * 25.00) / 1e6
    assert usd == expected


def test_unknown_model_raises_unpriced_model_error(price_table: PriceTable) -> None:
    usage: UsageMetadata = {"input_tokens": 100, "output_tokens": 10, "total_tokens": 110}
    with pytest.raises(UnpricedModelError):
        price_table.cost_usd("anthropic:does-not-exist", usage)


def test_negative_uncached_clamps_to_zero(price_table: PriceTable, caplog) -> None:
    """cache_read + cache_creation > input_tokens (defensive/adversarial input) clamps at 0."""
    usage: UsageMetadata = {
        "input_tokens": 100,
        "output_tokens": 10,
        "total_tokens": 110,
        "input_token_details": {"cache_read": 80, "cache_creation": 50},
    }
    with caplog.at_level("WARNING"):
        usd = price_table.cost_usd(OPUS, usage)
    # uncached clamped to 0 -> usd is purely cache_read + cache_creation + output cost
    expected = (80 * 0.50 + 50 * 6.25 + 10 * 25.00) / 1e6
    assert usd == expected
    assert any("negative" in rec.message.lower() for rec in caplog.records)


def test_from_config_builds_table_for_all_shipped_pricing_rows() -> None:
    cfg = load_config(REPO_ROOT)
    table = PriceTable.from_config(cfg.models)
    for model_key in cfg.models.pricing:
        usage: UsageMetadata = {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}
        # Should not raise UnpricedModelError for any shipped pricing row.
        table.cost_usd(model_key, usage)
