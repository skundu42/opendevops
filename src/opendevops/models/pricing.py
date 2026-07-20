"""Cache-tier-aware conversion of AIMessage.usage_metadata to USD cost.

`Price` is the per-model, per-MTok price row already parsed and validated by
`opendevops.config.ModelsConfig` (an alias for `config.ModelPricing` — pricing.py does not
redefine it). `PriceTable` wraps `cfg.models.pricing` (keyed strictly by the `provider:model`
string from `models.yaml`, e.g. `"anthropic:claude-opus-4-8"`) and converts a langchain
`UsageMetadata` (the `TypedDict` on `AIMessage.usage_metadata`) into a USD float, cache-tier
aware.

Formula (see `PriceTable.cost_usd`)::

    uncached = input_tokens - cache_read - cache_creation        # clamped to >= 0
    usd = (uncached      * price.input
           + cache_read     * price.cache_read
           + cache_creation * price.cache_write
           + output_tokens  * price.output) / 1e6

A missing `input_token_details` block means the model/provider reported no cache usage, so
both `cache_read` and `cache_creation` are treated as `0` (`uncached == input_tokens`).

An unpriced model is an unmetered model: `cost_usd` raises `UnpricedModelError` for any
`model_key` absent from the table rather than silently defaulting to `0` USD — callers must
refuse to boot/proceed rather than run unmetered. `model_key` must already be a bare
`provider:model` string; resolving agent names/aliases to that form is `models.registry`'s
job, not pricing's (see registry.py's `resolve`).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TypeAlias

from langchain_core.messages import UsageMetadata

from opendevops.config import ModelPricing, ModelsConfig

logger = logging.getLogger(__name__)

# Per-MTok price row, already parsed/validated by config.py; pricing.py just consumes it.
Price: TypeAlias = ModelPricing


class UnpricedModelError(KeyError):
    """Raised when `cost_usd` is asked to price a `model_key` with no pricing row.

    An unpriced model is an unmetered model: callers must refuse to boot/proceed rather than
    default the cost to 0.
    """

    def __init__(self, model_key: str) -> None:
        self.model_key = model_key
        super().__init__(
            f"no pricing entry for model {model_key!r}; refusing to compute an unmetered cost "
            f"(an unpriced model is an unmetered model)"
        )

    def __str__(self) -> str:
        # KeyError.__str__ reprs a single-arg message (double-quoting it); return the plain
        # message instead so this reads cleanly wherever it's logged/printed.
        return str(self.args[0])


@dataclass(frozen=True)
class PriceTable:
    """USD-per-MTok price rows keyed by the literal `provider:model` string from models.yaml."""

    prices: dict[str, Price] = field(default_factory=dict)

    @classmethod
    def from_config(cls, models_cfg: ModelsConfig) -> PriceTable:
        """Build a `PriceTable` from `AppConfig.models` (`cfg.models`)."""
        return cls(prices=dict(models_cfg.pricing))

    def cost_usd(self, model_key: str, usage: UsageMetadata) -> float:
        """Convert one `AIMessage.usage_metadata` reading into a USD cost for `model_key`.

        Raises `UnpricedModelError` if `model_key` has no pricing row.
        """
        try:
            price = self.prices[model_key]
        except KeyError:
            raise UnpricedModelError(model_key) from None

        input_tokens = usage.get("input_tokens", 0)
        output_tokens = usage.get("output_tokens", 0)
        details = usage.get("input_token_details")
        cache_read = details.get("cache_read", 0) if details else 0
        cache_creation = details.get("cache_creation", 0) if details else 0

        uncached = input_tokens - cache_read - cache_creation
        if uncached < 0:
            logger.warning(
                "negative uncached token count for model %r (input_tokens=%d, cache_read=%d, "
                "cache_creation=%d); clamping to 0",
                model_key,
                input_tokens,
                cache_read,
                cache_creation,
            )
            uncached = 0

        return (
            uncached * price.input
            + cache_read * price.cache_read
            + cache_creation * price.cache_write
            + output_tokens * price.output
        ) / 1e6
