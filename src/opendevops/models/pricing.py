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
from typing import Any, TypeAlias

from langchain_core.messages import AIMessage, UsageMetadata

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


def build_price_key_index(prices: dict[str, Any] | PriceTable) -> dict[str, str]:
    """Index each priced ``provider:model`` key by itself and by a *unique* bare model suffix.

    When two providers price the same bare model (e.g. ``openai:gpt-4o`` and ``azure:gpt-4o``),
    the bare suffix is omitted from the index so callers cannot silently pick the first insert.
    Disambiguate via :func:`resolve_price_key`'s ``default_model_key`` provider prefix instead.
    """
    keys = prices.prices if isinstance(prices, PriceTable) else prices
    index: dict[str, str] = {}
    ambiguous_suffixes: set[str] = set()
    for key in keys:
        index[key] = key
        _, _, suffix = key.partition(":")
        if not suffix or suffix in ambiguous_suffixes:
            continue
        existing = index.get(suffix)
        if existing is not None and existing != key:
            del index[suffix]
            ambiguous_suffixes.add(suffix)
            continue
        index.setdefault(suffix, key)
    return index


def resolve_price_key(
    model_name: str,
    prices: dict[str, Any] | PriceTable,
    *,
    index: dict[str, str] | None = None,
    default_model_key: str | None = None,
) -> str | None:
    """Map a reported model name to a priced ``provider:model`` key, or ``None`` if unknown.

    Resolution order: exact ``provider:model`` hit → unique bare-suffix index hit →
    ``{default_provider}:{bare}`` when ``default_model_key`` is set and that row exists.
    Ambiguous bare names without a matching default-provider row return ``None`` (caller
    falls back to pricing with the default key explicitly).
    """
    table = prices.prices if isinstance(prices, PriceTable) else prices
    if model_name in table:
        return model_name
    lookup = index if index is not None else build_price_key_index(prices)
    hit = lookup.get(model_name)
    if hit is not None:
        return hit
    if default_model_key and ":" not in model_name:
        provider, _, _ = default_model_key.partition(":")
        if provider:
            candidate = f"{provider}:{model_name}"
            if candidate in table:
                return candidate
    return None


def reported_model_name(message: AIMessage) -> str | None:
    """Best-effort model id from an ``AIMessage``'s ``response_metadata`` / ``name``."""
    meta = getattr(message, "response_metadata", None) or {}
    if isinstance(meta, dict):
        for key in ("model_name", "model", "model_id"):
            value = meta.get(key)
            if isinstance(value, str) and value:
                return value
    name = getattr(message, "name", None)
    return name if isinstance(name, str) and name else None


def price_message(
    message: AIMessage,
    price_table: PriceTable,
    *,
    default_model_key: str,
    index: dict[str, str] | None = None,
) -> tuple[float, str, bool]:
    """Price one AIMessage: ``(usd, model_key_used, used_default_fallback)``.

    Prefers the message's reported model name when it maps to a priced row; otherwise falls
    back to ``default_model_key`` (typically the main agent). Raises ``UnpricedModelError``
    only when the chosen key itself has no row.
    """
    usage = message.usage_metadata
    if not usage:
        return 0.0, default_model_key, False
    reported = reported_model_name(message)
    used_default = False
    if reported:
        resolved = resolve_price_key(
            reported,
            price_table,
            index=index,
            default_model_key=default_model_key,
        )
        if resolved is not None:
            return price_table.cost_usd(resolved, usage), resolved, False
        used_default = True
    return price_table.cost_usd(default_model_key, usage), default_model_key, used_default
