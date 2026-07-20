"""Tests for opendevops.budget: CostCap/DailyBudget middleware + DailyCounter.

Covers (per task brief):
  * exact per-call accumulation math against the real shipped PriceTable;
  * ordering-immunity of the state reducers (`_add_cost`, `_merge_usage` commute);
  * per-run trip firing at exactly `trip_ratio * profile.usd`, jump return shape, notice;
  * missing usage_metadata counted as `usage_missing` (never raises);
  * DailyCounter add/total round-trip, UTC-date keying, ON CONFLICT accumulation,
    persistence across instances, per-principal vs global independence;
  * daily caps (global + per-principal) fire independently;
  * fail-closed: counter outage in `before` jumps (counter_outage); outage in `after`
    continues the run and sets the `counter_write_failed` flag.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage, UsageMetadata

from opendevops.budget import (
    CostCapMiddleware,
    DailyBudgetMiddleware,
    InMemoryDailyCounter,
    SqliteDailyCounter,
)
from opendevops.budget import daily as daily_mod
from opendevops.budget.middleware import _add_cost, _merge_usage
from opendevops.config import BudgetsConfig, load_config
from opendevops.models.pricing import PriceTable

REPO_ROOT = Path(__file__).resolve().parents[2]
OPUS = "anthropic:claude-opus-4-8"

# A known usage fixture -> a known cost on opus pricing (see test_pricing.py).
KNOWN_USAGE: UsageMetadata = {
    "input_tokens": 10_000,
    "output_tokens": 2_000,
    "total_tokens": 12_000,
    "input_token_details": {"cache_read": 6_000, "cache_creation": 1_000},
}


# --------------------------------------------------------------------------------------
# fixtures / fakes
# --------------------------------------------------------------------------------------


@pytest.fixture
def price_table() -> PriceTable:
    return PriceTable.from_config(load_config(REPO_ROOT).models)


@pytest.fixture
def budgets() -> BudgetsConfig:
    return load_config(REPO_ROOT).budgets


@dataclass
class FakeContext:
    principal: str = "alice"


@dataclass
class FakeProfileContext:
    """A runtime context carrying a per-run budget profile (per-profile cap resolution)."""

    budget_profile: str
    principal: str = "alice"


@dataclass
class FakeRuntime:
    context: Any = None


def runtime(principal: str = "alice") -> FakeRuntime:
    return FakeRuntime(context=FakeContext(principal=principal))


def runtime_profile(name: str) -> FakeRuntime:
    return FakeRuntime(context=FakeProfileContext(budget_profile=name))


def ai(usage: UsageMetadata | None) -> AIMessage:
    return AIMessage(content="ok", usage_metadata=usage)


def state_with(*messages: Any) -> dict[str, Any]:
    return {"messages": list(messages)}


class StubCounter:
    """A DailyCounter with preset per-scope totals; records adds."""

    def __init__(self, totals: dict[str, float] | None = None) -> None:
        self.totals: dict[str, float] = dict(totals or {})
        self.added: list[tuple[str, float]] = []

    async def total(self, scope: str) -> float:
        return self.totals.get(scope, 0.0)

    async def add(self, scope: str, usd: float) -> float:
        self.added.append((scope, usd))
        self.totals[scope] = self.totals.get(scope, 0.0) + usd
        return self.totals[scope]


class RaisingCounter:
    """A DailyCounter that raises on the configured operation ('total', 'add', 'both')."""

    def __init__(self, raise_on: str) -> None:
        self.raise_on = raise_on

    async def total(self, scope: str) -> float:
        if self.raise_on in ("total", "both"):
            raise RuntimeError("counter down")
        return 0.0

    async def add(self, scope: str, usd: float) -> float:
        if self.raise_on in ("add", "both"):
            raise RuntimeError("counter down")
        return usd


# --------------------------------------------------------------------------------------
# reducers (pure functions — ordering-immunity)
# --------------------------------------------------------------------------------------


def test_add_cost_reducer_handles_missing_left() -> None:
    assert _add_cost(None, 0.1) == pytest.approx(0.1)
    assert _add_cost(0.1, 0.2) == pytest.approx(0.3)


def test_add_cost_reducer_commutes() -> None:
    assert _add_cost(0.1, 0.2) == pytest.approx(_add_cost(0.2, 0.1))


def test_merge_usage_sums_numbers_and_ors_flags() -> None:
    a = {"input_tokens": 10, "usage_missing": 1}
    b = {"input_tokens": 5, "counter_write_failed": True}
    merged = _merge_usage(a, b)
    assert merged["input_tokens"] == 15
    assert merged["usage_missing"] == 1
    assert merged["counter_write_failed"] is True


def test_merge_usage_commutes() -> None:
    a = {"input_tokens": 10, "counter_write_failed": True}
    b = {"input_tokens": 5, "usage_missing": 2}
    assert _merge_usage(a, b) == _merge_usage(b, a)


def test_merge_usage_does_not_mutate_inputs() -> None:
    a = {"input_tokens": 10}
    b = {"input_tokens": 5}
    _merge_usage(a, b)
    assert a == {"input_tokens": 10}
    assert b == {"input_tokens": 5}


# --------------------------------------------------------------------------------------
# CostCapMiddleware.aafter_model — stateless per-call accounting
# --------------------------------------------------------------------------------------


async def test_after_model_accumulates_exact_cost(
    price_table: PriceTable, budgets: BudgetsConfig
) -> None:
    mw = CostCapMiddleware(
        price_table, OPUS, {"default": budgets.profile("interactive")}, budgets.trip_ratio
    )
    st = state_with(HumanMessage(content="hi"), ai(KNOWN_USAGE))
    out = await mw.aafter_model(st, runtime())
    assert out is not None
    expected = price_table.cost_usd(OPUS, KNOWN_USAGE)
    assert out["run_cost_usd"] == pytest.approx(expected)
    usage = out["run_usage"]
    assert usage["input_tokens"] == 10_000
    assert usage["output_tokens"] == 2_000
    assert usage["cache_read"] == 6_000
    assert usage["cache_creation"] == 1_000
    assert usage["usage_missing"] == 0


async def test_after_model_returns_per_call_delta_not_total(
    price_table: PriceTable, budgets: BudgetsConfig
) -> None:
    """Ordering-immunity: the hook returns THIS call's cost; the reducer accumulates."""
    mw = CostCapMiddleware(
        price_table, OPUS, {"default": budgets.profile("interactive")}, budgets.trip_ratio
    )
    st = state_with(ai(KNOWN_USAGE))
    st["run_cost_usd"] = 99.0  # prior accumulated total must NOT leak into the delta
    out = await mw.aafter_model(st, runtime())
    assert out is not None
    assert out["run_cost_usd"] == pytest.approx(price_table.cost_usd(OPUS, KNOWN_USAGE))


async def test_after_model_missing_usage_counts_usage_missing(
    price_table: PriceTable, budgets: BudgetsConfig
) -> None:
    mw = CostCapMiddleware(
        price_table, OPUS, {"default": budgets.profile("interactive")}, budgets.trip_ratio
    )
    out = await mw.aafter_model(state_with(ai(None)), runtime())
    assert out is not None
    assert out["run_cost_usd"] == pytest.approx(0.0)
    assert out["run_usage"]["usage_missing"] == 1


async def test_after_model_sums_multiple_new_ai_messages(
    price_table: PriceTable, budgets: BudgetsConfig
) -> None:
    mw = CostCapMiddleware(
        price_table, OPUS, {"default": budgets.profile("interactive")}, budgets.trip_ratio
    )
    st = state_with(HumanMessage(content="hi"), ai(KNOWN_USAGE), ai(KNOWN_USAGE))
    out = await mw.aafter_model(st, runtime())
    assert out is not None
    assert out["run_cost_usd"] == pytest.approx(2 * price_table.cost_usd(OPUS, KNOWN_USAGE))
    assert out["run_usage"]["input_tokens"] == 20_000


async def test_after_model_only_counts_trailing_ai_run(
    price_table: PriceTable, budgets: BudgetsConfig
) -> None:
    """A prior AIMessage separated by a ToolMessage belongs to an earlier call — not counted."""
    mw = CostCapMiddleware(
        price_table, OPUS, {"default": budgets.profile("interactive")}, budgets.trip_ratio
    )
    st = state_with(
        ai(KNOWN_USAGE),  # earlier call, already accounted
        ToolMessage(content="result", tool_call_id="t1"),
        ai(KNOWN_USAGE),  # the new call
    )
    out = await mw.aafter_model(st, runtime())
    assert out is not None
    assert out["run_cost_usd"] == pytest.approx(price_table.cost_usd(OPUS, KNOWN_USAGE))


async def test_after_model_never_raises_on_unpriced_model(budgets: BudgetsConfig) -> None:
    """Belt-and-braces: an unpriced key must not blow up a live run; counted as a blind spot."""
    empty = PriceTable(prices={})
    mw = CostCapMiddleware(
        empty, OPUS, {"default": budgets.profile("interactive")}, budgets.trip_ratio
    )
    out = await mw.aafter_model(state_with(ai(KNOWN_USAGE)), runtime())
    assert out is not None
    assert out["run_cost_usd"] == pytest.approx(0.0)
    assert out["run_usage"]["usage_missing"] == 1


# --------------------------------------------------------------------------------------
# CostCapMiddleware.abefore_model — per-run trip
# --------------------------------------------------------------------------------------


async def test_before_model_trips_at_exactly_90pct(
    price_table: PriceTable, budgets: BudgetsConfig
) -> None:
    profile = budgets.profile("interactive")  # usd == 5.00, trip_ratio == 0.9 -> 4.50
    mw = CostCapMiddleware(price_table, OPUS, {"default": profile}, budgets.trip_ratio)
    threshold = budgets.trip_ratio * profile.usd
    st = state_with(HumanMessage(content="hi"))
    st["run_cost_usd"] = threshold
    out = await mw.abefore_model(st, runtime())
    assert out is not None
    assert out["jump_to"] == "end"
    assert out["budget_stop"] == {
        "kind": "per_run_usd",
        "spent": pytest.approx(threshold),
        "cap": pytest.approx(profile.usd),
    }
    assert len(out["messages"]) == 1
    assert isinstance(out["messages"][0], AIMessage)
    assert "Budget cap reached" in out["messages"][0].content


async def test_before_model_under_cap_returns_none(
    price_table: PriceTable, budgets: BudgetsConfig
) -> None:
    profile = budgets.profile("interactive")
    mw = CostCapMiddleware(price_table, OPUS, {"default": profile}, budgets.trip_ratio)
    st = state_with(HumanMessage(content="hi"))
    st["run_cost_usd"] = budgets.trip_ratio * profile.usd - 0.01  # just under threshold
    assert await mw.abefore_model(st, runtime()) is None


async def test_before_model_empty_state_returns_none(
    price_table: PriceTable, budgets: BudgetsConfig
) -> None:
    mw = CostCapMiddleware(
        price_table, OPUS, {"default": budgets.profile("interactive")}, budgets.trip_ratio
    )
    assert await mw.abefore_model(state_with(), runtime()) is None


# --------------------------------------------------------------------------------------
# CostCapMiddleware — per-run profile resolution from runtime.context
# --------------------------------------------------------------------------------------


async def test_before_model_resolves_cap_per_profile(
    price_table: PriceTable, budgets: BudgetsConfig
) -> None:
    """The SAME middleware trips at different spends depending on ``context.budget_profile``.

    ``scheduled`` (usd 2.00 -> threshold 1.80) trips at a $5 spend; ``incident`` (usd 10.00 ->
    threshold 9.00) does not — the effective cap is resolved per run, not frozen at construction.
    """
    profiles = {
        "default": budgets.profile("default"),
        "scheduled": budgets.profile("scheduled"),  # usd 2.00
        "incident": budgets.profile("incident"),  # usd 10.00
    }
    mw = CostCapMiddleware(price_table, OPUS, profiles, budgets.trip_ratio)
    st = state_with(HumanMessage(content="hi"))
    st["run_cost_usd"] = 5.0  # between scheduled's 1.80 and incident's 9.00 thresholds

    tripped = await mw.abefore_model(st, runtime_profile("scheduled"))
    assert tripped is not None
    assert tripped["jump_to"] == "end"
    assert tripped["budget_stop"]["cap"] == pytest.approx(2.0)

    assert await mw.abefore_model(st, runtime_profile("incident")) is None


async def test_before_model_unknown_or_missing_profile_falls_back_to_default(
    price_table: PriceTable, budgets: BudgetsConfig, caplog: pytest.LogCaptureFixture
) -> None:
    """An absent/unknown ``budget_profile`` resolves to ``default`` (fail-safe, never crashes).

    The silent fallback is now observable: it log-warns the unknown/absent profile name and the
    profile it fell back to, so a misconfigured context is diagnosable.
    """
    profiles = {"default": budgets.profile("default")}  # usd 2.00 -> threshold 1.80
    mw = CostCapMiddleware(price_table, OPUS, profiles, budgets.trip_ratio)
    st = state_with()
    st["run_cost_usd"] = 1.9  # over the default threshold

    # context names a profile absent from the map -> default cap applies -> trips (+ warns).
    with caplog.at_level(logging.WARNING, logger="opendevops.budget.middleware"):
        unknown = await mw.abefore_model(st, runtime_profile("ghost"))
    assert unknown is not None and unknown["budget_stop"]["cap"] == pytest.approx(2.0)
    assert any(
        rec.levelno == logging.WARNING
        and "ghost" in rec.getMessage()
        and "default" in rec.getMessage()
        for rec in caplog.records
    ), "expected a fallback warning naming the unknown profile 'ghost' and the 'default' fallback"

    # context missing entirely (no budget_profile) -> default cap applies -> trips (+ warns None).
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="opendevops.budget.middleware"):
        missing = await mw.abefore_model(st, FakeRuntime(context=None))
    assert missing is not None and missing["budget_stop"]["cap"] == pytest.approx(2.0)
    assert any(
        rec.levelno == logging.WARNING and "None" in rec.getMessage()
        for rec in caplog.records
    ), "expected a fallback warning for an absent budget_profile (name None)"


# --------------------------------------------------------------------------------------
# DailyCounter implementations
# --------------------------------------------------------------------------------------


async def test_inmemory_add_total_roundtrip() -> None:
    c = InMemoryDailyCounter()
    assert await c.total("global") == pytest.approx(0.0)
    assert await c.add("global", 1.5) == pytest.approx(1.5)
    assert await c.add("global", 0.5) == pytest.approx(2.0)
    assert await c.total("global") == pytest.approx(2.0)


async def test_sqlite_add_total_roundtrip(tmp_path: Path) -> None:
    c = SqliteDailyCounter(tmp_path / "spend.db")
    assert await c.total("global") == pytest.approx(0.0)
    assert await c.add("global", 2.5) == pytest.approx(2.5)
    assert await c.total("global") == pytest.approx(2.5)


async def test_sqlite_on_conflict_accumulates(tmp_path: Path) -> None:
    c = SqliteDailyCounter(tmp_path / "spend.db")
    await c.add("global", 1.0)
    await c.add("global", 2.0)
    await c.add("global", 0.25)
    assert await c.total("global") == pytest.approx(3.25)


async def test_sqlite_persists_across_instances(tmp_path: Path) -> None:
    path = tmp_path / "spend.db"
    await SqliteDailyCounter(path).add("principal:bob", 4.0)
    # A fresh instance against the same file sees the prior spend.
    assert await SqliteDailyCounter(path).total("principal:bob") == pytest.approx(4.0)


async def test_counter_uses_utc_date_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    c = SqliteDailyCounter(tmp_path / "spend.db")
    monkeypatch.setattr(daily_mod, "_utc_day", lambda: "2026-07-18")
    await c.add("global", 5.0)
    assert await c.total("global") == pytest.approx(5.0)
    # Roll the (UTC) day: the previous day's spend must not carry over.
    monkeypatch.setattr(daily_mod, "_utc_day", lambda: "2026-07-19")
    assert await c.total("global") == pytest.approx(0.0)
    await c.add("global", 1.0)
    assert await c.total("global") == pytest.approx(1.0)


async def test_scopes_are_independent(tmp_path: Path) -> None:
    c = SqliteDailyCounter(tmp_path / "spend.db")
    await c.add("global", 10.0)
    await c.add("principal:alice", 3.0)
    assert await c.total("global") == pytest.approx(10.0)
    assert await c.total("principal:alice") == pytest.approx(3.0)
    assert await c.total("principal:bob") == pytest.approx(0.0)


def test_sqlite_uses_wal_mode(tmp_path: Path) -> None:
    import sqlite3

    path = tmp_path / "spend.db"
    SqliteDailyCounter(path)._ensure_schema_sync()
    conn = sqlite3.connect(str(path))
    try:
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
    finally:
        conn.close()
    assert mode.lower() == "wal"


def test_sqlite_sets_busy_timeout(tmp_path: Path) -> None:
    """Every connection waits up to 5s for a competing writer's lock instead of erroring at once."""
    conn = SqliteDailyCounter(tmp_path / "spend.db")._connect()
    try:
        timeout = conn.execute("PRAGMA busy_timeout").fetchone()[0]
    finally:
        conn.close()
    assert timeout == 5000


# --------------------------------------------------------------------------------------
# DailyBudgetMiddleware
# --------------------------------------------------------------------------------------


async def test_daily_before_model_under_cap_returns_none(
    price_table: PriceTable, budgets: BudgetsConfig
) -> None:
    mw = DailyBudgetMiddleware(price_table, OPUS, StubCounter(), budgets.daily)
    assert await mw.abefore_model(state_with(), runtime()) is None


async def test_daily_before_model_trips_on_global(
    price_table: PriceTable, budgets: BudgetsConfig
) -> None:
    counter = StubCounter({"global": budgets.daily.global_usd})
    mw = DailyBudgetMiddleware(price_table, OPUS, counter, budgets.daily)
    out = await mw.abefore_model(state_with(), runtime("alice"))
    assert out is not None
    assert out["jump_to"] == "end"
    assert out["budget_stop"]["kind"] == "daily_usd"
    assert out["budget_stop"]["scope"] == "global"
    assert "Budget cap reached" in out["messages"][0].content


async def test_daily_before_model_trips_on_principal(
    price_table: PriceTable, budgets: BudgetsConfig
) -> None:
    counter = StubCounter({"principal:alice": budgets.daily.per_principal_usd})
    mw = DailyBudgetMiddleware(price_table, OPUS, counter, budgets.daily)
    out = await mw.abefore_model(state_with(), runtime("alice"))
    assert out is not None
    assert out["budget_stop"]["kind"] == "daily_usd"
    assert out["budget_stop"]["scope"] == "principal:alice"


async def test_daily_principal_cap_independent_of_global(
    price_table: PriceTable, budgets: BudgetsConfig
) -> None:
    """A different principal under its own cap is unaffected by alice's spend."""
    counter = StubCounter({"principal:alice": budgets.daily.per_principal_usd})
    mw = DailyBudgetMiddleware(price_table, OPUS, counter, budgets.daily)
    assert await mw.abefore_model(state_with(), runtime("bob")) is None


async def test_daily_after_model_charges_both_scopes(
    price_table: PriceTable, budgets: BudgetsConfig
) -> None:
    counter = StubCounter()
    mw = DailyBudgetMiddleware(price_table, OPUS, counter, budgets.daily)
    out = await mw.aafter_model(state_with(ai(KNOWN_USAGE)), runtime("alice"))
    assert out is None  # happy path adds no state
    cost = price_table.cost_usd(OPUS, KNOWN_USAGE)
    assert counter.added == [
        ("global", pytest.approx(cost)),
        ("principal:alice", pytest.approx(cost)),
    ]


async def test_daily_after_model_skips_when_no_usage(
    price_table: PriceTable, budgets: BudgetsConfig
) -> None:
    counter = StubCounter()
    mw = DailyBudgetMiddleware(price_table, OPUS, counter, budgets.daily)
    out = await mw.aafter_model(state_with(ai(None)), runtime("alice"))
    assert out is None
    assert counter.added == []


async def test_daily_counter_outage_before_fails_closed(
    price_table: PriceTable, budgets: BudgetsConfig
) -> None:
    mw = DailyBudgetMiddleware(price_table, OPUS, RaisingCounter("total"), budgets.daily)
    out = await mw.abefore_model(state_with(), runtime("alice"))
    assert out is not None
    assert out["jump_to"] == "end"
    assert out["budget_stop"]["kind"] == "counter_outage"
    assert len(out["messages"]) == 1


async def test_daily_counter_outage_before_fail_open_continues(
    price_table: PriceTable, budgets: BudgetsConfig
) -> None:
    mw = DailyBudgetMiddleware(
        price_table, OPUS, RaisingCounter("total"), budgets.daily, fail_mode="open"
    )
    assert await mw.abefore_model(state_with(), runtime("alice")) is None


async def test_daily_counter_outage_after_continues_and_flags(
    price_table: PriceTable, budgets: BudgetsConfig
) -> None:
    mw = DailyBudgetMiddleware(price_table, OPUS, RaisingCounter("add"), budgets.daily)
    out = await mw.aafter_model(state_with(ai(KNOWN_USAGE)), runtime("alice"))
    assert out is not None
    assert out["run_usage"]["counter_write_failed"] is True


async def test_daily_principal_from_missing_context_defaults(
    price_table: PriceTable, budgets: BudgetsConfig
) -> None:
    """No context principal must not crash; a stable fallback scope is used."""
    counter = StubCounter()
    mw = DailyBudgetMiddleware(price_table, OPUS, counter, budgets.daily)
    out = await mw.aafter_model(state_with(ai(KNOWN_USAGE)), FakeRuntime(context=None))
    assert out is None
    scopes = [scope for scope, _ in counter.added]
    assert "global" in scopes
    assert any(s.startswith("principal:") for s in scopes)


async def test_daily_principal_getter_override(
    price_table: PriceTable, budgets: BudgetsConfig
) -> None:
    counter = StubCounter()
    mw = DailyBudgetMiddleware(
        price_table, OPUS, counter, budgets.daily, principal_getter=lambda _rt: "svc-account"
    )
    await mw.aafter_model(state_with(ai(KNOWN_USAGE)), FakeRuntime(context=None))
    assert ("principal:svc-account", pytest.approx(price_table.cost_usd(OPUS, KNOWN_USAGE))) in [
        (s, c) for s, c in counter.added
    ]
