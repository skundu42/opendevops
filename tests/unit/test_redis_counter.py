"""RedisDailyCounter + the build_daily_counter factory.

The Redis counter is the shared, restart-surviving daily envelope for the service tier. These
tests drive it against ``fakeredis.aioredis`` (no live Redis) and assert it matches
:class:`SqliteDailyCounter`'s semantics exactly — UTC-day keying, add/total round-trip, per-scope +
per-date isolation, ``add`` returns the new total — plus the Redis-specific facts: a 48h TTL is set
and *anchored* to the key's first write (``EXPIRE ... NX``), float precision survives the
bytes/float reply parsing, a connection outage RAISES (fail-closed, never swallowed), and the
pre-Redis-7 ``NX``-unsupported server downgrades to an unconditional ``EXPIRE``.

The factory tests prove ``build_daily_counter`` selects sqlite vs redis per
``cfg.budgets.daily.backend`` and that the config validator refuses ``backend: redis`` with no url.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import fakeredis.aioredis
import pytest
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import ResponseError

from opendevops.budget import daily as daily_mod
from opendevops.budget.daily import (
    DAILY_LEDGER_FILE,
    RedisDailyCounter,
    SqliteDailyCounter,
    _to_float,
    build_daily_counter,
)
from opendevops.config import Daily, load_config

REPO_ROOT = Path(__file__).resolve().parents[2]

_EXPIRY = 48 * 60 * 60  # 172800


@pytest.fixture
def fake_redis() -> fakeredis.aioredis.FakeRedis:
    """A fresh, isolated fakeredis async client (its own server, so tests never share keys)."""
    return fakeredis.aioredis.FakeRedis(server=fakeredis.FakeServer())


# --------------------------------------------------------------------------------------
# _to_float — reply parsing (INCRBYFLOAT float / GET bytes / decoded str)
# --------------------------------------------------------------------------------------


def test_to_float_parses_bytes_str_and_float() -> None:
    assert _to_float(b"1.75") == pytest.approx(1.75)
    assert _to_float("2.5") == pytest.approx(2.5)
    assert _to_float(3.25) == pytest.approx(3.25)
    assert _to_float(4) == pytest.approx(4.0)


# --------------------------------------------------------------------------------------
# add / total round-trip + isolation (semantics parity with SqliteDailyCounter)
# --------------------------------------------------------------------------------------


async def test_add_total_roundtrip(fake_redis: fakeredis.aioredis.FakeRedis) -> None:
    c = RedisDailyCounter(fake_redis)
    assert await c.total("global") == pytest.approx(0.0)
    assert await c.add("global", 2.5) == pytest.approx(2.5)  # add returns the new total
    assert await c.add("global", 0.5) == pytest.approx(3.0)
    assert await c.total("global") == pytest.approx(3.0)


async def test_float_precision_accumulates(fake_redis: fakeredis.aioredis.FakeRedis) -> None:
    """INCRBYFLOAT accumulates on the server; the bytes/float reply parse preserves precision."""
    c = RedisDailyCounter(fake_redis)
    await c.add("global", 1.0)
    await c.add("global", 2.0)
    await c.add("global", 0.25)
    assert await c.total("global") == pytest.approx(3.25)


async def test_scopes_are_independent(fake_redis: fakeredis.aioredis.FakeRedis) -> None:
    c = RedisDailyCounter(fake_redis)
    await c.add("global", 10.0)
    await c.add("principal:alice", 3.0)
    assert await c.total("global") == pytest.approx(10.0)
    assert await c.total("principal:alice") == pytest.approx(3.0)
    assert await c.total("principal:bob") == pytest.approx(0.0)


async def test_uses_utc_date_key(
    fake_redis: fakeredis.aioredis.FakeRedis, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A new UTC day is a new key: yesterday's spend must not count against today's cap."""
    c = RedisDailyCounter(fake_redis)
    monkeypatch.setattr(daily_mod, "_utc_day", lambda: "2026-07-18")
    await c.add("global", 5.0)
    assert await c.total("global") == pytest.approx(5.0)
    # Roll the (UTC) day: the previous day's spend must not carry over.
    monkeypatch.setattr(daily_mod, "_utc_day", lambda: "2026-07-19")
    assert await c.total("global") == pytest.approx(0.0)
    await c.add("global", 1.0)
    assert await c.total("global") == pytest.approx(1.0)


async def test_key_shape_is_daily_scope_utcday(
    fake_redis: fakeredis.aioredis.FakeRedis, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The stored key is exactly ``daily:{scope}:{YYYY-MM-DD}`` (the documented key contract)."""
    monkeypatch.setattr(daily_mod, "_utc_day", lambda: "2026-07-18")
    c = RedisDailyCounter(fake_redis)
    await c.add("principal:sandipan", 1.0)
    assert await fake_redis.get("daily:principal:sandipan:2026-07-18") == b"1"


# --------------------------------------------------------------------------------------
# expiry — 48h TTL, anchored to first write (EXPIRE ... NX)
# --------------------------------------------------------------------------------------


async def test_add_sets_48h_expiry(
    fake_redis: fakeredis.aioredis.FakeRedis, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(daily_mod, "_utc_day", lambda: "2026-07-18")
    c = RedisDailyCounter(fake_redis)
    await c.add("global", 1.0)
    assert await fake_redis.ttl("daily:global:2026-07-18") == _EXPIRY


async def test_expiry_anchored_to_first_write_not_slid_forward(
    fake_redis: fakeredis.aioredis.FakeRedis, monkeypatch: pytest.MonkeyPatch
) -> None:
    """EXPIRE ... NX means a later same-day increment must NOT reset the TTL (anchored to first)."""
    monkeypatch.setattr(daily_mod, "_utc_day", lambda: "2026-07-18")
    key = "daily:global:2026-07-18"
    c = RedisDailyCounter(fake_redis)
    await c.add("global", 1.0)  # sets ttl 172800
    await fake_redis.expire(key, 50)  # shrink it to prove NX won't bump it back up
    await c.add("global", 1.0)  # second same-day add: nx=True => must not re-expand
    assert await fake_redis.ttl(key) <= 50


# --------------------------------------------------------------------------------------
# NX-unsupported (pre-Redis-7) downgrade to unconditional EXPIRE
# --------------------------------------------------------------------------------------


class _NoNxRedis:
    """A stub whose EXPIRE rejects the NX flag (models a pre-Redis-7 server), recording calls."""

    def __init__(self) -> None:
        self.expire_calls: list[tuple[int, bool]] = []

    async def incrbyfloat(self, key: str, amount: float) -> float:
        return amount

    async def get(self, key: str) -> bytes:
        return b"0"

    async def expire(self, key: str, ttl: int, nx: bool = False, **_kw: Any) -> bool:
        self.expire_calls.append((ttl, nx))
        if nx:
            raise ResponseError("ERR wrong number of arguments for 'expire' command")
        return True


async def test_nx_unsupported_downgrades_to_unconditional_expire() -> None:
    stub = _NoNxRedis()
    c = RedisDailyCounter(stub)
    await c.add("global", 1.0)
    # First tries nx=True (rejected), then falls back to an unconditional EXPIRE.
    assert stub.expire_calls == [(_EXPIRY, True), (_EXPIRY, False)]
    # The downgrade is remembered: the next add goes straight to unconditional EXPIRE (no nx retry).
    await c.add("global", 1.0)
    assert stub.expire_calls == [(_EXPIRY, True), (_EXPIRY, False), (_EXPIRY, False)]


# --------------------------------------------------------------------------------------
# outage — connection errors RAISE (fail-closed, never swallowed)
# --------------------------------------------------------------------------------------


class _RaisingRedis:
    """A client whose every op raises a Redis ConnectionError — models a counter outage."""

    async def incrbyfloat(self, key: str, amount: float) -> float:
        raise RedisConnectionError("connection refused")

    async def get(self, key: str) -> bytes:
        raise RedisConnectionError("connection refused")

    async def expire(self, *a: Any, **k: Any) -> bool:
        raise RedisConnectionError("connection refused")


async def test_add_propagates_connection_error() -> None:
    c = RedisDailyCounter(_RaisingRedis())
    with pytest.raises(RedisConnectionError):
        await c.add("global", 1.0)


async def test_total_propagates_connection_error() -> None:
    c = RedisDailyCounter(_RaisingRedis())
    with pytest.raises(RedisConnectionError):
        await c.total("global")


class _ExpireRaisesRedis:
    """incrbyfloat succeeds but EXPIRE fails with a connection error (outage mid-write)."""

    async def incrbyfloat(self, key: str, amount: float) -> float:
        return amount

    async def expire(self, *a: Any, **k: Any) -> bool:
        raise RedisConnectionError("connection dropped")


async def test_expire_connection_error_is_not_swallowed_by_nx_guard() -> None:
    """The NX try/except must re-raise a connection error (only a ResponseError downgrades)."""
    c = RedisDailyCounter(_ExpireRaisesRedis())
    with pytest.raises(RedisConnectionError):
        await c.add("global", 1.0)


# --------------------------------------------------------------------------------------
# build_daily_counter factory — backend selection
# --------------------------------------------------------------------------------------


def test_factory_defaults_to_sqlite() -> None:
    cfg = load_config(REPO_ROOT)  # shipped budgets.yaml: backend defaults to sqlite
    counter = build_daily_counter(cfg)
    assert isinstance(counter, SqliteDailyCounter)
    assert str(counter._path).endswith(DAILY_LEDGER_FILE)
    assert counter._path.parent == cfg.audit.dir


def test_factory_builds_redis_when_configured() -> None:
    cfg = load_config(REPO_ROOT)
    redis_daily = Daily(
        global_usd=cfg.budgets.daily.global_usd,
        per_principal_usd=cfg.budgets.daily.per_principal_usd,
        backend="redis",
        redis_url="redis://localhost:6379/0",
    )
    budgets = cfg.budgets.model_copy(update={"daily": redis_daily})
    cfg = cfg.model_copy(update={"budgets": budgets})
    counter = build_daily_counter(cfg)
    assert isinstance(counter, RedisDailyCounter)


def test_config_redis_backend_requires_url() -> None:
    """The Daily validator refuses ``backend: redis`` without a ``redis_url`` (fail-closed)."""
    with pytest.raises(ValueError, match="redis_url"):
        Daily(global_usd=50.0, per_principal_usd=25.0, backend="redis")


def test_config_sqlite_backend_is_the_default() -> None:
    daily = Daily(global_usd=50.0, per_principal_usd=25.0)
    assert daily.backend == "sqlite"
    assert daily.redis_url is None
