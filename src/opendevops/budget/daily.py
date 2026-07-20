"""Daily spend counters (T6 sqlite/in-memory; T18 redis).

A ``DailyCounter`` accumulates USD spend under a ``scope`` string, partitioned by UTC
calendar day (key = ``(scope, "YYYY-MM-DD")``). ``DailyBudgetMiddleware`` uses two scope
families: the single ``"global"`` envelope and one ``"principal:<principal>"`` envelope per
caller. Rollover is implicit: a new UTC day is a new key, so yesterday's spend never counts
against today's cap.

Implementations here:

* :class:`InMemoryDailyCounter` — process-local, for tests and the in-graph tier.
* :class:`SqliteDailyCounter` — durable stdlib ``sqlite3`` (WAL), create-on-first-use.
* :class:`RedisDailyCounter` — shared, restart-surviving, for the P3 service tier where several
  LangGraph Server workers accumulate one daily envelope (``INCRBYFLOAT`` + ``EXPIRE 48h``).

:func:`build_daily_counter` is the config-driven factory the gateway/CLI/server construction
sites call: it returns a sqlite or redis counter per ``cfg.budgets.daily.backend``.

The counter is the *soft*, pre-emptive control that lets the agent stop gracefully before a
call. The gateway's usage-metadata callback (see the plan) remains the authoritative,
after-the-fact ledger; a counter write failure therefore degrades the run but never loses the
authoritative accounting.

Fail-closed outage contract (all backends)
------------------------------------------
A counter *operation* that cannot reach its store RAISES — it never returns a fabricated ``0.0``
or silently swallows the error. The layers above translate that raise into safety: the gateway's
daily pre-check and ``DailyBudgetMiddleware.abefore_model`` refuse to start / continue a run when
they cannot prove headroom (fail-closed), and the after-model charge flags ``counter_write_failed``
while the authoritative ledger records the true spend. :class:`RedisDailyCounter` therefore does
*not* catch ``redis`` connection errors — propagating them is the whole point.
"""

from __future__ import annotations

import asyncio
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from opendevops.config import AppConfig


def _utc_day() -> str:
    """Today's date in UTC as ``YYYY-MM-DD`` (the day component of every counter key).

    Module-level so tests can freeze it via ``monkeypatch.setattr``.
    """
    return datetime.now(UTC).strftime("%Y-%m-%d")


@runtime_checkable
class DailyCounter(Protocol):
    """Async USD spend accumulator keyed by ``(scope, UTC-day)``."""

    async def add(self, scope: str, usd: float) -> float:
        """Add ``usd`` to ``scope``'s total for today (UTC); return the new total."""
        ...

    async def total(self, scope: str) -> float:
        """Return ``scope``'s accumulated spend for today (UTC); ``0.0`` if none."""
        ...


class InMemoryDailyCounter:
    """Process-local :class:`DailyCounter` for tests and the single-process graph tier.

    Not durable and not shared across processes — use :class:`SqliteDailyCounter` (P1) or
    ``RedisDailyCounter`` (P3) where persistence/sharing is required.
    """

    def __init__(self) -> None:
        self._data: dict[tuple[str, str], float] = {}
        self._lock = asyncio.Lock()

    async def add(self, scope: str, usd: float) -> float:
        async with self._lock:
            key = (scope, _utc_day())
            self._data[key] = self._data.get(key, 0.0) + usd
            return self._data[key]

    async def total(self, scope: str) -> float:
        async with self._lock:
            return self._data.get((scope, _utc_day()), 0.0)


class SqliteDailyCounter:
    """Durable :class:`DailyCounter` backed by a stdlib ``sqlite3`` file.

    Blocking sqlite work runs in a worker thread via :func:`asyncio.to_thread` so the event
    loop is never blocked. The schema is created on first use (``CREATE TABLE IF NOT
    EXISTS``); WAL journalling keeps concurrent readers/writers from tripping over each other.
    Accumulation is a single atomic ``INSERT ... ON CONFLICT(scope, day) DO UPDATE``.
    """

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._initialized = False
        self._init_lock = asyncio.Lock()

    # -- blocking helpers (run inside asyncio.to_thread) --------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._path))
        conn.execute("PRAGMA journal_mode=WAL")
        # Wait up to 5s for a competing writer's lock instead of raising
        # ``database is locked`` immediately: the counter is written from a worker thread on
        # every model call, and a concurrent CLI/``langgraph dev`` process may share the file.
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _ensure_schema_sync(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        conn = self._connect()
        try:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS daily_spend ("
                "  scope TEXT NOT NULL,"
                "  day   TEXT NOT NULL,"
                "  usd   REAL NOT NULL,"
                "  PRIMARY KEY (scope, day)"
                ")"
            )
            conn.commit()
        finally:
            conn.close()

    def _add_sync(self, scope: str, usd: float, day: str) -> float:
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO daily_spend (scope, day, usd) VALUES (?, ?, ?) "
                "ON CONFLICT(scope, day) DO UPDATE SET usd = usd + excluded.usd",
                (scope, day, usd),
            )
            conn.commit()
            row = conn.execute(
                "SELECT usd FROM daily_spend WHERE scope = ? AND day = ?", (scope, day)
            ).fetchone()
            return float(row[0]) if row is not None else 0.0
        finally:
            conn.close()

    def _total_sync(self, scope: str, day: str) -> float:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT usd FROM daily_spend WHERE scope = ? AND day = ?", (scope, day)
            ).fetchone()
            return float(row[0]) if row is not None else 0.0
        finally:
            conn.close()

    # -- async API ----------------------------------------------------------------------

    async def _ensure(self) -> None:
        if self._initialized:
            return
        async with self._init_lock:
            if self._initialized:
                return
            await asyncio.to_thread(self._ensure_schema_sync)
            self._initialized = True

    async def add(self, scope: str, usd: float) -> float:
        await self._ensure()
        return await asyncio.to_thread(self._add_sync, scope, usd, _utc_day())

    async def total(self, scope: str) -> float:
        await self._ensure()
        return await asyncio.to_thread(self._total_sync, scope, _utc_day())


# The sqlite ledger filename under ``cfg.audit.dir`` — the durable default the factory builds when
# ``backend: sqlite``. Shared with ``agent.get_agent()`` / ``server_graph()`` and ``LocalGateway``
# so one durable daily envelope spans every entry point that uses the file backend.
DAILY_LEDGER_FILE = "daily-budget.sqlite3"

# The daily key's TTL: 48h. A day key is only relevant for its own UTC calendar day, so 48h is ample
# headroom (it outlives the day it was created in) while still reaping stale keys — Redis is a cache
# tier, not the durable ledger. Anchored to the key's FIRST write (EXPIRE ... NX below).
_EXPIRY_SECONDS = 48 * 60 * 60  # 172800


def _to_float(value: Any) -> float:
    """Coerce a Redis scalar reply to ``float``.

    ``INCRBYFLOAT`` returns a parsed ``float`` under redis-py's response callback, but ``GET``
    returns raw ``bytes`` (``b"1.75"``) unless ``decode_responses=True``; a decoded client yields
    ``str``. All three are accepted so the counter is agnostic to the client's decode setting.
    """
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, bytes):
        return float(value.decode("utf-8"))
    return float(value)


class RedisDailyCounter:
    """Shared, restart-surviving :class:`DailyCounter` backed by Redis (P3 service tier).

    Semantics match :class:`SqliteDailyCounter` exactly — UTC-day keying (``daily:{scope}:{day}``),
    ``add`` returns the new running total, ``total`` returns ``0.0`` for an unseen scope — but the
    store is Redis, so *several* LangGraph Server workers (each its own process, whose in-memory or
    sqlite counter would diverge) accumulate one envelope, and it survives a server restart.

    * ``add`` → ``INCRBYFLOAT key usd`` (atomic server-side accumulation, commutative under
      concurrent workers) then ``EXPIRE key 172800 NX`` (48h TTL anchored to the key's first write;
      NX so a later same-day increment does not slide the expiry forward). Returns the new total.
    * ``total`` → ``GET key`` parsed to ``float`` (``0.0`` if the key is absent).

    Outage → RAISE: ``redis`` connection errors are *not* caught (see the module docstring's
    fail-closed contract). The only error this class handles is a pre-Redis-7 server rejecting the
    ``EXPIRE ... NX`` syntax, which it detects once and downgrades to an unconditional ``EXPIRE``.

    The async ``redis.asyncio.Redis`` client is injected (the test seam — a ``fakeredis.aioredis``
    or a raising stub) or built from a URL via :meth:`from_url`. ``redis`` lives in the ``server``
    extra and is imported lazily (only :meth:`from_url` / the NX-downgrade path touch it), so
    importing this module never requires ``redis`` for the sqlite/in-memory tiers.
    """

    def __init__(self, client: Any) -> None:
        self._redis = client
        # Optimistic: assume the server understands ``EXPIRE ... NX`` (Redis >= 7). Downgraded to
        # ``False`` permanently the first time a server rejects it (older Redis) — see _set_expiry.
        self._expire_supports_nx = True

    @classmethod
    def from_url(cls, url: str, **kwargs: Any) -> RedisDailyCounter:
        """Build a counter over a fresh ``redis.asyncio`` client from ``url`` (production path)."""
        from redis.asyncio import from_url as redis_from_url

        return cls(redis_from_url(url, **kwargs))

    @staticmethod
    def _key(scope: str) -> str:
        return f"daily:{scope}:{_utc_day()}"

    async def add(self, scope: str, usd: float) -> float:
        key = self._key(scope)
        new_total = await self._redis.incrbyfloat(key, usd)
        await self._set_expiry(key)
        return _to_float(new_total)

    async def total(self, scope: str) -> float:
        raw = await self._redis.get(self._key(scope))
        return _to_float(raw) if raw is not None else 0.0

    async def _set_expiry(self, key: str) -> None:
        """Set the 48h TTL, anchored to the key's first write via ``NX`` where the server allows it.

        ``EXPIRE ... NX`` (only-set-if-no-TTL) needs Redis >= 7; an older server answers the extra
        flag with a ``ResponseError``. We catch *only* that (never a connection error — those must
        propagate as an outage), remember the downgrade, and fall back to an unconditional
        ``EXPIRE`` for the rest of this counter's life. redis-py >= 5 always accepts the ``nx=``
        kwarg client-side, so there is no ``TypeError`` path to handle.
        """
        if self._expire_supports_nx:
            try:
                await self._redis.expire(key, _EXPIRY_SECONDS, nx=True)
                return
            except Exception as exc:  # noqa: BLE001 - re-raise anything but the NX-unsupported case
                from redis.exceptions import ResponseError

                if not isinstance(exc, ResponseError):
                    raise  # a connection/other error is a real outage — fail-closed, do not swallow
                self._expire_supports_nx = False
        await self._redis.expire(key, _EXPIRY_SECONDS)


def build_daily_counter(cfg: AppConfig) -> DailyCounter:
    """Construct the :class:`DailyCounter` selected by ``cfg.budgets.daily.backend`` (T18 factory).

    * ``"sqlite"`` (default) → a :class:`SqliteDailyCounter` on ``cfg.audit.dir`` — the durable
      local ledger for the single-process CLI / ``langgraph dev`` tier.
    * ``"redis"`` → a :class:`RedisDailyCounter` over ``cfg.budgets.daily.redis_url``, the shared
      cross-worker/restart-surviving counter for service mode.

    The config validator already refuses ``backend: redis`` without ``redis_url``; the guard here is
    belt-and-braces so the factory never builds a URL-less redis client.
    """
    daily = cfg.budgets.daily
    if daily.backend == "redis":
        if not daily.redis_url:  # pragma: no cover - config validation forbids this state
            raise ValueError("budgets.daily.backend='redis' requires budgets.daily.redis_url")
        return RedisDailyCounter.from_url(daily.redis_url)
    return SqliteDailyCounter(cfg.audit.dir / DAILY_LEDGER_FILE)
