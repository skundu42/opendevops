"""Spent-decision (replay) store for the remote executor service.

A valid decision token is single-use: the first pod to claim ``(run_id, tool_call_id)``
may execute; a second presentation within the token TTL is rejected with HTTP 409 and
must never execute. The in-memory backend is correct for ``replicas: 1``; the Redis
backend is required when a per-(environment, channel) Deployment is scaled horizontally
so two replicas cannot both claim the same decision.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class SpentDecisionStore(Protocol):
    """Atomic claim of a decision token identity; ``False`` if already spent."""

    async def claim(self, run_id: str, tool_call_id: str, exp: float) -> bool:
        """Claim ``(run_id, tool_call_id)`` until ``exp`` (unix seconds). False = replay."""
        ...


class MemorySpentDecisionStore:
    """Process-local spent-decision cache (single-replica / tests)."""

    def __init__(self, *, now: Any = time.time) -> None:
        self._spent: dict[tuple[str, str], float] = {}
        self._lock = asyncio.Lock()
        self._now = now

    async def claim(self, run_id: str, tool_call_id: str, exp: float) -> bool:
        key = (run_id, tool_call_id)
        async with self._lock:
            current = float(self._now())
            for stale in [k for k, e in self._spent.items() if e <= current]:
                del self._spent[stale]
            if key in self._spent:
                return False
            self._spent[key] = exp
            return True


class RedisSpentDecisionStore:
    """Shared spent-decision store via Redis ``SET key 1 NX EX <ttl>``.

    Key shape: ``executor:spent:{run_id}:{tool_call_id}``. TTL is derived from the token
    ``exp`` (ceil seconds remaining, minimum 1). Outages RAISE (fail-closed) — the service
    must not execute when it cannot prove the decision is unspent.
    """

    def __init__(self, client: Any, *, now: Any = time.time) -> None:
        self._redis = client
        self._now = now

    @classmethod
    def from_url(cls, url: str, *, now: Any = time.time, **kwargs: Any) -> RedisSpentDecisionStore:
        from redis.asyncio import from_url as redis_from_url

        return cls(redis_from_url(url, **kwargs), now=now)

    @staticmethod
    def _key(run_id: str, tool_call_id: str) -> str:
        return f"executor:spent:{run_id}:{tool_call_id}"

    async def claim(self, run_id: str, tool_call_id: str, exp: float) -> bool:
        ttl = max(1, int(exp - float(self._now()) + 0.999))
        # SET NX → True when we won the claim; None/False when already spent.
        won = await self._redis.set(self._key(run_id, tool_call_id), "1", nx=True, ex=ttl)
        return bool(won)


def build_spent_store(cfg: Any, *, now: Any = time.time) -> SpentDecisionStore:
    """Config-driven factory: ``memory`` (default) or ``redis``."""
    from opendevops.config import AppConfig, ExecutorConfig

    if isinstance(cfg, AppConfig):
        executor = cfg.executor
    elif isinstance(cfg, ExecutorConfig):
        executor = cfg
    else:
        raise TypeError("build_spent_store expects AppConfig or ExecutorConfig")

    if executor.spent_token_backend == "redis":
        if not executor.spent_token_redis_url:
            raise ValueError(
                "executor.spent_token_backend='redis' requires executor.spent_token_redis_url"
            )
        return RedisSpentDecisionStore.from_url(executor.spent_token_redis_url, now=now)
    return MemorySpentDecisionStore(now=now)
