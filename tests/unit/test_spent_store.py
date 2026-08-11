"""Spent-decision store: memory + Redis claim/replay semantics."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from opendevops.config import ExecutorConfig
from opendevops.executor_service.spent import (
    MemorySpentDecisionStore,
    RedisSpentDecisionStore,
    build_spent_store,
)


class _FakeRedis:
    def __init__(self) -> None:
        self._data: dict[str, str] = {}

    async def set(
        self, key: str, value: str, *, nx: bool = False, ex: int | None = None
    ) -> bool | None:
        del ex  # TTL recorded by redis; not needed for claim semantics here
        if nx and key in self._data:
            return None
        self._data[key] = value
        return True


@pytest.mark.asyncio
async def test_memory_claim_rejects_replay() -> None:
    store = MemorySpentDecisionStore(now=lambda: 1000.0)
    assert await store.claim("run-1", "tc-1", 1120.0) is True
    assert await store.claim("run-1", "tc-1", 1120.0) is False
    assert await store.claim("run-1", "tc-2", 1120.0) is True


@pytest.mark.asyncio
async def test_memory_evicts_expired_entries() -> None:
    clock = {"t": 1000.0}
    store = MemorySpentDecisionStore(now=lambda: clock["t"])
    assert await store.claim("run-1", "tc-1", 1005.0) is True
    clock["t"] = 1010.0
    # Expired key is evicted; a new claim with a fresh exp succeeds.
    assert await store.claim("run-1", "tc-1", 1200.0) is True


@pytest.mark.asyncio
async def test_redis_claim_rejects_replay() -> None:
    store = RedisSpentDecisionStore(_FakeRedis(), now=lambda: 1000.0)
    assert await store.claim("run-1", "tc-1", 1120.0) is True
    assert await store.claim("run-1", "tc-1", 1120.0) is False


def test_build_spent_store_defaults_to_memory() -> None:
    store = build_spent_store(ExecutorConfig())
    assert isinstance(store, MemorySpentDecisionStore)


def test_redis_backend_requires_url() -> None:
    with pytest.raises(ValidationError, match="spent_token_redis_url"):
        ExecutorConfig(spent_token_backend="redis")


def test_build_spent_store_redis(monkeypatch: pytest.MonkeyPatch) -> None:
    created: dict[str, Any] = {}

    def _from_url(url: str, *, now: Any = None, **kwargs: Any) -> RedisSpentDecisionStore:
        created["url"] = url
        return RedisSpentDecisionStore(_FakeRedis(), now=now or (lambda: 0.0))

    monkeypatch.setattr(
        "opendevops.executor_service.spent.RedisSpentDecisionStore.from_url",
        _from_url,
    )
    cfg = ExecutorConfig(
        spent_token_backend="redis",
        spent_token_redis_url="redis://localhost:6379/3",
    )
    store = build_spent_store(cfg)
    assert created["url"] == "redis://localhost:6379/3"
    assert isinstance(store, RedisSpentDecisionStore)
