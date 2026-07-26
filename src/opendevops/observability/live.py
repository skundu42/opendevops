"""Small in-process projection for queued webhook work and lifecycle transitions."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

_MAX_RETAINED_RUNS = 500


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, UTC).isoformat().replace("+00:00", "Z")


@dataclass
class _LiveRun:
    thread_id: str
    principal: str
    interface: str
    queued_at: float
    status: str = "queued"
    started_at: float | None = None
    completed_at: float | None = None
    run_id: str | None = None
    retries: int = 0
    error: str | None = None


@dataclass
class LiveTelemetry:
    """Concurrency-safe, secret-free lifecycle state for work initiated by the web app."""

    _runs: dict[str, _LiveRun] = field(default_factory=dict)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def queued(self, thread_id: str, principal: str, interface: str) -> None:
        async with self._lock:
            if len(self._runs) >= _MAX_RETAINED_RUNS and thread_id not in self._runs:
                finished = next(
                    (
                        key
                        for key, item in self._runs.items()
                        if item.status not in {"queued", "running"}
                    ),
                    None,
                )
                if finished is not None:
                    self._runs.pop(finished, None)
            self._runs[thread_id] = _LiveRun(
                thread_id=thread_id,
                principal=principal,
                interface=interface,
                queued_at=time.time(),
            )

    async def running(self, thread_id: str) -> None:
        async with self._lock:
            item = self._runs.get(thread_id)
            if item is not None:
                item.status = "running"
                item.started_at = time.time()

    async def completed(self, thread_id: str, run_id: str | None, error: str | None = None) -> None:
        async with self._lock:
            item = self._runs.get(thread_id)
            if item is not None:
                item.status = "error" if error else "completed"
                item.run_id = run_id
                item.error = error
                item.completed_at = time.time()

    async def cancelled(self, thread_id: str) -> None:
        async with self._lock:
            item = self._runs.get(thread_id)
            if item is not None:
                item.status = "cancelled"
                item.completed_at = time.time()

    async def snapshot(self) -> dict[str, Any]:
        async with self._lock:
            runs = list(self._runs.values())
        active = [
            {
                "thread_id": item.thread_id,
                "run_id": item.run_id,
                "principal": item.principal,
                "interface": item.interface,
                "status": item.status,
                "queued_at": _iso(item.queued_at),
                "started_at": _iso(item.started_at) if item.started_at else None,
                "retries": item.retries,
            }
            for item in runs
            if item.status in {"queued", "running"}
        ]
        queue_latencies = [
            item.started_at - item.queued_at
            for item in runs
            if item.started_at is not None
        ]
        return {
            "active_runs": active,
            "queue_depth": sum(1 for item in runs if item.status == "queued"),
            "worker_active": sum(1 for item in runs if item.status == "running"),
            "executor_errors": sum(1 for item in runs if item.status == "error"),
            "queue_latency_ms": (
                round(sum(queue_latencies) / len(queue_latencies) * 1000, 2)
                if queue_latencies
                else None
            ),
        }
