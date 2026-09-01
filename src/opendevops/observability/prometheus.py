"""Small shared sources for Prometheus metrics."""

from __future__ import annotations

import asyncio
from collections import Counter
from pathlib import Path
from typing import Any

from opendevops.audit.schema import AuditEvent, EventType

SCHEDULER_LAST_SUCCESS_KEY = "opendevops:scheduler:last_success"


class AuditDenialCache:
    """Count policy denials while reparsing only audit files that changed."""

    def __init__(self, audit_dir: Path) -> None:
        self._audit_dir = Path(audit_dir)
        self._files: dict[Path, tuple[tuple[int, int], Counter[str]]] = {}
        self._lock = asyncio.Lock()

    async def snapshot(self) -> dict[str, int]:
        async with self._lock:
            return await asyncio.to_thread(self._refresh)

    def _refresh(self) -> dict[str, int]:
        try:
            paths = set(self._audit_dir.glob("*.jsonl"))
        except OSError:
            paths = set()
        for stale in self._files.keys() - paths:
            del self._files[stale]
        for path in paths:
            try:
                stat = path.stat()
            except OSError:
                continue
            signature = (stat.st_mtime_ns, stat.st_size)
            cached = self._files.get(path)
            if cached is None or cached[0] != signature:
                self._files[path] = (signature, self._count_file(path))
        total: Counter[str] = Counter()
        for _, counts in self._files.values():
            total.update(counts)
        return dict(sorted(total.items()))

    @staticmethod
    def _count_file(path: Path) -> Counter[str]:
        counts: Counter[str] = Counter()
        try:
            with path.open(encoding="utf-8") as handle:
                for line in handle:
                    if not line.strip():
                        continue
                    try:
                        event = AuditEvent.model_validate_json(line)
                    except ValueError:
                        continue
                    if (
                        event.event_type is EventType.decision
                        and event.decision is not None
                        and event.decision.effect == "deny"
                    ):
                        counts[event.decision.rule_id] += 1
        except OSError:
            pass
        return counts


async def record_scheduler_success(
    redis_client: Any, job_id: str, timestamp: float
) -> None:
    """Persist one successful scheduler completion for the server metrics exporter."""

    await redis_client.hset(SCHEDULER_LAST_SUCCESS_KEY, job_id, timestamp)
