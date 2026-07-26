"""Durable, identity-scoped dashboard chat threads and sanitized transcript history."""

from __future__ import annotations

import sqlite3
import threading
import time
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict

from opendevops.control_plane import ActionIdentity

_MAX_THREADS_PER_IDENTITY = 50
_MAX_MESSAGES_PER_THREAD = 500
_RUN_LEASE_S = 2 * 60 * 60


class ChatThreadStatus(StrEnum):
    idle = "idle"
    running = "running"
    awaiting_approval = "awaiting_approval"


class ChatThread(BaseModel):
    model_config = ConfigDict(extra="forbid")

    thread_id: str
    title: str
    environment: Literal["staging", "prod"]
    status: ChatThreadStatus
    created_at: str
    updated_at: str
    last_run_id: str | None = None
    message_count: int = 0


class ChatMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message_id: str
    role: Literal["user", "assistant", "activity", "system"]
    kind: str
    content: str
    created_at: str
    run_id: str | None = None


class DashboardChatError(RuntimeError):
    """Safe refusal from the identity-scoped chat store."""


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, UTC).isoformat().replace("+00:00", "Z")


def _title(message: str) -> str:
    compact = " ".join(message.split())
    return compact[:72] + ("…" if len(compact) > 72 else "")


class DashboardChatStore:
    """SQLite transcript store sharing the control-plane durable volume.

    Chat content is intentionally separate from the immutable audit chain: the audit records
    attribution and run lifecycle without copying prompts or responses, while this table provides
    a bounded operator-visible transcript. Every read and new turn is scoped to exact
    ``(issuer, subject)`` ownership.
    """

    def __init__(
        self,
        database: Path,
        *,
        retention_days: int = 30,
        now: Any = time.time,
    ) -> None:
        self._path = Path(database)
        self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._path.parent.chmod(0o700)
        self._retention_s = retention_days * 86400
        self._now = now
        self._lock = threading.RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS dashboard_chat_threads (
                    thread_id TEXT PRIMARY KEY,
                    issuer TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    title TEXT NOT NULL,
                    environment TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    last_run_id TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_dashboard_chat_owner
                    ON dashboard_chat_threads (issuer, subject, updated_at DESC);
                CREATE TABLE IF NOT EXISTS dashboard_chat_messages (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    message_id TEXT NOT NULL UNIQUE,
                    thread_id TEXT NOT NULL
                        REFERENCES dashboard_chat_threads(thread_id) ON DELETE CASCADE,
                    role TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    content TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    run_id TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_dashboard_chat_messages
                    ON dashboard_chat_messages (thread_id, sequence);
                """
            )
        self._path.chmod(0o600)

    @staticmethod
    def _owned_row(
        connection: sqlite3.Connection,
        thread_id: str,
        actor: ActionIdentity,
    ) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT * FROM dashboard_chat_threads
            WHERE thread_id = ? AND issuer = ? AND subject = ?
            """,
            (thread_id, actor.issuer, actor.subject),
        ).fetchone()
        if row is None:
            raise DashboardChatError("chat thread not found")
        return row

    def _cleanup(self, connection: sqlite3.Connection, now: float) -> None:
        connection.execute(
            """
            DELETE FROM dashboard_chat_threads
            WHERE updated_at < ? AND status = 'idle'
            """,
            (now - self._retention_s,),
        )

    def create(
        self,
        thread_id: str,
        actor: ActionIdentity,
        environment: Literal["staging", "prod"],
    ) -> ChatThread:
        now = float(self._now())
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._cleanup(connection, now)
            count = connection.execute(
                """
                SELECT COUNT(*) AS count FROM dashboard_chat_threads
                WHERE issuer = ? AND subject = ?
                """,
                (actor.issuer, actor.subject),
            ).fetchone()
            if int(count["count"]) >= _MAX_THREADS_PER_IDENTITY:
                raise DashboardChatError(
                    "chat thread limit reached; older threads expire after retention"
                )
            connection.execute(
                """
                INSERT INTO dashboard_chat_threads (
                    thread_id, issuer, subject, title, environment, status,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'idle', ?, ?)
                """,
                (
                    thread_id,
                    actor.issuer,
                    actor.subject,
                    "New investigation",
                    environment,
                    now,
                    now,
                ),
            )
            connection.commit()
        return self.get(thread_id, actor)

    def get(self, thread_id: str, actor: ActionIdentity) -> ChatThread:
        with self._connect() as connection:
            row = self._owned_row(connection, thread_id, actor)
            return self._thread(connection, row)

    def get_internal(self, thread_id: str) -> ChatThread | None:
        """Return a thread without an ownership projection for trusted route coordination."""
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM dashboard_chat_threads WHERE thread_id = ?", (thread_id,)
            ).fetchone()
            return self._thread(connection, row) if row is not None else None

    def list_threads(self, actor: ActionIdentity) -> list[ChatThread]:
        now = float(self._now())
        with self._lock, self._connect() as connection:
            self._cleanup(connection, now)
            rows = connection.execute(
                """
                SELECT * FROM dashboard_chat_threads
                WHERE issuer = ? AND subject = ?
                ORDER BY updated_at DESC LIMIT ?
                """,
                (
                    actor.issuer,
                    actor.subject,
                    _MAX_THREADS_PER_IDENTITY,
                ),
            ).fetchall()
            return [self._thread(connection, row) for row in rows]

    def messages(self, thread_id: str, actor: ActionIdentity) -> list[ChatMessage]:
        with self._connect() as connection:
            self._owned_row(connection, thread_id, actor)
            rows = connection.execute(
                """
                SELECT message_id, role, kind, content, created_at, run_id
                FROM dashboard_chat_messages
                WHERE thread_id = ?
                ORDER BY sequence DESC LIMIT ?
                """,
                (thread_id, _MAX_MESSAGES_PER_THREAD),
            ).fetchall()
        return [
            ChatMessage(
                message_id=str(row["message_id"]),
                role=cast(
                    Literal["user", "assistant", "activity", "system"],
                    str(row["role"]),
                ),
                kind=str(row["kind"]),
                content=str(row["content"]),
                created_at=_iso(float(row["created_at"])),
                run_id=str(row["run_id"]) if row["run_id"] else None,
            )
            for row in reversed(rows)
        ]

    def begin_turn(
        self,
        thread_id: str,
        actor: ActionIdentity,
        message: str,
    ) -> ChatThread:
        now = float(self._now())
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = self._owned_row(connection, thread_id, actor)
            status = str(row["status"])
            stale = status == "running" and now - float(row["updated_at"]) > _RUN_LEASE_S
            if status != "idle" and not stale:
                detail = (
                    "chat is waiting for an approval"
                    if status == "awaiting_approval"
                    else "a chat run is already active"
                )
                raise DashboardChatError(detail)
            message_count = int(
                connection.execute(
                    """
                    SELECT COUNT(*) AS count FROM dashboard_chat_messages
                    WHERE thread_id = ?
                    """,
                    (thread_id,),
                ).fetchone()["count"]
            )
            if message_count >= _MAX_MESSAGES_PER_THREAD:
                raise DashboardChatError("chat history limit reached; start a new investigation")
            title = _title(message) if message_count == 0 else str(row["title"])
            connection.execute(
                """
                UPDATE dashboard_chat_threads
                SET title = ?, status = 'running', updated_at = ?
                WHERE thread_id = ?
                """,
                (title, now, thread_id),
            )
            self._insert_message(
                connection,
                thread_id,
                role="user",
                kind="message",
                content=message,
                created_at=now,
            )
            connection.commit()
        return self.get(thread_id, actor)

    def append(
        self,
        thread_id: str,
        *,
        role: Literal["assistant", "activity", "system"],
        kind: str,
        content: str,
        run_id: str | None = None,
    ) -> None:
        if not content:
            return
        now = float(self._now())
        with self._lock, self._connect() as connection:
            exists = connection.execute(
                "SELECT 1 FROM dashboard_chat_threads WHERE thread_id = ?",
                (thread_id,),
            ).fetchone()
            if exists is None:
                return
            self._insert_message(
                connection,
                thread_id,
                role=role,
                kind=kind,
                content=content,
                created_at=now,
                run_id=run_id,
            )
            connection.execute(
                """
                UPDATE dashboard_chat_threads
                SET updated_at = ?, last_run_id = COALESCE(?, last_run_id)
                WHERE thread_id = ?
                """,
                (now, run_id, thread_id),
            )

    def finish_turn(
        self,
        thread_id: str,
        *,
        awaiting_approval: bool,
        run_id: str | None,
    ) -> None:
        now = float(self._now())
        status = (
            ChatThreadStatus.awaiting_approval.value
            if awaiting_approval
            else ChatThreadStatus.idle.value
        )
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                UPDATE dashboard_chat_threads
                SET status = ?, updated_at = ?, last_run_id = COALESCE(?, last_run_id)
                WHERE thread_id = ?
                """,
                (status, now, run_id, thread_id),
            )

    def cancel(self, thread_id: str, actor: ActionIdentity | None = None) -> None:
        now = float(self._now())
        with self._lock, self._connect() as connection:
            if actor is not None:
                self._owned_row(connection, thread_id, actor)
            connection.execute(
                """
                UPDATE dashboard_chat_threads
                SET status = 'idle', updated_at = ?
                WHERE thread_id = ?
                """,
                (now, thread_id),
            )

    @staticmethod
    def _insert_message(
        connection: sqlite3.Connection,
        thread_id: str,
        *,
        role: str,
        kind: str,
        content: str,
        created_at: float,
        run_id: str | None = None,
    ) -> None:
        connection.execute(
            """
            INSERT INTO dashboard_chat_messages (
                message_id, thread_id, role, kind, content, created_at, run_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                thread_id,
                role,
                kind,
                content,
                created_at,
                run_id,
            ),
        )

    @staticmethod
    def _thread(connection: sqlite3.Connection, row: sqlite3.Row) -> ChatThread:
        count = connection.execute(
            """
            SELECT COUNT(*) AS count FROM dashboard_chat_messages
            WHERE thread_id = ?
            """,
            (row["thread_id"],),
        ).fetchone()
        return ChatThread(
            thread_id=str(row["thread_id"]),
            title=str(row["title"]),
            environment=cast(Literal["staging", "prod"], str(row["environment"])),
            status=ChatThreadStatus(str(row["status"])),
            created_at=_iso(float(row["created_at"])),
            updated_at=_iso(float(row["updated_at"])),
            last_run_id=str(row["last_run_id"]) if row["last_run_id"] else None,
            message_count=int(count["count"]),
        )
