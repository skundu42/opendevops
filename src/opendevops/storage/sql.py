"""Portable SQL access for the control-plane ledger and dashboard chat store.

Supports ``sqlite`` (default, local) and ``postgres`` (multi-replica service mode). Application
SQL uses ``?`` placeholders; the postgres backend rewrites them to ``%s``. Row access is
mapping-like (``row["column"]``) on both backends.
"""

from __future__ import annotations

import os
import sqlite3
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

BackendKind = Literal["sqlite", "postgres"]


class DatabaseError(RuntimeError):
    """Fail-closed storage misconfiguration or connection failure."""


@dataclass(frozen=True)
class ControlStoreConfig:
    """Resolved store settings (from :class:`~opendevops.config.ControlPlaneConfig`)."""

    backend: BackendKind
    sqlite_path: Path | None
    database_url: str | None


def resolve_store_config(
    *,
    backend: BackendKind,
    database: Path,
    database_url_env: str | None,
) -> ControlStoreConfig:
    """Validate backend wiring and resolve the postgres URL from the named env var."""
    if backend == "sqlite":
        return ControlStoreConfig(backend="sqlite", sqlite_path=database, database_url=None)
    if not database_url_env:
        raise DatabaseError(
            "control_plane.backend='postgres' requires control_plane.database_url_env"
        )
    url = os.environ.get(database_url_env)
    if not url:
        raise DatabaseError(
            f"control_plane database URL env var {database_url_env!r} is unset or empty"
        )
    return ControlStoreConfig(backend="postgres", sqlite_path=None, database_url=url)


class _SqliteConn:
    def __init__(self, raw: sqlite3.Connection) -> None:
        self._raw = raw
        self._raw.row_factory = sqlite3.Row

    def execute(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Cursor:
        return self._raw.execute(sql, params)

    def executescript(self, sql: str) -> sqlite3.Cursor:
        return self._raw.executescript(sql)

    def commit(self) -> None:
        self._raw.commit()

    def rollback(self) -> None:
        self._raw.rollback()

    def close(self) -> None:
        self._raw.close()

    def __enter__(self) -> _SqliteConn:
        return self

    def __exit__(self, exc_type: object, *_exc: object) -> None:
        try:
            if exc_type is None:
                self._raw.commit()
            else:
                self._raw.rollback()
        finally:
            self._raw.close()


class _PostgresConn:
    def __init__(self, raw: Any) -> None:
        self._raw = raw

    @staticmethod
    def _q(sql: str) -> str:
        return sql.replace("?", "%s")

    def execute(self, sql: str, params: Sequence[Any] = ()) -> Any:
        return self._raw.execute(self._q(sql), params)

    def executescript(self, sql: str) -> None:
        for stmt in sql.split(";"):
            piece = stmt.strip()
            if piece:
                self._raw.execute(piece)

    def commit(self) -> None:
        self._raw.commit()

    def rollback(self) -> None:
        self._raw.rollback()

    def close(self) -> None:
        self._raw.close()

    def __enter__(self) -> _PostgresConn:
        return self

    def __exit__(self, exc_type: object, *_exc: object) -> None:
        try:
            if exc_type is None:
                self._raw.commit()
            else:
                self._raw.rollback()
        finally:
            self._raw.close()


class ControlDatabase:
    """Connection factory for the shared control-plane + chat durable store."""

    def __init__(self, cfg: ControlStoreConfig) -> None:
        self._cfg = cfg
        self._lock = threading.RLock()
        if cfg.backend == "sqlite":
            assert cfg.sqlite_path is not None
            cfg.sqlite_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            cfg.sqlite_path.parent.chmod(0o700)

    @property
    def backend(self) -> BackendKind:
        return self._cfg.backend

    @property
    def lock(self) -> threading.RLock:
        return self._lock

    @property
    def sqlite_path(self) -> Path | None:
        return self._cfg.sqlite_path

    def connect(self) -> _SqliteConn | _PostgresConn:
        if self._cfg.backend == "sqlite":
            assert self._cfg.sqlite_path is not None
            sqlite_raw = sqlite3.connect(self._cfg.sqlite_path, timeout=10)
            sqlite_raw.execute("PRAGMA foreign_keys = ON")
            sqlite_raw.execute("PRAGMA busy_timeout = 10000")
            return _SqliteConn(sqlite_raw)
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as exc:  # pragma: no cover - optional extra
            raise DatabaseError(
                "control_plane.backend='postgres' requires the 'postgres' extra "
                "(install 'opendevops[postgres]')"
            ) from exc
        assert self._cfg.database_url is not None
        pg_raw: Any = psycopg.connect(self._cfg.database_url, row_factory=dict_row)
        return _PostgresConn(pg_raw)

    def begin_immediate(self, connection: _SqliteConn | _PostgresConn) -> None:
        if self._cfg.backend == "sqlite":
            connection.execute("BEGIN IMMEDIATE")
        else:
            connection.execute("BEGIN")

    def for_update(self, sql: str) -> str:
        """Append ``FOR UPDATE`` on postgres for row locks; sqlite returns *sql* unchanged."""
        if self._cfg.backend == "postgres":
            return sql.rstrip() + " FOR UPDATE"
        return sql

    def events_pk_ddl(self) -> str:
        if self._cfg.backend == "sqlite":
            return "sequence INTEGER PRIMARY KEY AUTOINCREMENT"
        return "sequence BIGSERIAL PRIMARY KEY"

    def chat_messages_pk_ddl(self) -> str:
        return self.events_pk_ddl()
