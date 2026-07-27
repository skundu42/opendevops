"""Unit tests for portable control-plane SQL backends and secret/model extensions."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from opendevops.config import ControlPlaneConfig, ExecutorConfig
from opendevops.control_plane import ActionIdentity, CapabilityGrantRequest, ChangeControlService
from opendevops.control_plane.service import Capability
from opendevops.interfaces.dashboard_chat import DashboardChatStore
from opendevops.storage import ControlDatabase, DatabaseError, resolve_store_config
from opendevops.tools.secrets import (
    FileSecretSource,
    VaultSecretSource,
    build_secret_source,
    resolve_secrets,
)


def test_sqlite_control_plane_roundtrip(tmp_path: Path) -> None:
    cfg = ControlPlaneConfig(database=tmp_path / "cp.sqlite3")
    svc = ChangeControlService(cfg)
    actor = ActionIdentity(issuer="https://id", subject="alice")
    proposal = svc.propose(
        CapabilityGrantRequest(
            environment="staging",
            capability=Capability.github_write,
            targets=["org/repo"],
            reason="need temporary write access",
            require_dry_run=False,
        ),
        actor,
    )
    assert svc.get(proposal.proposal_id).status.value == "pending"
    chat = DashboardChatStore(cfg)
    thread = chat.create("t1", actor, "staging")
    assert thread.thread_id == "t1"
    chat.begin_turn("t1", actor, "why is staging red?")
    assert len(chat.messages("t1", actor)) == 1


def test_postgres_backend_requires_url_env() -> None:
    with pytest.raises(ValidationError, match="database_url_env"):
        ControlPlaneConfig(backend="postgres")


def test_resolve_store_config_postgres_missing_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CONTROL_DATABASE_URL", raising=False)
    with pytest.raises(DatabaseError, match="unset"):
        resolve_store_config(
            backend="postgres",
            database=Path("./x"),
            database_url_env="CONTROL_DATABASE_URL",
        )


def test_file_secret_source(tmp_path: Path) -> None:
    (tmp_path / "PGPASSWORD").write_text("s3cret\n", encoding="utf-8")
    source = FileSecretSource(directory=tmp_path)
    assert source.get("PGPASSWORD") == "s3cret"
    assert source.get("missing") is None
    resolved = resolve_secrets(["psql", "{{secret:PGPASSWORD}}"], source)
    assert resolved.env["PGPASSWORD"] == "s3cret"
    assert resolved.argv == ["psql"]


def test_build_secret_source_file(tmp_path: Path) -> None:
    cfg = ExecutorConfig(secret_source="file", secret_file_dir=tmp_path)
    source = build_secret_source(cfg)
    assert isinstance(source, FileSecretSource)


def test_vault_secret_source_parses_kv2(monkeypatch: pytest.MonkeyPatch) -> None:
    import io
    import json

    payload = {
        "data": {"data": {"value": "from-vault", "other": "x"}},
    }

    class _Resp(io.BytesIO):
        def __enter__(self) -> _Resp:
            return self

        def __exit__(self, *a: object) -> None:
            return None

    def _urlopen(req: object, timeout: float = 0) -> _Resp:
        return _Resp(json.dumps(payload).encode())

    monkeypatch.setattr("urllib.request.urlopen", _urlopen)
    source = VaultSecretSource(addr="http://vault:8200", token="t")
    assert source.get("PGPASSWORD") == "from-vault"


def test_executor_vault_requires_block() -> None:
    with pytest.raises(ValidationError, match="executor.vault"):
        ExecutorConfig(secret_source="vault")


def test_shared_db_between_ledger_and_chat(tmp_path: Path) -> None:
    cfg = ControlPlaneConfig(database=tmp_path / "shared.sqlite3")
    db = ControlDatabase(
        resolve_store_config(
            backend="sqlite", database=cfg.database, database_url_env=None
        )
    )
    ChangeControlService(cfg, database=db)
    DashboardChatStore(db)
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        names = {str(row["name"]) for row in rows}
    assert "proposals" in names
    assert "dashboard_chat_threads" in names
