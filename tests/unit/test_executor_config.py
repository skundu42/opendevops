"""ExecutorConfig: local is default; remote is fail-closed on missing url / signing key."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from opendevops.config import ExecutorConfig


def test_default_is_local() -> None:
    cfg = ExecutorConfig()
    assert cfg.mode == "local"
    assert cfg.url is None
    assert cfg.secret_source == "env"
    assert cfg.secret_env_prefix == ""


def test_remote_requires_url() -> None:
    with pytest.raises(ValidationError, match="executor.url"):
        ExecutorConfig(mode="remote", signing_key_env="KEY")


def test_remote_requires_signing_key_env() -> None:
    with pytest.raises(ValidationError, match="signing_key_env"):
        ExecutorConfig(mode="remote", url="http://svc")


def test_remote_valid() -> None:
    cfg = ExecutorConfig(mode="remote", url="http://svc:8090", signing_key_env="AGENT_KEY")
    assert cfg.mode == "remote"
    assert cfg.url == "http://svc:8090"


def test_unknown_key_forbidden() -> None:
    with pytest.raises(ValidationError):
        ExecutorConfig(mode="local", nope="x")  # type: ignore[call-arg]


def test_appconfig_without_executor_block_defaults_local() -> None:
    """A config with no executor: block still validates (additive) and defaults to local mode."""
    from tests.unit.test_executor_service import make_cfg

    cfg = make_cfg("/tmp/cfg-noexec")  # no executor kwargs -> no executor block in the dict
    assert cfg.executor.mode == "local"
    assert cfg.executor.url is None


def test_repo_config_yaml_validates_with_executor_block() -> None:
    """The shipped config/config.yaml (now carrying an executor: block) still loads, mode=local."""
    from opendevops.config import load_config

    cfg = load_config()
    assert cfg.executor.mode == "local"
