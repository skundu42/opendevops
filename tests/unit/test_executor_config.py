"""ExecutorConfig: local is default; remote is fail-closed on incomplete urls / signing key."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from opendevops.config import ExecutorChannelUrls, ExecutorConfig


def _full_urls() -> dict[str, ExecutorChannelUrls]:
    return {
        "staging": ExecutorChannelUrls(ro="http://s-ro", rw="http://s-rw"),
        "prod": ExecutorChannelUrls(ro="http://p-ro", rw="http://p-rw"),
    }


def test_default_is_local() -> None:
    cfg = ExecutorConfig()
    assert cfg.mode == "local"
    assert cfg.urls is None
    assert cfg.secret_source == "env"
    assert cfg.secret_env_prefix == ""


def test_remote_requires_urls() -> None:
    with pytest.raises(ValidationError, match="executor.urls"):
        ExecutorConfig(mode="remote", signing_key_env="KEY")


def test_remote_requires_both_environments() -> None:
    with pytest.raises(ValidationError, match="executor.urls"):
        ExecutorConfig(
            mode="remote",
            signing_key_env="KEY",
            urls={"staging": ExecutorChannelUrls(ro="http://s-ro", rw="http://s-rw")},  # type: ignore[arg-type]
        )


def test_remote_requires_signing_key_env() -> None:
    with pytest.raises(ValidationError, match="signing_key_env"):
        ExecutorConfig(mode="remote", urls=_full_urls())


def test_remote_valid() -> None:
    cfg = ExecutorConfig(mode="remote", urls=_full_urls(), signing_key_env="AGENT_KEY")
    assert cfg.mode == "remote"
    assert cfg.urls is not None
    assert cfg.urls["staging"].ro == "http://s-ro"
    assert cfg.urls["prod"].rw == "http://p-rw"


def test_unknown_key_forbidden() -> None:
    with pytest.raises(ValidationError):
        ExecutorConfig(mode="local", nope="x")  # type: ignore[call-arg]


def test_legacy_url_field_forbidden() -> None:
    with pytest.raises(ValidationError):
        ExecutorConfig(mode="local", url="http://legacy")  # type: ignore[call-arg]


def test_appconfig_without_executor_block_defaults_local() -> None:
    """A config with no executor: block still validates (additive) and defaults to local mode."""
    from tests.unit.test_executor_service import make_cfg

    cfg = make_cfg("/tmp/cfg-noexec")  # no executor kwargs -> no executor block in the dict
    assert cfg.executor.mode == "local"
    assert cfg.executor.urls is None


def test_repo_config_yaml_validates_with_executor_block() -> None:
    """The shipped config/config.yaml (now carrying an executor: block) still loads, mode=local."""
    from opendevops.config import load_config

    cfg = load_config()
    assert cfg.executor.mode == "local"
