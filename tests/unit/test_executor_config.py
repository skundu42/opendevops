"""ExecutorConfig: local is default; remote is fail-closed on incomplete urls / signing key."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from opendevops.config import (
    ExecutorChannelKeys,
    ExecutorChannelUrls,
    ExecutorConfig,
    ExecutorTlsConfig,
    VaultSecretConfig,
)


def _full_urls() -> dict[str, ExecutorChannelUrls]:
    return {
        "staging": ExecutorChannelUrls(ro="http://s-ro", rw="http://s-rw"),
        "prod": ExecutorChannelUrls(ro="http://p-ro", rw="http://p-rw"),
    }


def _full_signing_keys() -> dict[str, ExecutorChannelKeys]:
    return {
        "staging": ExecutorChannelKeys(ro="S_RO", rw="S_RW"),
        "prod": ExecutorChannelKeys(ro="P_RO", rw="P_RW"),
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
    with pytest.raises(ValidationError, match="signing_key"):
        ExecutorConfig(mode="remote", urls=_full_urls())


def test_remote_valid() -> None:
    cfg = ExecutorConfig(mode="remote", urls=_full_urls(), signing_key_env="AGENT_KEY")
    assert cfg.mode == "remote"
    assert cfg.urls is not None
    assert cfg.urls["staging"].ro == "http://s-ro"
    assert cfg.urls["prod"].rw == "http://p-rw"


def test_remote_valid_with_signing_keys_map_only() -> None:
    cfg = ExecutorConfig(
        mode="remote", urls=_full_urls(), signing_keys=_full_signing_keys()
    )
    assert cfg.signing_key_env_for("staging", "ro") == "S_RO"
    assert cfg.signing_key_env_for("prod", "rw") == "P_RW"


@pytest.mark.parametrize("blank", ["", "   "])
def test_remote_rejects_blank_per_route_signing_key_names(blank: str) -> None:
    with pytest.raises(ValidationError, match="must not be blank"):
        ExecutorConfig(
            mode="remote",
            urls=_full_urls(),
            signing_keys={
                "staging": {"ro": blank, "rw": "S_RW"},
                "prod": {"ro": "P_RO", "rw": "P_RW"},
            },
        )


@pytest.mark.parametrize("blank", ["", "   "])
def test_remote_rejects_blank_shared_signing_key_name(blank: str) -> None:
    with pytest.raises(ValidationError, match="signing_key_env must not be blank"):
        ExecutorConfig(mode="remote", urls=_full_urls(), signing_key_env=blank)


def test_signing_key_env_for_falls_back_to_shared() -> None:
    cfg = ExecutorConfig(
        mode="remote", urls=_full_urls(), signing_key_env="SHARED"
    )
    assert cfg.signing_key_env_for("staging", "rw") == "SHARED"


def test_tls_requires_cert_pair() -> None:
    with pytest.raises(ValidationError, match="cert_file"):
        ExecutorTlsConfig(cert_file=Path("/certs/client.crt"))


def test_vault_approle_requires_ids() -> None:
    with pytest.raises(ValidationError, match="role_id_env"):
        VaultSecretConfig(auth="approle")


def test_vault_kubernetes_requires_role() -> None:
    with pytest.raises(ValidationError, match="kubernetes_role"):
        VaultSecretConfig(auth="kubernetes")


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
