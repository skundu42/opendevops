"""Config loader tests: shipped-file load, profile overlay, extra=forbid, unpriced-model check."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest
from pydantic import ValidationError

from graph.helpers import MODELS, budgets
from opendevops.config import AppConfig, ModelsConfig, load_config

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_load_shipped_config() -> None:
    """The real config/ files load into a fully-typed AppConfig aggregate."""
    cfg = load_config(REPO_ROOT)
    assert isinstance(cfg, AppConfig)
    # aggregate exposes all sections
    assert cfg.targets.kubernetes.allowed_contexts == []
    assert cfg.execution.cmd_timeout_seconds == 60
    assert cfg.execution.env_allowlist == ["PATH", "HOME"]
    assert cfg.principals == {}
    assert cfg.models.agents == {
        "main": "opus",
        "summarizer": "haiku",
        "log_summarizer": "haiku",
    }
    assert cfg.budgets.trip_ratio == 0.9


def test_tilde_expansion() -> None:
    """kubeconfig_ro '~/...' is expanded to an absolute path (no literal '~')."""
    cfg = load_config(REPO_ROOT)
    ro = cfg.targets.kubernetes.kubeconfig_ro
    assert ro.is_absolute()
    assert "~" not in str(ro)
    assert str(ro).endswith("/.kube/agent-view.yaml")
    assert cfg.targets.kubernetes.kubeconfig_rw is None


def test_default_profile() -> None:
    cfg = load_config(REPO_ROOT)
    d = cfg.budgets.profile()
    assert d.usd == 2.0
    assert d.model_calls == 50
    assert d.tool_calls == 100
    assert d.shell_calls == 30
    assert d.recursion_limit == 250
    assert d.wall_clock_s == 900


def test_shipped_server_section() -> None:
    """The shipped config.yaml carries the additive T16 ``server`` block."""
    cfg = load_config(REPO_ROOT)
    assert cfg.server.url == "http://localhost:8123"
    assert cfg.server.api_key_env == "LANGGRAPH_API_KEY"


def test_server_section_defaults_absent() -> None:
    """A config with no ``server:`` block still validates; url/api_key_env default to None."""
    cfg = AppConfig.model_validate(
        {
            "targets": {"kubernetes": {"kubeconfig_ro": "/tmp/k.yaml"}},
            "execution": {
                "cmd_timeout_seconds": 60,
                "output_max_chars": 50000,
                "env_allowlist": ["PATH"],
            },
            "audit": {"dir": "./audit"},
            "policy": {"dir": "./config/policy"},
            "models": copy.deepcopy(MODELS),
            "budgets": budgets(),
        }
    )
    assert cfg.server.url is None
    assert cfg.server.api_key_env is None


def test_server_section_extra_forbidden() -> None:
    """An unknown key under ``server:`` is rejected (extra='forbid')."""
    from opendevops.config import ServerConfig

    with pytest.raises(ValidationError):
        ServerConfig.model_validate({"url": "http://x", "bogus": 1})


def test_interactive_profile_overlay() -> None:
    """interactive overrides usd + wall_clock_s and inherits everything else from default."""
    cfg = load_config(REPO_ROOT)
    p = cfg.budgets.profile("interactive")
    assert p.usd == 5.0  # overridden
    assert p.wall_clock_s == 1800  # overridden
    assert p.model_calls == 50  # inherited from default
    assert p.tool_calls == 100  # inherited
    assert p.shell_calls == 30  # inherited
    assert p.recursion_limit == 250  # inherited


def test_scheduled_profile_overlay() -> None:
    cfg = load_config(REPO_ROOT)
    p = cfg.budgets.profile("scheduled")
    assert p.model_calls == 40  # overridden
    assert p.usd == 2.0  # overridden (same value as default here)
    assert p.wall_clock_s == 900  # inherited
    assert p.tool_calls == 100  # inherited


def test_incident_profile_overlay() -> None:
    cfg = load_config(REPO_ROOT)
    p = cfg.budgets.profile("incident")
    assert p.usd == 10.0
    assert p.wall_clock_s == 3600
    assert p.model_calls == 50  # inherited


def test_unknown_profile_raises() -> None:
    cfg = load_config(REPO_ROOT)
    with pytest.raises(KeyError):
        cfg.budgets.profile("does-not-exist")


def test_extra_forbid_rejects_unknown_config_key(
    write_config, base_config
) -> None:
    """Unknown top-level keys in config.yaml are rejected (extra=forbid)."""
    base_config["surprise"] = True
    root = write_config(config=base_config)
    with pytest.raises(ValidationError):
        load_config(root)


def test_extra_forbid_rejects_unknown_nested_key(
    write_config, base_config
) -> None:
    """Unknown nested keys are rejected too (strict validation is recursive)."""
    base_config["execution"]["turbo"] = True
    root = write_config(config=base_config)
    with pytest.raises(ValidationError):
        load_config(root)


def test_extra_forbid_rejects_unknown_budget_profile_key(
    write_config, base_budgets
) -> None:
    base_budgets["per_run"]["profiles"]["interactive"]["gpus"] = 4
    root = write_config(budgets=base_budgets)
    with pytest.raises(ValidationError):
        load_config(root)


def test_unpriced_agent_alias_rejected(write_config, base_models) -> None:
    """An agent alias that resolves to a model with no pricing entry refuses to boot."""
    # 'haiku' alias -> anthropic:claude-haiku-4-5; drop its pricing entry.
    del base_models["pricing"]["anthropic:claude-haiku-4-5"]
    root = write_config(models=base_models)
    with pytest.raises(ValidationError) as exc:
        load_config(root)
    assert "pricing" in str(exc.value).lower()


def test_agent_references_unknown_alias_rejected(write_config, base_models) -> None:
    base_models["agents"]["main"] = "ghost-alias"
    root = write_config(models=base_models)
    with pytest.raises(ValidationError):
        load_config(root)


def test_models_config_direct_validation() -> None:
    """ModelsConfig can be validated directly and enforces the priced-alias invariant."""
    bad = copy.deepcopy(
        {
            "agents": {"main": "opus"},
            "aliases": {"opus": "anthropic:claude-opus-4-8"},
            "pricing": {},
            "fallback_pricing": "error",
        }
    )
    with pytest.raises(ValidationError):
        ModelsConfig.model_validate(bad)


def test_missing_config_dir_raises(tmp_path) -> None:
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path)


# --------------------------------------------------------------------------------------
# targets.github (T11 / P2) — additive gh credential-family config
# --------------------------------------------------------------------------------------


def test_github_token_env_defaults_to_none_when_absent(write_config, base_config) -> None:
    """A config with no github block still loads; targets.github.token_env defaults to None."""
    assert "github" not in base_config["targets"]
    root = write_config(config=base_config)
    cfg = load_config(root)
    assert cfg.targets.github.token_env is None


def test_shipped_config_github_token_env_is_none() -> None:
    """The shipped config.yaml ships github.token_env: null (gh family refuses until exported)."""
    cfg = load_config(REPO_ROOT)
    assert cfg.targets.github.token_env is None


def test_github_token_env_round_trips_a_name(write_config, base_config) -> None:
    base_config["targets"]["github"] = {"token_env": "OPENDEVOPS_GH_TOKEN"}
    root = write_config(config=base_config)
    cfg = load_config(root)
    assert cfg.targets.github.token_env == "OPENDEVOPS_GH_TOKEN"


def test_github_null_token_env_round_trips(write_config, base_config) -> None:
    base_config["targets"]["github"] = {"token_env": None}
    root = write_config(config=base_config)
    cfg = load_config(root)
    assert cfg.targets.github.token_env is None


def test_github_unknown_key_rejected(write_config, base_config) -> None:
    """extra=forbid: an unknown key inside the github block refuses to boot."""
    base_config["targets"]["github"] = {"token_env": None, "bogus": 1}
    root = write_config(config=base_config)
    with pytest.raises(ValidationError):
        load_config(root)


# --------------------------------------------------------------------------------------
# targets.{aws,gcloud,azure} (T21 / P5a) — additive cloud credential-family config
# --------------------------------------------------------------------------------------


def test_cloud_targets_default_empty_when_absent(write_config, base_config) -> None:
    """A config with no cloud blocks still loads; every credential_env defaults to []."""
    assert "aws" not in base_config["targets"]
    root = write_config(config=base_config)
    cfg = load_config(root)
    assert cfg.targets.aws.credential_env == []
    assert cfg.targets.gcloud.credential_env == []
    assert cfg.targets.azure.credential_env == []


def test_shipped_config_cloud_targets_unconfigured() -> None:
    """The shipped config.yaml ships the cloud families unconfigured (empty credential_env)."""
    cfg = load_config(REPO_ROOT)
    assert cfg.targets.aws.credential_env == []
    assert cfg.targets.gcloud.credential_env == []
    assert cfg.targets.azure.credential_env == []


def test_cloud_credential_env_round_trips_names(write_config, base_config) -> None:
    base_config["targets"]["aws"] = {
        "credential_env": ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]
    }
    base_config["targets"]["gcloud"] = {"credential_env": ["GOOGLE_APPLICATION_CREDENTIALS"]}
    base_config["targets"]["azure"] = {"credential_env": ["AZURE_CLIENT_ID"]}
    root = write_config(config=base_config)
    cfg = load_config(root)
    assert cfg.targets.aws.credential_env == ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]
    assert cfg.targets.gcloud.credential_env == ["GOOGLE_APPLICATION_CREDENTIALS"]
    assert cfg.targets.azure.credential_env == ["AZURE_CLIENT_ID"]


def test_cloud_target_unknown_key_rejected(write_config, base_config) -> None:
    """extra=forbid: an unknown key inside a cloud block refuses to boot."""
    base_config["targets"]["aws"] = {"credential_env": [], "bogus": 1}
    root = write_config(config=base_config)
    with pytest.raises(ValidationError):
        load_config(root)
