"""Shared test fixtures: a tmp config-dir factory that materializes the three YAML files."""

from __future__ import annotations

import copy
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]

# Put the repo root on sys.path so the ops-tool package (``ops.maintenance`` / ``ops.quota_probe``)
# is importable by its unit tests. ``ops`` is deliberately NOT in the shipped wheel, so pytest's
# prepend import mode (which only inserts the tests dir) would otherwise not find it.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Valid baseline documents mirroring the shipped config/ files. Tests deep-copy and
# mutate these to exercise validation paths without touching the real files.
BASE_CONFIG: dict[str, Any] = {
    "targets": {
        "kubernetes": {
            "kubeconfig_ro": "~/.kube/agent-view.yaml",
            "kubeconfig_rw": None,
            "kubeconfig_rw_by_environment": {},
            "allowed_contexts": [],
        }
    },
    "execution": {
        "cmd_timeout_seconds": 60,
        "output_max_chars": 50000,
        "env_allowlist": ["PATH", "HOME"],
    },
    "audit": {"dir": "./audit"},
    "policy": {"dir": "./config/policy"},
    "principals": {},
}

BASE_MODELS: dict[str, Any] = {
    "agents": {"main": "opus", "summarizer": "haiku"},
    "aliases": {
        "opus": "anthropic:claude-opus-4-8",
        "sonnet": "anthropic:claude-sonnet-5",
        "haiku": "anthropic:claude-haiku-4-5",
    },
    "pricing": {
        "anthropic:claude-opus-4-8": {
            "input": 5.00,
            "output": 25.00,
            "cache_read": 0.50,
            "cache_write": 6.25,
        },
        "anthropic:claude-sonnet-5": {
            "input": 3.00,
            "output": 15.00,
            "cache_read": 0.30,
            "cache_write": 3.75,
        },
        "anthropic:claude-haiku-4-5": {
            "input": 1.00,
            "output": 5.00,
            "cache_read": 0.10,
            "cache_write": 1.25,
        },
    },
    "fallback_pricing": "error",
}

BASE_BUDGETS: dict[str, Any] = {
    "trip_ratio": 0.9,
    "fail_mode_on_counter_outage": "closed",
    "per_run": {
        "default": {
            "usd": 2.00,
            "model_calls": 50,
            "tool_calls": 100,
            "shell_calls": 30,
            "recursion_limit": 250,
            "wall_clock_s": 900,
        },
        "profiles": {
            "interactive": {"usd": 5.00, "wall_clock_s": 1800},
            "scheduled": {"usd": 2.00, "model_calls": 40},
            "incident": {"usd": 10.00, "wall_clock_s": 3600},
        },
    },
    "daily": {"global_usd": 50.00, "per_principal_usd": 25.00},
}


@pytest.fixture
def base_config() -> dict[str, Any]:
    return copy.deepcopy(BASE_CONFIG)


@pytest.fixture
def base_models() -> dict[str, Any]:
    return copy.deepcopy(BASE_MODELS)


@pytest.fixture
def base_budgets() -> dict[str, Any]:
    return copy.deepcopy(BASE_BUDGETS)


@pytest.fixture
def write_config(tmp_path: Path) -> Callable[..., Path]:
    """Factory: write config/models/budgets YAML into a fresh root and return the root path.

    Any argument left as None falls back to the shipped-equivalent baseline document,
    so tests only supply the file they intend to mutate.
    """

    def _write(
        config: dict[str, Any] | None = None,
        models: dict[str, Any] | None = None,
        budgets: dict[str, Any] | None = None,
    ) -> Path:
        cfg_dir = tmp_path / "config"
        cfg_dir.mkdir(parents=True, exist_ok=True)
        (cfg_dir / "config.yaml").write_text(
            yaml.safe_dump(config if config is not None else BASE_CONFIG)
        )
        (cfg_dir / "models.yaml").write_text(
            yaml.safe_dump(models if models is not None else BASE_MODELS)
        )
        (cfg_dir / "budgets.yaml").write_text(
            yaml.safe_dump(budgets if budgets is not None else BASE_BUDGETS)
        )
        return tmp_path

    return _write
