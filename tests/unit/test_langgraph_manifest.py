"""langgraph.json manifest + server_graph factory.

Validates the deployment manifest against the installed langgraph-cli schema, proves its graph
spec points at an importable callable, and proves ``server_graph()`` builds with NO checkpointer
(the platform injects Postgres persistence) and with the run-lifecycle book-ends enabled.
"""

from __future__ import annotations

import copy
import importlib
import json
from pathlib import Path
from typing import Any

import pytest

from graph.helpers import MODELS, budgets
from opendevops.config import AppConfig

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST = REPO_ROOT / "langgraph.json"


def _load_manifest() -> dict[str, Any]:
    return json.loads(MANIFEST.read_text())


def test_manifest_parses_and_has_expected_shape() -> None:
    manifest = _load_manifest()
    assert manifest["graphs"] == {"devops": "./src/opendevops/agent.py:server_graph"}
    assert manifest["dependencies"] == ["."]
    # The webhook app is mounted via http.app.
    assert manifest["http"] == {"app": "./src/opendevops/interfaces/webapp.py:app"}


def test_manifest_http_app_points_at_importable_asgi_app(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The ``http.app`` spec resolves to an importable module attribute (a FastAPI app)."""
    from fastapi import FastAPI

    spec = _load_manifest()["http"]["app"]
    path_part, _, attr = spec.partition(":")
    assert attr == "app"
    assert (REPO_ROOT / path_part.lstrip("./")).is_file()
    # The default app builds lazily from $OPENDEVOPS_CONFIG (points at the shipped config.yaml).
    monkeypatch.setenv("OPENDEVOPS_CONFIG", str(REPO_ROOT / "config" / "config.yaml"))
    module = importlib.import_module("opendevops.interfaces.webapp")
    app = getattr(module, attr)
    assert isinstance(app, FastAPI)


def test_manifest_validates_against_langgraph_cli_schema() -> None:
    """The manifest passes langgraph-cli's own ``validate_config`` (the deployment schema)."""
    from langgraph_cli.config import validate_config

    validated = validate_config(_load_manifest())
    assert validated["graphs"]["devops"].endswith(":server_graph")


def test_manifest_graph_spec_points_at_importable_callable() -> None:
    """The ``module.py:attr`` spec resolves to an importable, callable factory."""
    spec = _load_manifest()["graphs"]["devops"]
    path_part, _, attr = spec.partition(":")
    assert attr == "server_graph"
    # The file the spec names exists on disk.
    assert (REPO_ROOT / path_part.lstrip("./")).is_file()
    # And the attribute is importable + callable.
    module = importlib.import_module("opendevops.agent")
    factory = getattr(module, attr)
    assert callable(factory)


def test_server_graph_builds_with_no_checkpointer_and_run_lifecycle(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """server_graph() calls build_agent with checkpointer=None and run_lifecycle=True."""
    import opendevops.agent as agent_mod
    import opendevops.config as config_mod

    cfg = AppConfig.model_validate(
        {
            "targets": {"kubernetes": {"kubeconfig_ro": str(tmp_path / "k.yaml")}},
            "execution": {
                "cmd_timeout_seconds": 60,
                "output_max_chars": 50000,
                "env_allowlist": ["PATH"],
            },
            "audit": {"dir": str(tmp_path / "audit")},
            "policy": {"dir": str(REPO_ROOT / "config" / "policy")},
            "server": {"url": "http://localhost:8123"},
            "models": copy.deepcopy(MODELS),
            "budgets": budgets(),
        }
    )
    captured: dict[str, Any] = {}

    def _spy_build_agent(cfg_arg: AppConfig, **kwargs: Any) -> str:
        captured["cfg"] = cfg_arg
        captured["kwargs"] = kwargs
        return "SENTINEL_GRAPH"

    monkeypatch.setattr(config_mod, "load_config", lambda *_a, **_k: cfg)
    monkeypatch.setattr(agent_mod, "build_agent", _spy_build_agent)

    graph = agent_mod.server_graph()

    assert graph == "SENTINEL_GRAPH"
    assert captured["cfg"] is cfg
    assert captured["kwargs"]["checkpointer"] is None
    assert captured["kwargs"]["run_lifecycle"] is True
    # audit + counter are shared instances (built here, wired into the graph).
    assert captured["kwargs"]["audit"] is not None
    assert captured["kwargs"]["counter"] is not None


def test_load_server_config_uses_env_var(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """OPENDEVOPS_CONFIG points at .../config/config.yaml; the root is its grandparent."""
    import opendevops.agent as agent_mod
    import opendevops.config as config_mod

    captured: dict[str, Any] = {}

    def _fake_load_config(root: Any = None) -> str:
        captured["root"] = root
        return "CFG"

    monkeypatch.setattr(config_mod, "load_config", _fake_load_config)
    cfg_file = tmp_path / "myenv" / "config" / "config.yaml"
    cfg_file.parent.mkdir(parents=True)
    cfg_file.write_text("targets: {}")
    monkeypatch.setenv("OPENDEVOPS_CONFIG", str(cfg_file))

    assert agent_mod._load_server_config() == "CFG"
    # root is the grandparent of the config.yaml file (the project root load_config expects).
    assert captured["root"] == cfg_file.resolve().parent.parent


def test_load_server_config_default_cwd(monkeypatch: pytest.MonkeyPatch) -> None:
    """With OPENDEVOPS_CONFIG unset, load_config is called with no root (cwd => config/...)."""
    import opendevops.agent as agent_mod
    import opendevops.config as config_mod

    captured: dict[str, Any] = {}

    def _fake_load_config(root: Any = None) -> str:
        captured["called"] = True
        captured["root"] = root
        return "CFG"

    monkeypatch.setattr(config_mod, "load_config", _fake_load_config)
    monkeypatch.delenv("OPENDEVOPS_CONFIG", raising=False)

    assert agent_mod._load_server_config() == "CFG"
    assert captured["called"] is True
    assert captured["root"] is None
