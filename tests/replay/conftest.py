"""Fixtures for the replay/eval tier.

Reuses the graph suite's pure builders (``graph.helpers``: ``BindableFake``, scripted-message
builders, the shipped-equivalent ``MODELS`` / ``budgets`` documents, the audit-chain helpers) and
points a *real* :func:`opendevops.agent.build_agent` at the *shipped* policy dir — so every
scenario exercises the real policy/audit/budget stack. Only two things are swapped:

* the chat model — ``registry.build_chat_model`` is monkeypatched to inject a scripted fake;
* the ``run_command`` **execution** — a :class:`ReplayToolMiddleware` is appended *after*
  ``PolicyMiddleware`` (making it the innermost tool-call wrap) by monkeypatching
  ``opendevops.agent.create_deep_agent`` to extend the middleware list build_agent hands it.

The ``create_deep_agent`` monkeypatch is the injection seam (see the report for why it was chosen
over reconstructing the middleware list or patching the list assembly): it reuses 100% of
``build_agent``'s wiring (summarizer swap, harness profiles, boot assertions) and only adds the
innermost wrap, which is exactly the placement the brief requires.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import opendevops.agent as agent_mod
from graph.helpers import MODELS, budgets  # noqa: F401  (re-exported for scenario modules)
from opendevops.audit.logger import AuditLogger
from opendevops.budget.daily import InMemoryDailyCounter
from opendevops.config import AppConfig
from opendevops.models import registry

from .replay_middleware import ReplayStep, ReplayToolMiddleware

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_DIR = REPO_ROOT / "config" / "policy"
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture
def audit_dir(tmp_path: Path) -> Path:
    """The tmp directory the AuditLogger writes per-run chain files into."""
    return tmp_path / "audit"


@pytest.fixture
def make_cfg(tmp_path: Path, audit_dir: Path) -> Callable[..., AppConfig]:
    """Factory: a validated :class:`AppConfig` on the shipped policy dir with tmp paths.

    Configures BOTH kubeconfig channels (a rw path so the mutate/escalate rules' ``channel: rw``
    executions have a credential family) and the gh token env (the gh-read pack's coverage gate).
    Replay never actually runs a subprocess, so the paths need not exist.

    The per-run *environment* (staging/prod) rides the run context via ``make_context``, not the
    config, so this factory takes no environment argument.
    """

    def _make() -> AppConfig:
        return AppConfig.model_validate(
            {
                "targets": {
                    "kubernetes": {
                        "kubeconfig_ro": str(tmp_path / "kubeconfig-ro.yaml"),
                        "kubeconfig_rw": str(tmp_path / "kubeconfig-rw.yaml"),
                        "allowed_contexts": ["kind-opendevops"],
                    },
                    "github": {
                        "token_env": "OPENDEVOPS_TEST_GH_TOKEN",
                        # gh-write rw coverage gate (write PAT name + repo allowlist; never
                        # exec'd in replay — the golden trajectories are gh reads).
                        "token_env_rw": "OPENDEVOPS_TEST_GH_TOKEN_RW",
                        "write_repos": ["octo-org/staging-app"],
                    },
                    # cloud read packs' coverage gate (names only; never exec'd in replay).
                    "aws": {"credential_env": ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]},
                    "gcloud": {"credential_env": ["GOOGLE_APPLICATION_CREDENTIALS"]},
                    "azure": {"credential_env": ["AZURE_CLIENT_ID", "AZURE_TENANT_ID"]},
                    # ssh-read pack coverage gate (names/paths only; never dialed in replay).
                    "ssh": {
                        "hosts": ["allowed.host.internal"],
                        "user": "deploy",
                        "key_env": "OPENDEVOPS_TEST_SSH_KEY",
                        "known_hosts_path": str(tmp_path / "known_hosts"),
                    },
                },
                "execution": {
                    "cmd_timeout_seconds": 60,
                    "output_max_chars": 50000,
                    "env_allowlist": ["PATH", "HOME"],
                },
                "audit": {"dir": str(audit_dir)},
                "policy": {"dir": str(POLICY_DIR)},
                "state": {"dir": str(tmp_path / "state")},
                "principals": {},
                "models": copy.deepcopy(MODELS),
                "budgets": budgets(),
            }
        )

    return _make


@pytest.fixture
def cfg(make_cfg: Callable[..., AppConfig]) -> AppConfig:
    """The default validated config (shipped-equivalent models + budgets, staging)."""
    return make_cfg()


@pytest.fixture
def replay_agent(
    monkeypatch: pytest.MonkeyPatch, cfg: AppConfig
) -> Callable[..., tuple[Any, AuditLogger, ReplayToolMiddleware]]:
    """Build the real agent with a scripted fake model + an innermost :class:`ReplayToolMiddleware`.

    Returns ``(graph, audit, replay)``. The ``replay`` middleware is returned so a scenario can
    assert the fixture was fully consumed. ``registry.build_chat_model`` is monkeypatched to inject
    the fake and ``agent_mod.create_deep_agent`` is wrapped to append the replay middleware — so the
    graph is otherwise assembled by the untouched production ``build_agent``.
    """

    def _build(
        fake_model: Any,
        steps: list[ReplayStep],
        *,
        cfg_override: AppConfig | None = None,
        checkpointer: Any = None,
    ) -> tuple[Any, AuditLogger, ReplayToolMiddleware]:
        use_cfg = cfg_override if cfg_override is not None else cfg
        replay = ReplayToolMiddleware(steps)

        real_create = agent_mod.create_deep_agent

        def _patched_create(**kwargs: Any) -> Any:
            middleware = [*kwargs.get("middleware", []), replay]
            return real_create(**{**kwargs, "middleware": middleware})

        monkeypatch.setattr(agent_mod, "create_deep_agent", _patched_create)
        monkeypatch.setattr(registry, "build_chat_model", lambda _cfg, _name: fake_model)

        audit = AuditLogger(use_cfg.audit.dir)
        counter = InMemoryDailyCounter()
        graph = agent_mod.build_agent(
            use_cfg, audit=audit, counter=counter, checkpointer=checkpointer
        )
        return graph, audit, replay

    return _build
