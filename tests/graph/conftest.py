"""Fixtures for the graph-deterministic test suite (T8), reused by T9's gateway tests.

The fixtures materialize a real :class:`AppConfig` pointed at the *shipped* policy directory
(so the tests exercise the real rules) but with a tmp audit dir, a tmp read kubeconfig path, and
``allowed_contexts=["kind-opendevops"]``. ``built_agent`` monkeypatches
``registry.build_chat_model`` to return an injected fake model and calls the real
:func:`opendevops.agent.build_agent` with fresh audit + counter instances, returning all three
so a test can drive an invoke and then assert on the audit chain the middleware wrote.

Pure builders (fake models, scripted messages, context/audit helpers) live in
``tests/graph/helpers.py`` and are imported here so both are available to any graph/gateway test.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from opendevops.agent import build_agent
from opendevops.audit.logger import AuditLogger
from opendevops.budget.daily import InMemoryDailyCounter
from opendevops.config import AppConfig
from opendevops.models import registry

# Re-export the pure helpers (imported relative to this package so the import works regardless
# of whether pytest roots the package as `graph` or `tests.graph`). Test modules import them the
# same way: `from .helpers import ...`.
from .helpers import (  # noqa: F401
    MODELS,
    BindableFake,
    ai_text,
    ai_tool_call,
    budgets,
    chain_ok,
    event_types,
    invoke_config,
    make_context,
    make_fake_model,
    read_events,
    start_run,
    usage,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_DIR = REPO_ROOT / "config" / "policy"


@pytest.fixture
def audit_dir(tmp_path: Path) -> Path:
    """The tmp directory the AuditLogger writes per-run chain files into."""
    return tmp_path / "audit"


@pytest.fixture
def make_cfg(tmp_path: Path, audit_dir: Path) -> Callable[..., AppConfig]:
    """Factory: a validated :class:`AppConfig` on the shipped policy dir with tmp paths.

    ``models`` / ``budgets`` default to the shipped-equivalent documents; a test overrides only
    what it needs (an unpriced ``models`` to prove boot refusal, ``budgets(shell_calls=1)`` etc.).
    """

    def _make(
        models: dict[str, Any] | None = None, budgets_doc: dict[str, Any] | None = None
    ) -> AppConfig:
        kubeconfig = tmp_path / "kubeconfig-ro.yaml"
        # A real (empty) known_hosts file: resolve_ssh_credential now pre-flights is_file()
        # (Minor 1), and the ssh_run graph test reaches credential resolution before its stubbed
        # executor. Empty is acceptably fail-closed (asyncssh would reject all keys at connect).
        known_hosts = tmp_path / "known_hosts"
        known_hosts.touch()
        return AppConfig.model_validate(
            {
                "targets": {
                    "kubernetes": {
                        "kubeconfig_ro": str(kubeconfig),
                        "kubeconfig_rw": None,
                        "allowed_contexts": ["kind-opendevops"],
                    },
                    # P2: the gh-read pack's allow rules require the gh credential family
                    # to be configured or build_agent refuses to boot (coverage gate). P5f: the
                    # gh-write pack's rw allows additionally require the rw write PAT (token_env_rw
                    # => the "gh-rw" pseudo-family) and its write_repos allowlist at boot.
                    "github": {
                        "token_env": "OPENDEVOPS_TEST_GH_TOKEN",
                        "token_env_rw": "OPENDEVOPS_TEST_GH_TOKEN_RW",
                        "write_repos": ["octo-org/staging-app"],
                    },
                    # P5a: the aws/gcloud/az-read packs' allow rules require their cloud
                    # credential families configured (coverage gate). Naming the env vars is
                    # enough for boot; their VALUES are only read at exec time, which these
                    # fake-model graph tests never reach.
                    "aws": {"credential_env": ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]},
                    "gcloud": {"credential_env": ["GOOGLE_APPLICATION_CREDENTIALS"]},
                    "azure": {"credential_env": ["AZURE_CLIENT_ID", "AZURE_TENANT_ID"]},
                    # P5b: the ssh-read pack's allow rule requires the ssh credential family at
                    # boot (coverage gate). Names/paths only; asyncssh is never dialed in these
                    # fake-model tests, which don't reach an ssh_run execution.
                    "ssh": {
                        "hosts": ["allowed.host.internal"],
                        "user": "deploy",
                        "key_env": "OPENDEVOPS_TEST_SSH_KEY",
                        "known_hosts_path": str(known_hosts),
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
                "models": models if models is not None else copy.deepcopy(MODELS),
                "budgets": budgets_doc if budgets_doc is not None else budgets(),
            }
        )

    return _make


@pytest.fixture
def cfg(make_cfg: Callable[..., AppConfig]) -> AppConfig:
    """The default validated config (shipped-equivalent models + budgets)."""
    return make_cfg()


@pytest.fixture
def built_agent(
    monkeypatch: pytest.MonkeyPatch, cfg: AppConfig
) -> Callable[..., tuple[Any, AuditLogger, InMemoryDailyCounter]]:
    """Build the real agent with an injected fake model + fresh audit/counter.

    Returns ``(graph, audit, counter)``. ``registry.build_chat_model`` is monkeypatched to return
    the fake (``registry.resolve`` stays real, so the model_key is the true
    ``anthropic:claude-opus-4-8`` and pricing/limits are wired exactly as production).
    """

    def _build(
        fake_model: Any,
        *,
        cfg_override: AppConfig | None = None,
        counter: InMemoryDailyCounter | None = None,
        checkpointer: Any = None,
        run_lifecycle: bool = False,
    ) -> tuple[Any, AuditLogger, InMemoryDailyCounter]:
        use_cfg = cfg_override if cfg_override is not None else cfg
        monkeypatch.setattr(
            registry, "build_chat_model", lambda _cfg, _name: fake_model
        )
        audit = AuditLogger(use_cfg.audit.dir)
        cnt = counter if counter is not None else InMemoryDailyCounter()
        graph = build_agent(
            use_cfg,
            audit=audit,
            counter=cnt,
            checkpointer=checkpointer,
            run_lifecycle=run_lifecycle,
        )
        return graph, audit, cnt

    return _build
