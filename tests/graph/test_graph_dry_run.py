"""Graph-level dry-run enforcement flow: write_file -> apply -> real apply.

Two scenarios through the REAL agent graph + REAL shipped policy:

* happy path — the model writes a manifest, issues a bare ``kubectl apply -f`` (the engine
  rewrites it to ``--dry-run=server`` and the successful dry-run records the manifest sha), then
  issues ``kubectl apply -f ... --dry-run=none`` which the hook now permits. Both applies execute;
  the audit chain shows the rewrite (with ``--dry-run=server`` in ``rewritten_argv``) then the
  allow, and verifies.
* deny-first — the model tries the real apply (``--dry-run=none``) BEFORE any dry-run; the hook
  denies it with ``require-dry-run-before-real-apply``.

The subprocess is faked (a fake executor returning exit 0) so the dry-run deterministically
succeeds — the point is the policy composition + state recording, not kubectl itself. A rw
kubeconfig path is configured so ``build_env`` grants the ``rw`` apply its credential.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest
from langchain_core.messages import ToolMessage

import opendevops.tools.run_command as run_command_mod
from opendevops.config import AppConfig
from opendevops.tools.executor import ExecResult

from .helpers import (
    MODELS,
    ai_text,
    ai_tool_call,
    budgets,
    chain_ok,
    invoke_config,
    make_context,
    make_fake_model,
    read_events,
    start_run,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_DIR = REPO_ROOT / "config" / "policy"

MANIFEST = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: demo\n"
MANIFEST_PATH = "/manifests/deploy.yaml"


class _FakeExecutor:
    """A run_command executor stand-in: every exec succeeds (exit 0), no real subprocess."""

    def __init__(self, home: str) -> None:
        self._home = home

    @property
    def home(self) -> str:
        return self._home

    async def execute(self, argv: list[str], timeout_s: int, env: dict[str, str]) -> ExecResult:
        return ExecResult(
            exit_code=0,
            output="configmap/demo configured (dry run)",
            duration_ms=1,
            timed_out=False,
        )


def _cfg_with_rw(tmp_path: Path) -> AppConfig:
    """A validated config on the shipped policy dir with a configured rw kubeconfig path."""
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
                    "token_env_rw": "OPENDEVOPS_TEST_GH_TOKEN_RW",  # gh-write rw gate
                    "write_repos": ["octo-org/staging-app"],
                },
                # cloud read packs' coverage gate (names only; not exec'd here).
                "aws": {
                    "credential_env": ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"],
                    "credential_env_rw": ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"],
                },
                "gcloud": {
                    "credential_env": ["GOOGLE_APPLICATION_CREDENTIALS"],
                    "credential_env_rw": ["GOOGLE_APPLICATION_CREDENTIALS"],
                },
                "azure": {
                    "credential_env": ["AZURE_CLIENT_ID", "AZURE_TENANT_ID"],
                    "credential_env_rw": ["AZURE_CLIENT_ID", "AZURE_TENANT_ID"],
                },
                # ssh-read pack coverage gate (names/paths only; never dialed here).
                "ssh": {
                    "hosts": ["allowed.host.internal"],
                    "user": "deploy",
                    "key_env": "OPENDEVOPS_TEST_SSH_KEY",
                    "known_hosts_path": "/nonexistent/known_hosts",
                },
            },
            "execution": {
                "cmd_timeout_seconds": 60,
                "output_max_chars": 50000,
                "env_allowlist": ["PATH", "HOME"],
            },
            "audit": {"dir": str(tmp_path / "audit")},
            "policy": {"dir": str(POLICY_DIR)},
            "principals": {},
            "models": copy.deepcopy(MODELS),
            "budgets": budgets(),
        }
    )


def _tool_messages(state: dict[str, Any]) -> list[ToolMessage]:
    return [m for m in state["messages"] if isinstance(m, ToolMessage)]


def _decision_for(events: list[dict[str, Any]], tool_call_id: str) -> dict[str, Any]:
    return next(
        e
        for e in events
        if e["event_type"] == "decision" and e.get("tool_call_id") == tool_call_id
    )


async def test_dry_run_first_then_real_apply_flow(
    built_agent: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(run_command_mod, "_DEFAULT_EXECUTOR", _FakeExecutor(str(home)))

    cfg = _cfg_with_rw(tmp_path)
    fake = make_fake_model(
        [
            ai_tool_call(
                "write_file", {"file_path": MANIFEST_PATH, "content": MANIFEST}, "call-write"
            ),
            ai_tool_call(
                "run_command", {"argv": ["kubectl", "apply", "-f", MANIFEST_PATH]}, "call-dry"
            ),
            ai_tool_call(
                "run_command",
                {"argv": ["kubectl", "apply", "-f", MANIFEST_PATH, "--dry-run=none"]},
                "call-real",
            ),
            ai_text("Applied the manifest after a successful server-side dry run."),
        ]
    )
    graph, audit, _ = built_agent(fake, cfg_override=cfg)
    ctx = make_context("run-dry-flow")
    start_run(audit, ctx)

    out = await graph.ainvoke(
        {"messages": [("user", "deploy the configmap")]},
        config=invoke_config(ctx.run_id),
        context=ctx,
    )

    # Both applies executed (the fake executor exit_code:0 output is what the model saw).
    tool_msgs = _tool_messages(out)
    apply_outputs = [m for m in tool_msgs if m.content.startswith("exit_code:")]
    assert len(apply_outputs) == 2

    events = read_events(cfg.audit.dir, ctx.run_id)

    # 1st apply: rewritten to --dry-run=server (dry-run-first enforcement).
    dry = _decision_for(events, "call-dry")
    assert dry["decision"]["effect"] == "rewrite"
    assert dry["decision"]["rule_id"] == "force-server-dry-run-first"
    assert dry["decision"]["rewritten_argv"][-1] == "--dry-run=server"

    # its execution recorded the applied manifest in staged_files.
    dry_exec = next(
        e
        for e in events
        if e["event_type"] == "execution" and e.get("tool_call_id") == "call-dry"
    )
    assert MANIFEST_PATH in {f["path"] for f in dry_exec["execution"]["staged_files"]}

    # 2nd apply: the real apply (--dry-run=none) is now permitted by the plain allow.
    real = _decision_for(events, "call-real")
    assert real["decision"]["effect"] == "allow"
    assert real["decision"]["rule_id"] == "kubectl-apply"

    assert chain_ok(cfg.audit.dir, ctx.run_id)


async def test_real_apply_before_dry_run_is_denied(
    built_agent: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(run_command_mod, "_DEFAULT_EXECUTOR", _FakeExecutor(str(home)))

    cfg = _cfg_with_rw(tmp_path)
    fake = make_fake_model(
        [
            ai_tool_call(
                "write_file", {"file_path": MANIFEST_PATH, "content": MANIFEST}, "call-write"
            ),
            ai_tool_call(
                "run_command",
                {"argv": ["kubectl", "apply", "-f", MANIFEST_PATH, "--dry-run=none"]},
                "call-real-first",
            ),
            ai_text("I need to dry-run first."),
        ]
    )
    graph, audit, _ = built_agent(fake, cfg_override=cfg)
    ctx = make_context("run-dry-deny")
    start_run(audit, ctx)

    out = await graph.ainvoke(
        {"messages": [("user", "apply it now")]},
        config=invoke_config(ctx.run_id),
        context=ctx,
    )

    tool_msgs = _tool_messages(out)
    deny = next(m for m in tool_msgs if m.status == "error")
    assert "Denied by policy [require-dry-run-before-real-apply]" in deny.content

    events = read_events(cfg.audit.dir, ctx.run_id)
    dec = _decision_for(events, "call-real-first")
    assert dec["decision"]["effect"] == "deny"
    assert dec["decision"]["rule_id"] == "require-dry-run-before-real-apply"
    # a real apply was refused, so no execution event fired for it
    assert not any(
        e["event_type"] == "execution" and e.get("tool_call_id") == "call-real-first"
        for e in events
    )
    assert chain_ok(cfg.audit.dir, ctx.run_id)
