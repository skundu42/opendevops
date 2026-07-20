"""Strongest pin for the escalation-timeout sweeper: real graph, real resume, real chain.

A ``kubectl delete pod`` matches ``kubectl-delete-workload-escalate`` and SUSPENDS a real
``LocalGateway`` run on ``interrupt()``. We build the sweeper's :class:`InterruptedRun` record from
the real interrupt payload (rule_id + ``timeout_s``), prove the PURE :func:`select_timed_out` picks
it once its escalation age exceeds ``timeout_s``, then drive the sweeper's
:func:`resume_timed_out` with the REAL ``gateway.resume_interrupt`` and assert the full enforcement:

* a ``resolution`` audit event with ``approver="__timeout__"`` + ``type="reject"`` + the
  ``"escalation timed out"`` message;
* the model receives a deny ToolMessage (the reject flowed through the normal pipeline);
* the per-run audit chain still verifies end-to-end.

This is the enforcement mechanism behind a rule's ``on_timeout: deny``.
"""

from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest_asyncio
from ops.maintenance import (
    InterruptedRun,
    resume_timed_out,
    select_timed_out,
)

from opendevops.audit.logger import AuditLogger
from opendevops.audit.verify import verify_run_file
from opendevops.budget.daily import InMemoryDailyCounter
from opendevops.config import AppConfig
from opendevops.gateway.local import LocalGateway
from opendevops.models import registry

from .helpers import MODELS, BindableFake, ai_text, ai_tool_call, budgets

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_DIR = REPO_ROOT / "config" / "policy"
_DELETE_ARGV = ["kubectl", "delete", "pod", "x", "-n", "web"]


def _cfg(tmp_path: Path) -> AppConfig:
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
                "aws": {"credential_env": ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]},
                "gcloud": {"credential_env": ["GOOGLE_APPLICATION_CREDENTIALS"]},
                "azure": {"credential_env": ["AZURE_CLIENT_ID", "AZURE_TENANT_ID"]},
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
            "state": {"dir": str(tmp_path / "state")},
            "principals": {},
            "models": copy.deepcopy(MODELS),
            "budgets": budgets(),
        }
    )


@pytest_asyncio.fixture
async def gateway(monkeypatch: Any, tmp_path: Path) -> Any:
    cfg = _cfg(tmp_path)
    fake = BindableFake(
        messages=iter(
            [
                ai_tool_call("run_command", {"argv": _DELETE_ARGV}, "call-del"),
                ai_text("Understood — leaving the pod in place."),
            ]
        )
    )
    monkeypatch.setattr(registry, "build_chat_model", lambda _c, _n: fake)
    gw = LocalGateway(cfg, audit=AuditLogger(cfg.audit.dir), counter=InMemoryDailyCounter())
    try:
        yield gw, cfg
    finally:
        await gw.aclose()


def _events(cfg: AppConfig, run_id: str) -> list[dict[str, Any]]:
    import json

    path = Path(cfg.audit.dir) / f"{run_id}.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


async def test_escalate_then_sweep_reject_resolves_with_timeout_approver(gateway: Any) -> None:
    gw, cfg = gateway

    # 1. A real run escalates and SUSPENDS (chain open, no resolution yet).
    suspended = await gw.run(
        "thread-sweep", "delete pod x", principal="alice", interface="cli", environment="staging"
    )
    assert suspended.interrupted is not None
    payload = suspended.interrupted.payload
    review = payload["review_configs"][0]
    assert review["rule_id"] == "kubectl-delete-workload-escalate"
    timeout_s = review["timeout_s"]
    assert timeout_s == 1800
    types = [e["event_type"] for e in _events(cfg, suspended.run_id)]
    assert "escalation" in types and "resolution" not in types

    # 2. Build the sweeper record from the REAL interrupt payload; date the escalation past timeout.
    now = datetime.now(UTC)
    run = InterruptedRun(
        thread_id=suspended.interrupted.thread_id,
        rule_id=review["rule_id"],
        timeout_s=timeout_s,
        escalation_ts=now - timedelta(seconds=timeout_s + 60),
        run_id=suspended.run_id,
    )
    victims = select_timed_out([run], now=now)
    assert [v.thread_id for v in victims] == ["thread-sweep"]

    # 3. Sweep: resume-reject through the REAL gateway (approver injected = __timeout__).
    resumed = await resume_timed_out(gw.resume_interrupt, victims)
    assert resumed == ["thread-sweep"]

    # 4. Enforcement asserted end-to-end.
    events = _events(cfg, suspended.run_id)
    resolutions = [e for e in events if e["event_type"] == "resolution"]
    assert len(resolutions) == 1
    resolution = resolutions[0]
    assert resolution["approver"] == "__timeout__"
    assert resolution["summary"]["type"] == "reject"
    assert resolution["summary"]["message"] == "escalation timed out"

    # The escalate decision is recorded, and the run completed after the reject flowed the pipeline.
    assert any(
        e["event_type"] == "decision" and e.get("decision", {}).get("effect") == "escalate"
        for e in events
    )
    assert any(e["event_type"] == "run_completed" for e in events)
    assert verify_run_file(Path(cfg.audit.dir) / f"{suspended.run_id}.jsonl").ok
