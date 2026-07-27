"""The audit-chain concurrency test.

The whole reason audit chains are PER-RUN (``audit/<run_id>.jsonl``) is that LangGraph Server runs
concurrently across workers and a shared-file ``prev_hash`` read-modify-write would race and
permanently break verification. This test models that topology in-process:

    N = 8 concurrent ``LocalGateway.run()`` calls (``asyncio.gather``), each on its OWN thread with
    its OWN scripted fake model, all sharing ONE audit dir (one ``AuditLogger``) and ONE daily
    counter.

and asserts three guarantees:

  1. every per-run chain file verifies (linkage + hash recomputation) — concurrency never corrupts
     a chain;
  2. no cross-run event bleed — every event in a run's file carries that run's ``run_id`` (uniform),
     and the ``run_id``s are all distinct;
  3. the daily counter total equals the SUM of the per-run charges — commutative accumulation holds
     under concurrent writers (global envelope), and each principal scope holds exactly its run.
"""

from __future__ import annotations

import asyncio
import copy
import json
from pathlib import Path
from typing import Any

import pytest

import opendevops.tools.run_command as run_command_mod
from graph.helpers import MODELS, BindableFake, budgets, usage
from opendevops.audit import verify_run_file
from opendevops.audit.logger import AuditLogger
from opendevops.budget.daily import InMemoryDailyCounter
from opendevops.config import AppConfig
from opendevops.gateway import LocalGateway
from opendevops.models import registry
from opendevops.tools.executor import ExecResult

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_DIR = REPO_ROOT / "config" / "policy"
_MAIN = "anthropic:claude-opus-4-8"
_PODS = ["kubectl", "get", "pods", "-n", "default"]

# One tool turn + one final text turn; usage priced on opus == 0.01 + 0.00375 = 0.01375 per run.
_PER_RUN_COST = 0.01375


def _tc(argv: list[str], call_id: str, usage_metadata: dict[str, Any]) -> Any:
    from langchain_core.messages import AIMessage

    return AIMessage(
        content="",
        tool_calls=[
            {"name": "run_command", "args": {"argv": argv}, "id": call_id, "type": "tool_call"}
        ],
        usage_metadata=usage_metadata,  # type: ignore[arg-type]
        response_metadata={"model_name": _MAIN},
    )


def _txt(text: str, usage_metadata: dict[str, Any]) -> Any:
    from langchain_core.messages import AIMessage

    return AIMessage(
        content=text,
        usage_metadata=usage_metadata,  # type: ignore[arg-type]
        response_metadata={"model_name": _MAIN},
    )


class _StubExecutor:
    """A run_command executor stand-in — returns ok without spawning a real subprocess."""

    def __init__(self, home: str) -> None:
        self._home = home

    @property
    def home(self) -> str:
        return self._home

    async def execute(self, argv: list[str], timeout_s: int, env: dict[str, str]) -> ExecResult:
        return ExecResult(exit_code=0, output="ok", duration_ms=1, timed_out=False)


def _make_cfg(base: Path) -> AppConfig:
    """A validated config on the shipped policy dir, with a per-gateway isolated state dir."""
    return AppConfig.model_validate(
        {
            "targets": {
                "kubernetes": {
                    "kubeconfig_ro": str(base / "kubeconfig-ro.yaml"),
                    "kubeconfig_rw": None,
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
            "audit": {"dir": str(base / "audit")},  # ignored: a SHARED AuditLogger is injected
            "policy": {"dir": str(POLICY_DIR)},
            "state": {"dir": str(base / "state")},   # DISTINCT per gateway (isolated checkpointer)
            "principals": {},
            "models": copy.deepcopy(MODELS),
            "budgets": budgets(),
        }
    )


async def test_concurrent_runs_produce_independent_verifiable_chains(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    n = 8
    shared_audit = AuditLogger(tmp_path / "audit")  # ONE shared audit dir for all N runs
    counter = InMemoryDailyCounter()                # ONE shared daily counter

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(run_command_mod, "_DEFAULT_EXECUTOR", _StubExecutor(str(home)))

    # One distinct main fake per run (each scripts an allowed tool call + a final text); a shared
    # haiku fake for the summarizer + log_summarizer-subagent slots (neither triggered by these
    # 2-message run_command runs). Gateways are built sequentially below, so the pop order
    # deterministically assigns fake i -> gateway i.
    main_fakes = [
        BindableFake(
            messages=iter(
                [
                    _tc(_PODS, f"c{i}", usage(input=1000, output=200)),
                    _txt(f"run {i} done.", usage(input=500, output=50)),
                ]
            )
        )
        for i in range(n)
    ]
    haiku_fake = BindableFake(messages=iter([]))
    queue = list(main_fakes)

    def _build_chat_model(_cfg: AppConfig, name: str) -> Any:
        return haiku_fake if name in ("summarizer", "log_summarizer") else queue.pop(0)

    monkeypatch.setattr(registry, "build_chat_model", _build_chat_model)

    gateways = [
        LocalGateway(_make_cfg(tmp_path / f"gw{i}"), audit=shared_audit, counter=counter)
        for i in range(n)
    ]
    assert not queue, "every main fake should have been consumed, one per gateway build"

    try:
        results = await asyncio.gather(
            *(
                gw.run(
                    f"thread-{i}",
                    "list pods",
                    principal=f"p{i}",
                    interface="cli",
                    environment="staging",
                )
                for i, gw in enumerate(gateways)
            )
        )
    finally:
        await asyncio.gather(*(gw.aclose() for gw in gateways))

    audit_dir = tmp_path / "audit"

    # (2) run_ids are all distinct — no two concurrent runs collided on a chain file.
    run_ids = [r.run_id for r in results]
    assert len(set(run_ids)) == n

    total_charge = 0.0
    for i, result in enumerate(results):
        assert result.error is None
        assert result.final_text == f"run {i} done."
        chain = audit_dir / f"{result.run_id}.jsonl"

        # (1) every per-run chain verifies under concurrency.
        assert verify_run_file(chain).ok, f"chain {result.run_id} failed verification"

        # (2) no cross-run event bleed: every event in the file carries THIS run's run_id, and the
        # chain is the full expected turn (book-ends + the tool decision/execution).
        events = [json.loads(ln) for ln in chain.read_text().splitlines() if ln.strip()]
        assert {e["run_id"] for e in events} == {result.run_id}
        assert [e["event_type"] for e in events] == [
            "run_started",
            "model_call",
            "decision",
            "execution",
            "model_call",
            "run_completed",
        ]

        # (3a) each principal scope holds exactly its own single run's charge.
        assert await counter.total(f"principal:p{i}") == pytest.approx(_PER_RUN_COST)
        assert result.cost_usd_state == pytest.approx(_PER_RUN_COST)
        total_charge += result.cost_usd_state

    # (3b) the global daily total == the sum of every run's charge (commutative accumulation).
    assert total_charge == pytest.approx(n * _PER_RUN_COST)
    assert await counter.total("global") == pytest.approx(total_charge)
