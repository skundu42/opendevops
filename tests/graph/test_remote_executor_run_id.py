"""Remote executor split through the REAL graph (P5d): proves run_id binds via ``get_runtime()``.

This is the load-bearing integration check for the run_id-binding finding: on the remote path the
agent must sign a decision token bound to the run's ``run_id``, and that ``run_id`` is resolved
AMBIENTLY (``langgraph.runtime.get_runtime()``) inside the tool coroutine — never threaded through
the middleware or the tool signature. Here a real ``build_agent`` graph runs a run_command tool call
in ``executor.mode = remote`` against an in-process executor service; the RemoteExecutor's run_id
provider is the production ``_default_run_id`` (get_runtime), and we assert it resolved the SAME
run_id the run was invoked with — end-to-end, no network.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from langchain_core.messages import ToolMessage

from opendevops.config import AppConfig, ExecutorConfig
from opendevops.executor_service import create_app
from opendevops.tools import executor as executor_mod
from opendevops.tools.executor import LocalExecutor, RemoteExecutor, _default_run_id
from opendevops.tools.signing import generate_keypair

from .helpers import (
    ai_text,
    ai_tool_call,
    invoke_config,
    make_context,
    make_fake_model,
    start_run,
)


async def test_remote_path_binds_run_id_via_get_runtime(
    built_agent: Any, cfg: AppConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    priv, pub = generate_keypair()

    # In-process executor service (verifies the token, runs the subprocess). Real time so the
    # token the agent signs (exp = now+120) is valid when the service verifies it moments later.
    service = create_app(cfg, public_key=pub, executor=LocalExecutor())

    # The RemoteExecutor's run_id provider IS the production get_runtime path; record what it
    # resolves so we can assert it equals the run's run_id.
    resolved: dict[str, str] = {}

    def _record_run_id() -> str:
        rid = _default_run_id()  # langgraph.runtime.get_runtime(AgentContext).context.run_id
        resolved["run_id"] = rid
        return rid

    remote_cfg = cfg.model_copy(
        update={
            "executor": ExecutorConfig(
                mode="remote", url="http://svc", signing_key_env="UNUSED"
            )
        }
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=service), base_url="http://svc"
    ) as client:
        remote = RemoteExecutor(
            remote_cfg,
            client=client,
            private_key=priv,
            run_id_provider=_record_run_id,
        )
        # Route run_command to our injected RemoteExecutor (bypasses env-based key loading).
        monkeypatch.setattr(executor_mod, "select_executor", lambda _cfg: remote)

        fake = make_fake_model(
            [
                ai_tool_call(
                    "run_command",
                    {"argv": ["kubectl", "get", "pods", "--namespace", "default"]},
                    "call-1",
                ),
                ai_text("done"),
            ]
        )
        graph, audit, _ = built_agent(fake, cfg_override=remote_cfg)
        ctx = make_context("run-remote-xyz")
        start_run(audit, ctx)

        out = await graph.ainvoke(
            {"messages": [("user", "list pods")]},
            config=invoke_config(ctx.run_id),
            context=ctx,
        )

    # get_runtime resolved the CORRECT run_id inside the tool coroutine (the binding finding).
    assert resolved.get("run_id") == "run-remote-xyz"

    # And the full remote round-trip completed: the model saw a real execution result (kubectl is
    # absent in CI -> exit 127, but the token verified and the service executed), NOT a refusal.
    tool_msgs = [m for m in out["messages"] if isinstance(m, ToolMessage)]
    assert tool_msgs and tool_msgs[0].content.startswith("exit_code:")
