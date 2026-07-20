"""RemoteExecutor round-trip against an IN-PROCESS executor service (no real network).

Drives ``run_command_core`` with ``executor.mode = remote`` and a RemoteExecutor whose httpx client
is an ``ASGITransport`` over the real service app. Asserts the remote path yields the SAME
ToolMessage / EXEC_META contract as the local path, still runs the decision gate agent-side, and
never calls ``build_env`` on the agent (zero credentials held).
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import httpx
import pytest
from deepagents.backends.utils import create_file_data
from langchain_core.messages import ToolMessage
from langgraph.types import Command

# reuse the config + doubles from the service test
from tests.unit.test_executor_service import DictSource, SpyExecutor, make_cfg

from opendevops.executor_service import create_app
from opendevops.tools.executor import ExecResult, LocalExecutor, RemoteExecutor
from opendevops.tools.run_command import (
    EXEC_META_KEY,
    ExecDecision,
    current_decision,
    run_command_core,
)
from opendevops.tools.signing import generate_keypair


@contextmanager
def decision(dec: ExecDecision) -> Iterator[None]:
    tok = current_decision.set(dec)
    try:
        yield
    finally:
        current_decision.reset(tok)


def _exec_meta(out: Any) -> dict[str, Any] | None:
    msg: ToolMessage | None = None
    if isinstance(out, ToolMessage):
        msg = out
    elif isinstance(out, Command):
        for m in out.update.get("messages", []):
            if isinstance(m, ToolMessage):
                msg = m
                break
    return None if msg is None else msg.additional_kwargs.get(EXEC_META_KEY)


def _content(out: Any) -> str:
    if isinstance(out, ToolMessage):
        return str(out.content)
    if isinstance(out, Command):
        for m in out.update.get("messages", []):
            if isinstance(m, ToolMessage):
                return str(m.content)
    return str(out)


def _remote_cfg(tmp: str):
    return make_cfg(tmp, mode="remote", url="http://svc", signing_key_env="AGENT_SIGN_KEY")


def _remote_executor(agent_cfg, app, priv, *, client: httpx.AsyncClient) -> RemoteExecutor:
    return RemoteExecutor(
        agent_cfg,
        client=client,
        private_key=priv,
        run_id_provider=lambda: "run-1",
        now=lambda: 1000.0,
    )


def _service(tmp: str, pub, *, executor: Any, secrets: dict[str, str] | None = None):
    return create_app(
        make_cfg(tmp),
        public_key=pub,
        secret_source=DictSource(secrets or {}),
        executor=executor,
        now=lambda: 1000.0,
    )


# --------------------------------------------------------------------------------------


async def test_remote_roundtrip_matches_local_exec_meta(tmp_path: Any) -> None:
    priv, pub = generate_keypair()
    app = _service(str(tmp_path / "svc"), pub, executor=LocalExecutor())
    agent_cfg = _remote_cfg(str(tmp_path / "agent"))
    dec = ExecDecision(tool_call_id="call-1", channel="ro", tool_family=None, argv=("true",))

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://svc"
    ) as client:
        remote = _remote_executor(agent_cfg, app, priv, client=client)
        with decision(dec):
            remote_out = await run_command_core(
                ["true"], 60, agent_cfg, tool_call_id="call-1", executor=remote, files={}
            )
            local_out = await run_command_core(
                ["true"], 60, make_cfg(str(tmp_path / "local")), tool_call_id="call-1", files={}
            )

    r_meta = _exec_meta(remote_out)
    l_meta = _exec_meta(local_out)
    assert r_meta is not None and l_meta is not None
    # identical contract: exit code, stdout sha, truncation flag, staged files
    assert r_meta["exit_code"] == l_meta["exit_code"] == 0
    assert r_meta["stdout_sha256"] == l_meta["stdout_sha256"]
    assert r_meta["truncated"] == l_meta["truncated"] is False
    assert r_meta["staged_files"] == l_meta["staged_files"] == []
    assert set(r_meta) == set(l_meta)
    assert _content(remote_out) == _content(local_out)


async def test_remote_roundtrip_staged_files_recorded(tmp_path: Any) -> None:
    priv, pub = generate_keypair()
    app = _service(str(tmp_path / "svc"), pub, executor=LocalExecutor())
    agent_cfg = _remote_cfg(str(tmp_path / "agent"))
    argv = ["kubectl", "apply", "-f", "/manifests/deploy.yaml"]
    files = {"/manifests/deploy.yaml": create_file_data("apiVersion: v1\nkind: ConfigMap\n")}
    dec = ExecDecision(
        tool_call_id="call-1", channel="ro", tool_family="kubectl", argv=tuple(argv)
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://svc"
    ) as client:
        remote = _remote_executor(agent_cfg, app, priv, client=client)
        with decision(dec):
            out = await run_command_core(
                argv, 60, agent_cfg, tool_call_id="call-1", executor=remote, files=files
            )
    meta = _exec_meta(out)
    assert meta is not None
    # the staged manifest is recorded agent-side for audit (identical to the local path)
    assert meta["staged_files"] == [
        {"path": "/manifests/deploy.yaml", "sha256": meta["staged_files"][0]["sha256"]}
    ]
    assert len(meta["staged_files"][0]["sha256"]) == 64


async def test_remote_secret_never_appears_in_toolmessage(tmp_path: Any) -> None:
    priv, pub = generate_keypair()
    secret = "REMOTE-SECRET-abc123"
    # a fake service executor that "leaks" the value into stdout; the service must scrub it.
    leak = SpyExecutor(output=f"leaked {secret} to stdout")
    app = _service(str(tmp_path / "svc"), pub, executor=leak, secrets={"TOK": secret})
    agent_cfg = _remote_cfg(str(tmp_path / "agent"))
    argv = ["myapp", "--auth", "{{secret:TOK}}"]
    dec = ExecDecision(tool_call_id="call-1", channel="ro", tool_family=None, argv=tuple(argv))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://svc"
    ) as client:
        remote = _remote_executor(agent_cfg, app, priv, client=client)
        with decision(dec):
            out = await run_command_core(
                argv, 60, agent_cfg, tool_call_id="call-1", executor=remote, files={}
            )
    meta = _exec_meta(out)
    assert meta is not None
    # the value is nowhere on the agent side: not in the message, not in the meta
    assert secret not in _content(out)
    assert secret not in str(meta)
    # the argv the agent sent carried only the {{secret:...}} token — the VALUE was resolved
    # in the service; the leaked stdout came back scrubbed.
    assert "***" in _content(out)
    # M2: EXEC_META.scrub_count reflects the SERVICE's authoritative count (>=1), not the agent's
    # idempotent re-scrub of the already-scrubbed output.
    assert meta["scrub_count"] >= 1


async def test_remote_exec_meta_scrub_count_is_service_count(tmp_path: Any) -> None:
    """M2: the remote path reports the service's scrub_count, not the agent's (~0) re-scrub."""
    priv, pub = generate_keypair()
    secret = "SCRUBME-XYZ-9988"
    leak = SpyExecutor(output=f"a={secret} b={secret} c={secret}")  # 3 literal occurrences
    app = _service(str(tmp_path / "svc"), pub, executor=leak, secrets={"TOK": secret})
    agent_cfg = _remote_cfg(str(tmp_path / "agent"))
    argv = ["tool", "{{secret:TOK}}"]
    dec = ExecDecision(tool_call_id="call-1", channel="ro", tool_family=None, argv=tuple(argv))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://svc"
    ) as client:
        remote = _remote_executor(agent_cfg, app, priv, client=client)
        with decision(dec):
            out = await run_command_core(
                argv, 60, agent_cfg, tool_call_id="call-1", executor=remote, files={}
            )
    meta = _exec_meta(out)
    assert meta is not None
    assert secret not in _content(out)
    assert meta["scrub_count"] == 3  # the service redacted all three occurrences


async def test_remote_path_does_not_call_build_env_on_agent(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The agent holds no credential: build_env must never run in-process on the remote path."""
    priv, pub = generate_keypair()
    app = _service(str(tmp_path / "svc"), pub, executor=LocalExecutor())
    agent_cfg = _remote_cfg(str(tmp_path / "agent"))

    calls: list[Any] = []

    def _boom(*a: Any, **k: Any) -> dict[str, str]:
        calls.append(a)
        raise AssertionError("build_env must not run on the agent in remote mode")

    monkeypatch.setattr("opendevops.tools.run_command.build_env", _boom)
    dec = ExecDecision(tool_call_id="call-1", channel="ro", tool_family=None, argv=("true",))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://svc"
    ) as client:
        remote = _remote_executor(agent_cfg, app, priv, client=client)
        with decision(dec):
            out = await run_command_core(
                ["true"], 60, agent_cfg, tool_call_id="call-1", executor=remote, files={}
            )
    assert calls == []  # build_env never touched
    assert _exec_meta(out) is not None  # and the exec still succeeded via the service


async def test_remote_decision_gate_runs_before_signing(tmp_path: Any) -> None:
    """A gate mismatch refuses agent-side — the service (spy) is never reached."""
    priv, pub = generate_keypair()
    spy = SpyExecutor()
    app = _service(str(tmp_path / "svc"), pub, executor=spy)
    agent_cfg = _remote_cfg(str(tmp_path / "agent"))
    # decision authorizes a DIFFERENT argv than what is run
    dec = ExecDecision(
        tool_call_id="call-1", channel="ro", tool_family=None, argv=("kubectl", "get", "pods")
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://svc"
    ) as client:
        remote = _remote_executor(agent_cfg, app, priv, client=client)
        with decision(dec):
            out = await run_command_core(
                ["kubectl", "delete", "pods"], 60, agent_cfg,
                tool_call_id="call-1", executor=remote, files={},
            )
    assert out == "execution refused: no policy decision"
    assert not spy.called  # never signed, never posted, never executed


async def test_remote_transport_failure_fails_closed(tmp_path: Any) -> None:
    priv, _pub = generate_keypair()
    agent_cfg = _remote_cfg(str(tmp_path / "agent"))

    class _BrokenClient:
        async def post(self, *a: Any, **k: Any) -> Any:
            raise httpx.ConnectError("no route to service")

    remote = RemoteExecutor(
        agent_cfg,
        client=_BrokenClient(),  # type: ignore[arg-type]
        private_key=priv,
        run_id_provider=lambda: "run-1",
        now=lambda: 1000.0,
    )
    dec = ExecDecision(tool_call_id="call-1", channel="ro", tool_family=None, argv=("true",))
    with decision(dec):
        out = await run_command_core(
            ["true"], 60, agent_cfg, tool_call_id="call-1", executor=remote, files={}
        )
    assert isinstance(out, str)
    assert out.startswith("execution refused:")
    assert "unreachable" in out


def test_service_result_maps_to_exec_result() -> None:
    """A well-formed service response maps cleanly to the shared ExecResult shape."""
    r = ExecResult(exit_code=0, output="ok", duration_ms=3, timed_out=False)
    assert (r.exit_code, r.output, r.timed_out) == (0, "ok", False)
