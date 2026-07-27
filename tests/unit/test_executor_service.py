"""Executor service: verifies-then-executes on a good token; rejects a tampered token
WITHOUT running (a spy proves no exec) — including the C1 attacks (substituted content, rewritten
staging metadata, swapped tool_family) and the I1 replay; materializes staged files; resolves
secrets into env not argv; full-scrubs known secret values from the output.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import shutil
from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest

from opendevops.config import AppConfig
from opendevops.executor_service import create_app
from opendevops.tools.executor import ExecResult, LocalExecutor
from opendevops.tools.signing import DecisionToken, generate_keypair, sign_decision

# Async tests are auto-collected (pyproject: asyncio_mode = "auto").


# --------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------


def make_cfg(tmp: str, **executor: Any) -> AppConfig:
    data: dict[str, Any] = {
        "targets": {
            "kubernetes": {
                "kubeconfig_ro": f"{tmp}/kro.yaml",
                "kubeconfig_rw": None,
                "allowed_contexts": [],
            }
        },
        "execution": {
            "cmd_timeout_seconds": 60,
            "output_max_chars": 50000,
            "env_allowlist": ["PATH", "HOME"],
        },
        "audit": {"dir": f"{tmp}/audit"},
        "policy": {"dir": "./config/policy"},
        "models": {
            "agents": {"main": "opus"},
            "aliases": {"opus": "anthropic:claude-opus-4-8"},
            "pricing": {
                "anthropic:claude-opus-4-8": {
                    "input": 5.0,
                    "output": 25.0,
                    "cache_read": 0.5,
                    "cache_write": 6.25,
                }
            },
            "fallback_pricing": "error",
        },
        "budgets": {
            "trip_ratio": 0.9,
            "fail_mode_on_counter_outage": "closed",
            "per_run": {
                "default": {
                    "usd": 2.0,
                    "model_calls": 50,
                    "tool_calls": 100,
                    "shell_calls": 30,
                    "recursion_limit": 250,
                    "wall_clock_s": 900,
                }
            },
            "daily": {"global_usd": 50.0, "per_principal_usd": 25.0},
        },
    }
    if executor:
        data["executor"] = executor
    return AppConfig.model_validate(data)


@dataclass
class DictSource:
    data: dict[str, str] = field(default_factory=dict)

    def get(self, name: str) -> str | None:
        return self.data.get(name)


@dataclass
class Staged:
    """A staged file: `.to_wire()` for the request body, itself a StagedFileLike for signing."""

    flag: str = "--filename"
    virtual_path: str = "/manifests/deploy.yaml"
    content: str = "apiVersion: v1\nkind: ConfigMap\n"
    argv_index: int = 3
    inline: bool = False
    inline_prefix: str | None = None

    def to_wire(self) -> dict[str, Any]:
        return {
            "flag": self.flag,
            "virtual_path": self.virtual_path,
            "content": self.content,
            "sha256": hashlib.sha256(self.content.encode("utf-8")).hexdigest(),
            "argv_index": self.argv_index,
            "inline": self.inline,
            "inline_prefix": self.inline_prefix,
        }


@dataclass
class SpyExecutor:
    """Records whether/what execute() ran (proves a rejected request never reaches a subprocess)."""

    home: str = "/tmp/spy-home"
    called: bool = False
    calls: list[dict[str, Any]] = field(default_factory=list)
    output: str = ""
    exit_code: int = 0

    async def execute(self, argv: list[str], timeout_s: int, env: dict[str, str]) -> ExecResult:
        self.called = True
        staged: dict[str, str] = {}
        for tok in argv:
            path = tok.split("=", 1)[-1]  # handle --flag=path
            if os.path.isfile(path):
                with open(path, encoding="utf-8") as fh:
                    staged[path] = fh.read()
        self.calls.append(
            {"argv": list(argv), "env": dict(env), "timeout": timeout_s, "staged": staged}
        )
        return ExecResult(
            exit_code=self.exit_code, output=self.output, duration_ms=1, timed_out=False
        )


def _client(app: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://svc")


def _sign(
    priv: Any,
    argv: list[str],
    *,
    staged: tuple[Staged, ...] = (),
    run_id: str = "run-1",
    tcid: str = "call-1",
    channel: str = "ro",
    family: str | None = None,
    environment: str = "staging",
    host: str | None = None,
    now: float = 1000.0,
) -> DecisionToken:
    return sign_decision(
        argv,
        list(staged),
        run_id,
        tcid,
        channel,
        family,
        priv,
        environment=environment,
        host=host,
        now=lambda: now,
    )


def _body(
    argv: list[str],
    token: DecisionToken,
    *,
    run_id: str = "run-1",
    tcid: str = "call-1",
    channel: str = "ro",
    family: str | None = None,
    environment: str = "staging",
    host: str | None = None,
    timeout: int = 60,
    staged_wire: tuple[dict[str, Any], ...] = (),
) -> dict[str, Any]:
    return {
        "argv": argv,
        "run_id": run_id,
        "tool_call_id": tcid,
        "channel": channel,
        "environment": environment,
        "tool_family": family,
        "host": host,
        "timeout_s": timeout,
        "staged_files": list(staged_wire),
        "token": token.to_dict(),
    }


def _app(cfg: Any, *args: Any, **kwargs: Any):
    """create_app with default staging/ro identity for unit tests."""
    kwargs.setdefault("identity_environment", "staging")
    kwargs.setdefault("identity_channel", "ro")
    if args:
        kwargs.setdefault("public_key", args[0])
    return create_app(cfg, **kwargs)


# --------------------------------------------------------------------------------------
# verifies-then-executes on a good token
# --------------------------------------------------------------------------------------


async def test_good_token_verifies_then_executes(tmp_path: Any) -> None:
    priv, pub = generate_keypair()
    spy = SpyExecutor(output="ran-ok")
    app = _app(
        make_cfg(str(tmp_path)), public_key=pub, secret_source=DictSource(), executor=spy,
        now=lambda: 1050.0,
    )
    argv = ["kubectl", "get", "pods"]
    token = _sign(priv, argv, family="kubectl")
    async with _client(app) as client:
        resp = await client.post("http://svc/execute", json=_body(argv, token, family="kubectl"))
    assert resp.status_code == 200
    assert spy.called
    data = resp.json()
    assert data["exit_code"] == 0 and data["output"] == "ran-ok"


async def test_faithful_staged_request_executes_and_materializes(tmp_path: Any) -> None:
    priv, pub = generate_keypair()
    spy = SpyExecutor()
    app = _app(make_cfg(str(tmp_path)), public_key=pub, executor=spy, now=lambda: 1000.0)
    argv = ["kubectl", "apply", "-f", "/manifests/deploy.yaml"]
    staged = Staged(argv_index=3, content="apiVersion: apps/v1\nkind: Deployment\n")
    token = _sign(priv, argv, staged=(staged,), family="kubectl")
    async with _client(app) as client:
        resp = await client.post(
            "http://svc/execute",
            json=_body(argv, token, family="kubectl", staged_wire=(staged.to_wire(),)),
        )
    assert resp.status_code == 200 and spy.called
    call = spy.calls[0]
    assert call["argv"][3] != "/manifests/deploy.yaml"  # rewritten to on-disk path
    assert staged.content in call["staged"].values()  # correct content materialized


# --------------------------------------------------------------------------------------
# rejects WITHOUT executing — token integrity (unsigned / expired / hash / channel)
# --------------------------------------------------------------------------------------


async def test_unsigned_rejected_without_executing(tmp_path: Any) -> None:
    _, pub = generate_keypair()
    spy = SpyExecutor()
    app = _app(make_cfg(str(tmp_path)), public_key=pub, executor=spy)
    async with _client(app) as client:
        resp = await client.post(
            "http://svc/execute",
            json={
                "argv": ["kubectl", "get", "pods"],
                "run_id": "run-1",
                "tool_call_id": "call-1",
                "channel": "ro",
                "environment": "staging",
                "timeout_s": 60,
                "staged_files": [],
                "token": {},  # unsigned / malformed
            },
        )
    assert resp.status_code == 403 and not spy.called


async def test_expired_rejected_without_executing(tmp_path: Any) -> None:
    priv, pub = generate_keypair()
    spy = SpyExecutor()
    app = _app(make_cfg(str(tmp_path)), public_key=pub, executor=spy, now=lambda: 9999.0)
    argv = ["kubectl", "get", "pods"]
    token = _sign(priv, argv, family="kubectl")
    async with _client(app) as client:
        resp = await client.post("http://svc/execute", json=_body(argv, token, family="kubectl"))
    assert resp.status_code == 403 and not spy.called


async def test_argv_hash_mismatch_rejected_without_executing(tmp_path: Any) -> None:
    priv, pub = generate_keypair()
    spy = SpyExecutor()
    app = _app(make_cfg(str(tmp_path)), public_key=pub, executor=spy, now=lambda: 1000.0)
    token = _sign(priv, ["kubectl", "get", "pods"], family="kubectl")
    async with _client(app) as client:
        resp = await client.post(
            "http://svc/execute",
            json=_body(["kubectl", "delete", "pods"], token, family="kubectl"),
        )
    assert resp.status_code == 403 and not spy.called


async def test_wrong_channel_rejected_without_executing(tmp_path: Any) -> None:
    priv, pub = generate_keypair()
    spy = SpyExecutor()
    app = _app(make_cfg(str(tmp_path)), public_key=pub, executor=spy, now=lambda: 1000.0)
    argv = ["kubectl", "get", "pods"]
    token = _sign(priv, argv, channel="ro", family="kubectl")
    async with _client(app) as client:
        resp = await client.post(
            "http://svc/execute", json=_body(argv, token, channel="rw", family="kubectl")
        )
    assert resp.status_code == 403 and not spy.called


# --------------------------------------------------------------------------------------
# C1 attacks — the service must run ONLY the signed decision (spy proves no run)
# --------------------------------------------------------------------------------------


async def test_substituted_content_rejected_without_executing(tmp_path: Any) -> None:
    """Token signed for content A; request carries content B (same metadata) -> 403, no run."""
    priv, pub = generate_keypair()
    spy = SpyExecutor()
    app = _app(make_cfg(str(tmp_path)), public_key=pub, executor=spy, now=lambda: 1000.0)
    argv = ["kubectl", "apply", "-f", "/manifests/deploy.yaml"]
    signed = Staged(argv_index=3, content="apiVersion: v1\nkind: ConfigMap\n")
    token = _sign(priv, argv, staged=(signed,), family="kubectl")
    attacker = Staged(argv_index=3, content="apiVersion: v1\nkind: Secret\ndata:\n  x: evil\n")
    async with _client(app) as client:
        resp = await client.post(
            "http://svc/execute",
            json=_body(argv, token, family="kubectl", staged_wire=(attacker.to_wire(),)),
        )
    assert resp.status_code == 403 and not spy.called


async def test_rewritten_staging_metadata_rejected_without_executing(tmp_path: Any) -> None:
    """Token signed for argv_index/inline_prefix X; request rewrites them -> 403, no run."""
    priv, pub = generate_keypair()
    spy = SpyExecutor()
    app = _app(make_cfg(str(tmp_path)), public_key=pub, executor=spy, now=lambda: 1000.0)
    argv = ["kubectl", "apply", "-f", "/manifests/deploy.yaml"]
    signed = Staged(argv_index=3, inline=False, inline_prefix=None)
    token = _sign(priv, argv, staged=(signed,), family="kubectl")
    # attacker flips the value to an attached inline flag injection at a different index
    attacker = Staged(argv_index=1, inline=True, inline_prefix="--config=")
    async with _client(app) as client:
        resp = await client.post(
            "http://svc/execute",
            json=_body(argv, token, family="kubectl", staged_wire=(attacker.to_wire(),)),
        )
    assert resp.status_code == 403 and not spy.called


async def test_swapped_tool_family_rejected_without_executing(tmp_path: Any) -> None:
    """Token signed for family kubectl; request swaps to aws for a different credential -> 403."""
    priv, pub = generate_keypair()
    spy = SpyExecutor()
    app = _app(make_cfg(str(tmp_path)), public_key=pub, executor=spy, now=lambda: 1000.0)
    argv = ["kubectl", "get", "pods"]
    token = _sign(priv, argv, family="kubectl")
    async with _client(app) as client:
        resp = await client.post("http://svc/execute", json=_body(argv, token, family="aws"))
    assert resp.status_code == 403 and not spy.called


# --------------------------------------------------------------------------------------
# I1 replay — a valid token is single-use
# --------------------------------------------------------------------------------------


async def test_replay_second_presentation_rejected_without_executing(tmp_path: Any) -> None:
    priv, pub = generate_keypair()
    spy = SpyExecutor(output="ran")
    app = _app(make_cfg(str(tmp_path)), public_key=pub, executor=spy, now=lambda: 1000.0)
    argv = ["kubectl", "get", "pods"]
    token = _sign(priv, argv, family="kubectl")
    body = _body(argv, token, family="kubectl")
    async with _client(app) as client:
        first = await client.post("http://svc/execute", json=body)
        second = await client.post("http://svc/execute", json=body)  # identical replay
    assert first.status_code == 200
    assert second.status_code == 409
    assert len(spy.calls) == 1  # the replay did NOT run


async def test_concurrent_duplicates_run_exactly_once(tmp_path: Any) -> None:
    priv, pub = generate_keypair()
    spy = SpyExecutor(output="ran")
    app = _app(make_cfg(str(tmp_path)), public_key=pub, executor=spy, now=lambda: 1000.0)
    argv = ["kubectl", "get", "pods"]
    token = _sign(priv, argv, family="kubectl")
    body = _body(argv, token, family="kubectl")
    async with _client(app) as client:
        r1, r2 = await asyncio.gather(
            client.post("http://svc/execute", json=body),
            client.post("http://svc/execute", json=body),
        )
    statuses = sorted([r1.status_code, r2.status_code])
    assert statuses == [200, 409]
    assert len(spy.calls) == 1


# --------------------------------------------------------------------------------------
# secrets-into-env, full-scrub
# --------------------------------------------------------------------------------------


async def test_secret_resolved_into_env_not_argv(tmp_path: Any) -> None:
    priv, pub = generate_keypair()
    spy = SpyExecutor()
    app = _app(
        make_cfg(str(tmp_path)),
        public_key=pub,
        secret_source=DictSource({"MYSECRET": "topsecretvalue"}),
        executor=spy,
        now=lambda: 1000.0,
    )
    argv = ["myapp", "--mode", "sync", "{{secret:MYSECRET}}"]
    token = _sign(priv, argv)
    async with _client(app) as client:
        resp = await client.post("http://svc/execute", json=_body(argv, token))
    assert resp.status_code == 200
    call = spy.calls[0]
    assert call["env"]["MYSECRET"] == "topsecretvalue"
    assert "topsecretvalue" not in " ".join(call["argv"])
    assert call["argv"] == ["myapp", "--mode", "sync"]


async def test_full_scrub_redacts_secret_value_from_output(tmp_path: Any) -> None:
    priv, pub = generate_keypair()
    secret = "SUPERSECRETVALUE-abc123"
    spy = SpyExecutor(output=f"the tool leaked {secret} into stdout")
    app = _app(
        make_cfg(str(tmp_path)),
        public_key=pub,
        secret_source=DictSource({"LEAK": secret}),
        executor=spy,
        now=lambda: 1000.0,
    )
    argv = ["echo", "{{secret:LEAK}}"]
    token = _sign(priv, argv)
    async with _client(app) as client:
        resp = await client.post("http://svc/execute", json=_body(argv, token))
    assert resp.status_code == 200
    data = resp.json()
    assert secret not in data["output"] and "***" in data["output"]
    assert data["scrub_count"] >= 1  # M2: the service's authoritative count


async def test_end_to_end_secret_env_to_scrubbed_output(tmp_path: Any) -> None:
    """Real subprocess: secret reaches the child via ENV, its echoed value is scrubbed on return."""
    if shutil.which("python3") is None:  # pragma: no cover - CI has python3
        pytest.skip("python3 not on PATH")
    priv, pub = generate_keypair()
    secret = "REALSUBPROCSECRET-xyz789"
    app = _app(
        make_cfg(str(tmp_path)),
        public_key=pub,
        secret_source=DictSource({"LEAK": secret}),
        executor=LocalExecutor(),
        now=lambda: 1000.0,
    )
    argv = ["python3", "-c", "import os;print(os.environ.get('LEAK',''))", "{{secret:LEAK}}"]
    token = _sign(priv, argv)
    async with _client(app) as client:
        resp = await client.post("http://svc/execute", json=_body(argv, token))
    assert resp.status_code == 200
    data = resp.json()
    assert data["exit_code"] == 0
    assert secret not in data["output"] and "***" in data["output"]


async def test_credential_unavailable_is_422_not_500(tmp_path: Any) -> None:
    priv, pub = generate_keypair()
    spy = SpyExecutor()
    app = _app(make_cfg(str(tmp_path)), public_key=pub, executor=spy, now=lambda: 1000.0)
    argv = ["gh", "pr", "list"]
    token = _sign(priv, argv, family="gh")
    async with _client(app) as client:
        resp = await client.post("http://svc/execute", json=_body(argv, token, family="gh"))
    assert resp.status_code == 422 and not spy.called



async def test_identity_mismatch_rejected_without_executing(tmp_path: Any) -> None:
    """A staging/ro token must not execute on a prod/rw pod — 403, spy untouched."""
    priv, pub = generate_keypair()
    spy = SpyExecutor()
    app = _app(
        make_cfg(str(tmp_path)),
        pub,
        executor=spy,
        identity_environment="prod",
        identity_channel="rw",
        now=lambda: 1000.0,
    )
    argv = ["kubectl", "get", "pods"]
    token = _sign(priv, argv, channel="ro", family="kubectl", environment="staging")
    async with _client(app) as client:
        resp = await client.post(
            "http://svc/execute",
            json=_body(argv, token, channel="ro", family="kubectl", environment="staging"),
        )
    assert resp.status_code == 403 and not spy.called
    assert "identity" in resp.json()["detail"]
