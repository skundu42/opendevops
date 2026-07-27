"""The executor service HTTP app: verify the decision token, then run the exec.

``create_app(cfg, public_key=..., secret_source=..., executor=...)`` returns a FastAPI app with a
single ``POST /execute`` endpoint. The request pipeline is strictly ordered so a rejected request
NEVER reaches a subprocess (pinned by test — the executor spy proves no run happened):

    1. VERIFY the ed25519 decision token (bad sig / expired / argv-hash mismatch / wrong bound
       field -> 403, before the executor is ever touched);
    1a. ASSERT the token's ``environment`` / ``channel`` match this pod's configured identity
       (``OPENDEVOPS_EXECUTOR_ENV`` / ``OPENDEVOPS_EXECUTOR_CHANNEL``) -> 403 on mismatch;
    2. resolve ``{{secret:NAME}}`` into the subprocess env (unknown secret -> 422);
    3. for ``run_command`` families: build the per-family credential env IN THE SERVICE; for
       ``tool_family=ssh``: resolve the config-pinned SSH credential and run via ``SshExecutor``;
    4. materialize staged files into a per-call tmpdir and rewrite argv to the on-disk paths
       (``run_command`` only);
    5. run the argv ``shell=False`` (or shell-quoted over SSH) with a per-call timeout;
    6. full-scrub the output (literal resolved secret VALUES, then the pattern scrubber) so no
       secret value ever leaves the service — then return the ``ExecResult``.

The service holds the ed25519 PUBLIC key only. There is no signature-stripping / alg-confusion
path: an unsigned or unverifiable request is a 403 with no execution. The expiry clock is injectable
(``now``) for deterministic tests.

SDK firewall: no ``langgraph_sdk`` import anywhere in this module (or the package). The tool modules
it reuses (``executor`` / ``staging`` / ``secrets`` / ``scrub`` / ``signing``) do not import
``langgraph_sdk`` either — ``executor.py`` only touches ``langgraph.runtime`` lazily, inside the
RemoteExecutor client path, which the service never calls.
"""

from __future__ import annotations

import asyncio
import os
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, Literal

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from opendevops.tools.executor import (
    CredentialUnavailable,
    LocalExecutor,
    SshConnectionError,
    SshExecutor,
    build_env,
    resolve_ssh_credential,
)
from opendevops.tools.scrub import scrub_full, strip_ansi
from opendevops.tools.secrets import (
    SecretResolutionError,
    SecretSource,
    build_secret_source,
    resolve_secrets,
)
from opendevops.tools.signing import DecisionToken, TokenError, verify_decision
from opendevops.tools.staging import FileRef, stage, staging_tmpdir

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from opendevops.config import AppConfig

# Absolute ceiling on any per-command timeout (mirrors run_command_core's clamp).
_MAX_TIMEOUT_S = 300

_SSH_FAMILY = "ssh"


class _StagedFileWire(BaseModel):
    """One staged file as it travels in the request body (content materialized in the service)."""

    flag: str
    virtual_path: str
    content: str
    sha256: str
    argv_index: int
    inline: bool
    inline_prefix: str | None = None


class ExecuteRequest(BaseModel):
    """The exec request: authorized argv + correlation fields + staged content + signed token."""

    argv: list[str]
    run_id: str
    tool_call_id: str
    channel: str
    environment: str
    tool_family: str | None = None
    host: str | None = None
    timeout_s: int
    staged_files: list[_StagedFileWire] = []
    token: dict[str, Any]


class ExecuteResponse(BaseModel):
    """The exec result — the fields ``LocalExecutor`` yields, with the output already scrubbed."""

    exit_code: int
    output: str
    duration_ms: int
    timed_out: bool
    scrub_count: int


def _clamp_timeout(timeout_s: int, cfg: AppConfig) -> int:
    upper = min(cfg.execution.cmd_timeout_seconds, _MAX_TIMEOUT_S)
    return max(1, min(timeout_s, upper))


def _read_pod_identity() -> tuple[Literal["staging", "prod"], Literal["ro", "rw"]]:
    """Read and validate ``OPENDEVOPS_EXECUTOR_ENV`` / ``_CHANNEL`` — fail-closed at boot."""
    raw_env = os.environ.get("OPENDEVOPS_EXECUTOR_ENV")
    raw_channel = os.environ.get("OPENDEVOPS_EXECUTOR_CHANNEL")
    if raw_env not in ("staging", "prod"):
        raise RuntimeError(
            "executor service requires OPENDEVOPS_EXECUTOR_ENV to be 'staging' or 'prod' "
            f"(got {raw_env!r})"
        )
    if raw_channel not in ("ro", "rw"):
        raise RuntimeError(
            "executor service requires OPENDEVOPS_EXECUTOR_CHANNEL to be 'ro' or 'rw' "
            f"(got {raw_channel!r})"
        )
    return raw_env, raw_channel  # type: ignore[return-value]


def create_app(
    cfg: AppConfig,
    *,
    public_key: Ed25519PublicKey,
    identity_environment: Literal["staging", "prod"],
    identity_channel: Literal["ro", "rw"],
    secret_source: SecretSource | None = None,
    executor: Any = None,
    ssh_executor: Any = None,
    now: Callable[[], float] = time.time,
) -> FastAPI:
    """Build the executor service app.

    Args:
        cfg: the service's config — it holds the credential targets (``build_env`` / SSH resolve
            read them from the service's own environment).
        public_key: the ed25519 PUBLIC key the token is verified against (the service never holds
            the private key).
        identity_environment: this pod's environment identity (must match the signed token).
        identity_channel: this pod's channel identity (must match the signed token).
        secret_source: the ``{{secret:NAME}}`` backend; defaults to :class:`EnvSecretSource` over
            the service's process environment (prefixed by ``cfg.executor.secret_env_prefix``).
        executor: the subprocess runner (``.home`` + ``.execute``); defaults to a real
            :class:`LocalExecutor`. Tests inject a spy to prove a rejected request never runs.
        ssh_executor: the SSH runner (``.execute(host, argv, timeout, cred)``); defaults to
            :class:`SshExecutor`.
        now: injectable clock for token-expiry checks (deterministic tests).
    """
    source = (
        secret_source
        if secret_source is not None
        else build_secret_source(cfg)
    )
    runner: Any = executor if executor is not None else LocalExecutor()
    ssh_runner: Any = ssh_executor if ssh_executor is not None else SshExecutor()

    # I1 — spent-decision (replay) cache, closure-scoped so it lives for the app's lifetime.
    # Keyed by (run_id, tool_call_id); the value is the token ``exp`` (its eviction time). A valid
    # token is single-use: a second presentation within the 120s TTL is a replay and is rejected
    # 409 WITHOUT executing. The lock makes the check-and-mark atomic so two concurrent duplicates
    # cannot both pass. SINGLE-REPLICA assumption: this is per-process — a multi-replica
    # per-(env,channel) deployment needs a SHARED store (Redis), mirroring the daily-counter's
    # Redis option (budgets.daily.backend). Not built here; documented.
    spent: dict[tuple[str, str], float] = {}
    spent_lock = asyncio.Lock()

    async def _claim_decision(run_id: str, tool_call_id: str, exp: float) -> bool:
        """Atomically claim (run_id, tool_call_id); False if already spent. Evicts stale keys."""
        key = (run_id, tool_call_id)
        async with spent_lock:
            current = now()
            for stale in [k for k, e in spent.items() if e <= current]:
                del spent[stale]
            if key in spent:
                return False
            spent[key] = exp
            return True

    app = FastAPI(title="opendevops executor service")
    app.state.identity_environment = identity_environment
    app.state.identity_channel = identity_channel

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {
            "status": "ok",
            "environment": identity_environment,
            "channel": identity_channel,
        }

    @app.post("/execute", response_model=ExecuteResponse)
    async def execute(req: ExecuteRequest) -> ExecuteResponse:
        # 1. VERIFY the token FIRST — before the executor is touched (a reject must not run). The
        #    verify binds the staging PLAN (content recomputed from the received bytes + rewrite
        #    metadata), tool_family, environment, and host, so substituted content / a rewritten
        #    argv_index or inline_prefix / a swapped family / env / host fails here, 403, with no
        #    execution.
        try:
            token = DecisionToken.from_dict(req.token)
            verify_decision(
                token,
                req.argv,
                req.staged_files,
                req.run_id,
                req.tool_call_id,
                req.channel,
                req.tool_family,
                public_key,
                environment=req.environment,
                host=req.host,
                now=now,
            )
        except TokenError as exc:
            # No execution, clear 4xx. The message names the reason but never any secret/argv value.
            raise HTTPException(status_code=403, detail=f"decision token rejected: {exc}") from exc

        # 1a. Pod identity assert — a staging token must never execute on a prod pod (or ro on rw).
        if (
            token.environment != identity_environment
            or token.channel != identity_channel
        ):
            raise HTTPException(
                status_code=403,
                detail=(
                    "decision token rejected: environment/channel does not match this "
                    f"executor identity ({identity_environment}/{identity_channel})"
                ),
            )

        # 1b. REPLAY guard (I1): mark the decision spent on first valid presentation, BEFORE any
        #     execution and regardless of outcome (a retry must re-authorize with a fresh token). A
        #     second presentation within the TTL is a replay -> 409, no run.
        if not await _claim_decision(req.run_id, req.tool_call_id, token.exp):
            raise HTTPException(
                status_code=409, detail="decision token already spent (replay rejected)"
            )

        # 2. Resolve standalone {{secret:NAME}} declarations into env vars and remove the markers.
        try:
            resolved = resolve_secrets(req.argv, source)
        except SecretResolutionError as exc:
            raise HTTPException(
                status_code=422, detail=f"secret resolution failed: {exc}"
            ) from exc

        timeout = _clamp_timeout(req.timeout_s, cfg)

        # 3a. SSH path — service holds the SSH key; agent does not.
        if req.tool_family == _SSH_FAMILY:
            if not req.host:
                raise HTTPException(
                    status_code=422, detail="ssh execution requires a host field"
                )
            if req.staged_files:
                raise HTTPException(
                    status_code=422, detail="ssh execution must not carry staged files"
                )
            if req.channel != "ro":
                raise HTTPException(
                    status_code=422, detail="ssh execution requires channel 'ro'"
                )
            try:
                cred = resolve_ssh_credential(cfg)
            except CredentialUnavailable as exc:
                raise HTTPException(
                    status_code=422, detail=f"credential unavailable: {exc}"
                ) from exc
            try:
                result = await ssh_runner.execute(
                    req.host, list(resolved.argv), timeout, cred
                )
            except SshConnectionError as exc:
                # Generic detail — never echo key paths from asyncssh. Agent maps 502 → refusal.
                raise HTTPException(
                    status_code=502,
                    detail="ssh connection or host-key verification failed",
                ) from exc
        else:
            # 3b. Build the credential env HERE — the service is the only credential holder.
            #     tool_family is trusted ONLY because the token bound it (verified above).
            if req.host is not None:
                raise HTTPException(
                    status_code=422, detail="host is only valid for tool_family=ssh"
                )
            try:
                env = build_env(cfg, req.tool_family, req.channel, runner.home)
            except CredentialUnavailable as exc:
                raise HTTPException(
                    status_code=422, detail=f"credential unavailable: {exc}"
                ) from exc
            # Secrets go into the ENV only (NAME=value); the argv carries just the $NAME marker.
            env.update(resolved.env)

            # 4. Materialize staged files into a per-call tmpdir; rewrite argv to on-disk paths.
            #    Staging metadata is trusted ONLY because the token bound the plan (verified above)
            #    — substituted content never reaches here.
            refs = [
                FileRef(
                    flag=f.flag,
                    virtual_path=f.virtual_path,
                    content=f.content,
                    sha256=f.sha256,
                    argv_index=f.argv_index,
                    inline=f.inline,
                    inline_prefix=f.inline_prefix,
                )
                for f in req.staged_files
            ]
            if refs:
                with staging_tmpdir() as tmpdir:
                    run_argv = stage(resolved.argv, refs, tmpdir)
                    result = await runner.execute(run_argv, timeout, env)
            else:
                result = await runner.execute(resolved.argv, timeout, env)

        # 6. Full-scrub: strip ANSI, redact the exact resolved secret VALUES, then pattern-scrub.
        stripped = strip_ansi(result.output)
        scrubbed, count = scrub_full(stripped, resolved.values)
        return ExecuteResponse(
            exit_code=result.exit_code,
            output=scrubbed,
            duration_ms=result.duration_ms,
            timed_out=result.timed_out,
            scrub_count=count,
        )

    return app


def build_app_from_env() -> FastAPI:
    """Deployment factory: load config + PUBLIC verify key + pod identity, build the app.

    Used by the container entrypoint (``uvicorn ...service:build_app_from_env --factory``). Reads
    config via :func:`opendevops.config.load_config`, the ed25519 public key from the env var
    named by ``executor.verify_key_env``, and ``OPENDEVOPS_EXECUTOR_ENV`` /
    ``OPENDEVOPS_EXECUTOR_CHANNEL`` — fail-closed if any are unconfigured/unset.
    """
    from opendevops.config import load_config
    from opendevops.tools.signing import load_public_key_from_env

    cfg = load_config()
    public_key = load_public_key_from_env(cfg.executor.verify_key_env)
    identity_environment, identity_channel = _read_pod_identity()
    return create_app(
        cfg,
        public_key=public_key,
        identity_environment=identity_environment,
        identity_channel=identity_channel,
    )
