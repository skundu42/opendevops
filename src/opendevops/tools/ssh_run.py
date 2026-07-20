"""The structured remote-exec tool ``ssh_run(host, argv)``.

``ssh_run`` is a SEPARATE tool from the argv-only local ``run_command``: ``ssh`` as a run_command
argv0 is hard-denied (base.yaml ``interpreters-hard-deny``). It connects to an ALLOWLISTED ``host``
as the config-pinned user with the config-pinned key + ``known_hosts`` (host-key verification ON,
fail-closed on an unknown key), runs the model's ``argv`` as a shell-quoted remote command (no
remote-shell metacharacter interpretation against a POSIX login shell — see
:class:`~opendevops.tools.executor.SshExecutor`), applies the SAME output pipeline as run_command
(ANSI-strip -> scrub -> sha256 -> truncate), and returns a ``ToolMessage`` carrying the per-exec
``EXEC_META`` that ``PolicyMiddleware`` audits and strips. The model supplies ONLY the allowlisted
host name + the remote argv; user / key / port / ``known_hosts`` are pinned by config.

Authorization model (now symmetric with run_command's ContextVar gate)
----------------------------------------------------------------------
``ssh_run`` flows through the SAME ``PolicyMiddleware`` decide -> audit(decision) -> execute ->
audit(execution) pipeline as run_command, with THREE fail-closed layers, so an invocation outside
the middleware refuses:
  1. the **policy engine**, which DENYs a non-allowlisted host or remote command PATH BEFORE the
     middleware ever calls this handler (so the tool running at all is proof host + command were
     authorized);
  2. the in-tool **decision-token gate** — the ``current_decision`` ``ExecDecision`` the middleware
     now sets for ssh_run too (mirroring run_command), re-checked here on ``argv`` equality +
     ``tool_call_id``: no ssh exec runs without a matching authorization, so a future direct call
     site cannot become an RCE; and
  3. the tool's own **re-validation** of ``host`` against the config allowlist plus the
     config-pinned credential (it can never connect to a host outside the config allowlist).
``ssh`` has a single ``ro`` credential, so no middleware-injected channel is needed.

Note: like run_command, this module deliberately does **not** use ``from __future__ import
annotations`` — the tool declares an injected ``runtime: ToolRuntime`` parameter and langchain's
``StructuredTool`` introspects the *raw* annotation to decide what to inject; stringized (PEP 563)
annotations would silently drop the injected runtime.
"""

from typing import Any

from deepagents.backends.utils import create_file_data
from langchain.tools import ToolRuntime
from langchain_core.messages import ToolMessage
from langchain_core.tools import BaseTool, StructuredTool
from langgraph.types import Command
from pydantic import BaseModel, Field

from opendevops.config import AppConfig
from opendevops.tools.executor import (
    CredentialUnavailable,
    ExecResult,
    SshConnectionError,
    SshExecutor,
    resolve_ssh_credential,
)
from opendevops.tools.run_command import EXEC_META_KEY, current_decision
from opendevops.tools.scrub import scrub, sha256_hex, strip_ansi, truncate_head_tail

SSH_RUN_NAME = "ssh_run"
"""The tool name; matched by the ssh pack (``tool_name: ssh_run``), stamped on the ToolMessage."""

_SSH_REFUSED = "ssh refused: no matching policy authorization for this call"
"""In-tool fail-closed refusal when the decision-token gate does not match (mirrors run_command's
``_REFUSED``): no ssh exec without a ``current_decision`` whose argv + tool_call_id match this
call."""

# A shared default executor (stateless). Tests inject a fake via ``executor=`` to avoid a socket.
_DEFAULT_SSH_EXECUTOR = SshExecutor()


def _validate_inputs(host: object, argv: object) -> str | None:
    """Return a boundary-rejection message, or None if *host* / *argv* are acceptable.

    Mirrors run_command's argv boundary: a bare-name ``argv[0]`` (no ``/``) so the remote PATH does
    the lookup and an absolute-path dodge (``/tmp/evil``) is blocked; a non-empty string host.
    """
    if not isinstance(host, str) or not host:
        return "ssh refused: host must be a non-empty string"
    if not isinstance(argv, list) or len(argv) == 0:
        return "ssh refused: argv must be a non-empty list"
    if not all(isinstance(a, str) for a in argv):
        return "ssh refused: argv elements must all be strings"
    if "/" in argv[0]:
        return "ssh refused: argv[0] must be a bare program name (no '/')"
    return None


def _format_result(
    result: ExecResult, cfg: AppConfig, tool_call_id: str | None
) -> "str | ToolMessage | Command[Any]":
    """Run the output pipeline and build the tool return value (carrying the exec meta).

    Same shape as run_command's formatter: ANSI-strip -> scrub -> sha256(scrubbed) ->
    head/tail truncate, with the full scrubbed text spilled to ``/output/<id>.txt`` on truncation.
    The meta rides on ``additional_kwargs[EXEC_META_KEY]`` (the exact key PolicyMiddleware reads and
    strips), stamped with ``name=ssh_run`` so the audit/cache attribute it to this tool.
    """
    stripped = strip_ansi(result.output)
    scrubbed, scrub_count = scrub(stripped)
    stdout_sha256 = sha256_hex(scrubbed)

    max_chars = cfg.execution.output_max_chars
    truncated = len(scrubbed) > max_chars

    files_update: dict[str, Any] | None = None
    if truncated and tool_call_id is not None:
        fs_path = f"/output/{tool_call_id}.txt"
        display, _, _ = truncate_head_tail(scrubbed, max_chars, fs_path)
        files_update = {fs_path: create_file_data(scrubbed)}
    else:
        display, _, _ = truncate_head_tail(scrubbed, max_chars, None)

    message = f"exit_code: {result.exit_code}\n{display}"
    meta: dict[str, Any] = {
        "stdout_sha256": stdout_sha256,
        "duration_ms": result.duration_ms,
        "exit_code": result.exit_code,
        "truncated": truncated,
        "scrub_count": scrub_count,
        # ssh_run stages no files (no -f flags); kept for shape-parity with run_command's meta.
        "staged_files": [],
    }

    if tool_call_id is None:
        # No id to bind a ToolMessage to => cannot carry the meta (direct unit calls only).
        return message

    tool_message = ToolMessage(
        content=message,
        tool_call_id=tool_call_id,
        name=SSH_RUN_NAME,
        additional_kwargs={EXEC_META_KEY: meta},
    )
    if files_update is not None:
        return Command(update={"files": files_update, "messages": [tool_message]})
    return tool_message


async def ssh_run_core(
    host: str,
    argv: list[str],
    timeout_s: int,
    cfg: AppConfig,
    *,
    tool_call_id: str | None = None,
    executor: Any = None,
) -> "str | ToolMessage | Command[Any]":
    """Validate -> decision gate -> host allowlist -> resolve cred -> clamp -> execute -> format.

    Never raises. The policy engine has already denied a non-allowlisted host / remote command
    before this handler is reached; the in-tool decision-token gate (symmetry with run_command),
    the host re-check and the config-pinned credential are defense in depth. A connection /
    host-key-verification failure becomes a refusal (no exec meta, so no execution audit event) —
    the same posture as run_command's boundary refusals.
    """
    # 1. Boundary (before touching config or a socket).
    boundary = _validate_inputs(host, argv)
    if boundary is not None:
        return boundary

    # 1.5 decision gate — no ssh exec without a matching authorization (symmetry with run_command).
    decision = current_decision.get()
    if decision is None or decision.argv != tuple(argv):
        return _SSH_REFUSED
    if tool_call_id is not None and decision.tool_call_id != tool_call_id:
        return _SSH_REFUSED

    # 2. Host allowlist (single source of truth = config; policy already gated on the same list).
    if host not in cfg.targets.ssh.hosts:
        return f"ssh refused: host {host!r} is not in the configured allowlist"

    # 3. Resolve the config-pinned credential (fail-closed on any missing/unset piece).
    try:
        cred = resolve_ssh_credential(cfg)
    except CredentialUnavailable as exc:
        return f"ssh refused: {exc}"

    # 4. Clamp timeout to [1, min(cfg.cmd_timeout_seconds, 300)] (same bounds as run_command).
    upper = min(cfg.execution.cmd_timeout_seconds, 300)
    clamped_timeout = max(1, min(timeout_s, upper))

    # 5. Execute over ssh (argv shell-quoted; host-key verification ON) -> ExecResult, or refuse.
    active_executor = executor if executor is not None else _DEFAULT_SSH_EXECUTOR
    try:
        result: ExecResult = await active_executor.execute(
            host, list(argv), clamped_timeout, cred
        )
    except SshConnectionError:
        # Minor 3: a generic literal — the raw asyncssh text can embed the pinned key-file PATH
        # (e.g. "Unable to read private key '/etc/agent/keys/id_ed25519'"). The host is
        # model-supplied (not secret), so it is kept for the model to self-correct. Still
        # fail-closed: no exec meta, so no execution-audit event fires.
        return f"ssh refused: connection or host-key verification to {host!r} failed"

    # 6. Output pipeline + audit meta.
    return _format_result(result, cfg, tool_call_id)


class _SshRunArgs(BaseModel):
    """Model-facing schema for ssh_run (the injected ToolRuntime is not exposed)."""

    host: str = Field(
        description=(
            "The target host. Must be one of the operator-configured allowlisted hosts; the login "
            "user, key, port and host-key verification are all pinned by config, not by you."
        )
    )
    argv: list[str] = Field(
        description=(
            "The remote command as a list of arguments; argv[0] is the program (a bare name "
            "resolved by the remote PATH) and the rest are literal arguments. There is NO remote "
            "shell: pipes, redirects, globs, ';'/'&&' chaining and $(...) substitution are NOT "
            "interpreted — they are transmitted as literal arguments."
        )
    )
    timeout_s: int = Field(
        default=60,
        description="Wall-clock timeout in seconds (clamped to the configured maximum).",
    )


_TOOL_DESCRIPTION = (
    "Run a single command on a remote host over SSH and return its combined stdout+stderr, "
    "prefixed with the exit code on the first line. Structured + credential-pinned: you supply "
    "only an allowlisted host name and an argv list; the login user, private key, port and "
    "host-key verification are pinned by the operator's config. argv-only: argv[0] is the program "
    "(a bare name resolved by the remote PATH), the rest are literal arguments. There is NO remote "
    "shell interpretation (against a POSIX-compatible remote login shell) — no pipes, redirection, "
    "globbing, ';'/'&&' chaining, or command substitution. Only a tight set of read-only remote "
    "status/diagnostic commands is permitted."
)


def make_ssh_run(cfg: AppConfig) -> BaseTool:
    """Build the ``ssh_run`` tool bound to *cfg* (a deepagents/langchain ``BaseTool``)."""

    async def _ssh_run(
        host: str,
        argv: list[str],
        runtime: ToolRuntime[Any, Any],
        timeout_s: int = 60,
    ) -> "str | ToolMessage | Command[Any]":
        tool_call_id = getattr(runtime, "tool_call_id", None)
        return await ssh_run_core(
            host, argv, timeout_s, cfg, tool_call_id=tool_call_id
        )

    return StructuredTool.from_function(
        coroutine=_ssh_run,
        name=SSH_RUN_NAME,
        description=_TOOL_DESCRIPTION,
        args_schema=_SshRunArgs,
        infer_schema=False,
    )
