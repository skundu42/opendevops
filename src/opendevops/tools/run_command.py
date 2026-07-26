"""The one execution tool (argv-only): decision gate + LocalExecutor + scrubber + FS spill.

``run_command(argv, timeout_s=60)`` is the agent's *only* execution surface. This module wires
together:

* the **decision gate** — a module-level :data:`current_decision` ``ContextVar`` that
  PolicyMiddleware sets (token = set/reset) around the tool handler. No code path reaches a
  subprocess without a matching decision (argv equality + tool_call_id when the runtime
  provides one), the in-process analogue of the remote executor's signed decision token.
* the **argv boundary** — empty argv, non-string elements and ``/`` in ``argv[0]`` are
  rejected at the boundary (error string, never an exception), so PATH lookup stays the
  executor's job and ``../`` / absolute-path dodges are blocked.
* the **output pipeline** — ANSI-strip -> scrub -> sha256(scrubbed) -> head/tail truncate.
* the **exec-meta return channel** — the per-exec audit facts (sha / duration / exit_code /
  truncated / scrub_count) ride on the returned ``ToolMessage``'s
  ``additional_kwargs[EXEC_META_KEY]``. PolicyMiddleware reads (and strips) them there.
  A ``ContextVar`` is deliberately *not* used: langchain runs the tool coroutine in a copied
  context (``tool.ainvoke``), so a value the tool sets does not propagate back to the middleware
  frame — the child->parent leg of the boundary is lost. The return value does cross it.

Virtual-FS spill on truncation (investigation outcome)
------------------------------------------------------
When output exceeds ``execution.output_max_chars`` the full *scrubbed* text is spilled to the
deepagents virtual filesystem at ``/output/<tool_call_id>.txt`` and the truncation marker
references that path. **This is implemented** (not skipped): a spike against a real
``create_deep_agent`` graph confirmed a plain tool return of
``Command(update={"files": {path: FileData}, "messages": [ToolMessage]})`` persists into the
``files`` state channel and is read back verbatim by the built-in ``read_file`` tool — the
same shape deepagents' own ``write_file`` produces (``create_file_data``). No graph internals
are touched. Two integration dependencies are worth flagging:
  1. the spill requires the ``files`` state channel, contributed by ``FilesystemMiddleware``
     (present in the default ``create_deep_agent`` stack); and
  2. ``PolicyMiddleware.wrap_tool_call`` must pass a ``Command`` return through
     unchanged (its signature already returns ``ToolMessage | Command``).
If a future backend/permissions config routes ``/output/`` away from state or denies writes
there, ``read_file`` visibility would need re-checking.

Note: this module deliberately does **not** use ``from __future__ import annotations``. The
``run_command`` tool declares an injected ``runtime: ToolRuntime`` parameter, and langchain's
``StructuredTool._injected_args_keys`` introspects the *raw* ``signature().annotation`` to
decide which args to inject. Stringized (PEP 563) annotations defeat that isinstance check —
so the injected ``runtime`` would be silently dropped and the tool would fail at call time.
deepagents' own filesystem tools avoid ``__future__`` annotations for the same reason.
"""

from collections.abc import Mapping
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Literal

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
    LocalExecutor,
    RemoteExecutorError,
    build_env,
)
from opendevops.tools.scrub import scrub_full, sha256_hex, strip_ansi, truncate_head_tail
from opendevops.tools.secrets import (
    EnvSecretSource,
    SecretResolutionError,
    SecretSource,
    has_secret_tokens,
    resolve_secrets,
)
from opendevops.tools.staging import (
    StagingError,
    resolve_file_refs,
    stage,
    staging_tmpdir,
)

# --------------------------------------------------------------------------------------
# decision gate (the in-process analogue of the remote executor's signed decision token)
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ExecDecision:
    """A policy authorization for exactly one execution, set by PolicyMiddleware."""

    tool_call_id: str
    channel: Literal["ro", "rw"]
    tool_family: str | None
    argv: tuple[str, ...]
    environment: str | None = None


current_decision: ContextVar[ExecDecision | None] = ContextVar(
    "current_decision", default=None
)
"""Set by PolicyMiddleware around the run_command handler; read by the tool to gate exec."""

RUN_COMMAND_NAME = "run_command"
"""The tool name; also stamped on the ToolMessage run_command builds itself."""

EXEC_META_KEY = "exec_meta"
"""additional_kwargs key carrying the per-exec audit facts to PolicyMiddleware.

The middleware reads this off the returned ToolMessage (directly, or inside a Command's
``update["messages"]``), emits the execution audit event, and strips the key before the message
reaches the model or the result cache. Its absence means the tool did not execute — built-in FS
tools and any refusal leave it unset, so they get a decision event but no execution event."""


_REFUSED = "execution refused: no policy decision"

# A shared default executor (stateless). Tests may inject a spy via ``executor=``.
_DEFAULT_EXECUTOR = LocalExecutor()


# --------------------------------------------------------------------------------------
# boundary + core
# --------------------------------------------------------------------------------------


def _validate_argv(argv: object) -> str | None:
    """Return a boundary-rejection message, or None if *argv* is acceptable."""
    if not isinstance(argv, list) or len(argv) == 0:
        return "execution refused: argv must be a non-empty list"
    if not all(isinstance(a, str) for a in argv):
        return "execution refused: argv elements must all be strings"
    if "/" in argv[0]:
        return (
            "execution refused: argv[0] must be a bare program name (no '/'); "
            "PATH lookup is handled by the executor"
        )
    return None


def _exec_tool_message(
    content: str, tool_call_id: str, meta: dict[str, Any]
) -> ToolMessage:
    """A run_command ToolMessage carrying its per-exec audit meta for PolicyMiddleware.

    The meta rides on ``additional_kwargs[EXEC_META_KEY]`` (see :data:`EXEC_META_KEY`); the
    middleware reads and strips it before the message reaches the model or the result cache.
    Returning a ToolMessage (a ``ToolOutputMixin``) rather than a bare string is what preserves
    the meta across langchain's tool boundary — a bare string is re-wrapped into a *fresh*
    ToolMessage by the tool runtime, dropping any additional_kwargs.
    """
    return ToolMessage(
        content=content,
        tool_call_id=tool_call_id,
        name=RUN_COMMAND_NAME,
        additional_kwargs={EXEC_META_KEY: meta},
    )


def _format_result(
    result: ExecResult,
    cfg: AppConfig,
    tool_call_id: str | None,
    staged_files: list[dict[str, str]] | None = None,
    secret_values: list[str] | None = None,
) -> str | ToolMessage | Command[Any]:
    """Run the output pipeline and build the tool return value (carrying the exec meta).

    With a ``tool_call_id`` (always the case through the graph) the meta rides on the returned
    ToolMessage's ``additional_kwargs``; without one (direct unit calls only, no middleware to
    feed) the result degrades to a bare string and carries no meta. ``staged_files`` — the
    ``[{path, sha256}]`` of any virtual manifest materialized for this exec — is recorded on the
    meta so the audit ``execution.staged_files`` captures exactly the applied manifest.

    ``secret_values`` — the exact secret VALUES resolved for this call — are literal-scrubbed
    from the output as a backstop over the pattern scrubber. Empty (the default, and always so on
    the remote path where the service already scrubbed and the agent holds no values) makes
    ``scrub_full`` byte-for-byte identical to the original pattern ``scrub``.
    """
    stripped = strip_ansi(result.output)
    scrubbed, local_scrub_count = scrub_full(stripped, secret_values or ())
    stdout_sha256 = sha256_hex(scrubbed)

    # M2: prefer the executor's AUTHORITATIVE scrub count when it supplied one (the remote path —
    # the service scrubbed the values the agent never holds; the agent's re-scrub above is
    # idempotent and would report ~0). Local mode leaves ``result.scrub_count`` None -> use the
    # in-process count. Audit fidelity only; the scrubbed text / sha are unaffected.
    scrub_count = result.scrub_count if result.scrub_count is not None else local_scrub_count

    max_chars = cfg.execution.output_max_chars
    truncated = len(scrubbed) > max_chars

    files_update: dict[str, Any] | None = None
    if truncated and tool_call_id is not None:
        fs_path = f"/output/{tool_call_id}.txt"
        display, _, _ = truncate_head_tail(scrubbed, max_chars, fs_path)
        files_update = {fs_path: create_file_data(scrubbed)}
    else:
        # Either no truncation, or no tool_call_id to name a spill file: degrade to an
        # in-band marker stating how many chars were dropped.
        display, _, _ = truncate_head_tail(scrubbed, max_chars, None)

    message = f"exit_code: {result.exit_code}\n{display}"
    meta: dict[str, Any] = {
        "stdout_sha256": stdout_sha256,
        "duration_ms": result.duration_ms,
        "exit_code": result.exit_code,
        "truncated": truncated,
        "scrub_count": scrub_count,
        # The applied manifest(s): [{path: virtual_path, sha256: content-hash}]. Empty for calls
        # with no file flags. PolicyMiddleware forwards this into the audit execution event.
        "staged_files": staged_files or [],
    }

    if tool_call_id is None:
        # No id to bind a ToolMessage to => cannot carry the meta. This path never runs through
        # the middleware-wrapped graph (the ToolNode always supplies an id); only direct unit
        # calls reach it, and they have no execution audit event to feed.
        return message

    tool_message = _exec_tool_message(message, tool_call_id, meta)
    if files_update is not None:
        return Command(update={"files": files_update, "messages": [tool_message]})
    return tool_message


async def run_command_core(
    argv: list[str],
    timeout_s: int,
    cfg: AppConfig,
    *,
    tool_call_id: str | None = None,
    executor: Any = None,
    files: Mapping[str, Any] | None = None,
) -> str | ToolMessage | Command[Any]:
    """Gate -> validate -> clamp -> build env -> stage -> execute -> format. Never raises to model.

    ``files`` is the deepagents virtual-FS ``files`` state mapping (the same channel the spill
    writes). For file-consuming flags the referenced virtual files are materialized into a
    per-call private tmpdir and argv is rewritten to the staged paths *inside* the
    already-approved execution — the decision gate compares the ORIGINAL argv (what policy OK'd).
    """
    # 1. argv boundary (before touching the decision or a subprocess).
    boundary_error = _validate_argv(argv)
    if boundary_error is not None:
        return boundary_error

    # 2. decision gate — no subprocess without a matching authorization (ORIGINAL argv).
    decision = current_decision.get()
    if decision is None or decision.argv != tuple(argv):
        return _REFUSED
    if tool_call_id is not None and decision.tool_call_id != tool_call_id:
        return _REFUSED

    # 3. clamp timeout to [1, min(cfg.cmd_timeout_seconds, 300)].
    upper = min(cfg.execution.cmd_timeout_seconds, 300)
    clamped_timeout = max(1, min(timeout_s, upper))

    active_executor = executor if executor is not None else _DEFAULT_EXECUTOR

    # 3b. executor mode. On the REMOTE path the agent holds NO credential and NO secret value:
    #     do NOT call build_env or resolve secrets in-process — sign the AUTHORIZED argv and hand
    #     off to the executor service (which holds the credentials + secrets). The decision gate
    #     above already ran on this path too. LOCAL (default) is byte-for-byte unchanged.
    if cfg.executor.mode == "remote":
        return await _run_command_remote(
            active_executor, list(argv), clamped_timeout, cfg, decision, tool_call_id, files
        )

    # 4. LOCAL path: construct env (fixed base + sandbox HOME + at most one decision-keyed
    #    credential), then resolve any {{secret:NAME}} into that env in-process.
    try:
        env = build_env(
            cfg,
            decision.tool_family,
            decision.channel,
            active_executor.home,
            environment=decision.environment,
        )
    except CredentialUnavailable as exc:
        return f"execution refused: {exc}"

    # 4b. Secret resolution (in-process on local mode — the single-process deployment holds the
    #     secret source). A secret-free argv is a transparent no-op (argv/env/scrub unchanged), so
    #     every existing test is byte-for-byte identical.
    run_argv_base = list(argv)
    secret_values: list[str] = []
    if has_secret_tokens(argv):
        try:
            resolved = resolve_secrets(argv, _local_secret_source(cfg))
        except SecretResolutionError as exc:
            return f"execution refused: {exc}"
        run_argv_base = resolved.argv
        env.update(resolved.env)
        secret_values = resolved.values

    # 5. staging bridge — resolve any file-flag refs against the virtual FS. A path absent from
    #    the virtual FS (or an unsupported -k) refuses with NO execution and NO exec-meta.
    try:
        refs = resolve_file_refs(run_argv_base, files or {})
    except StagingError as exc:
        return f"staging refused: {exc}"

    # 6. stage (if needed) -> execute the REWRITTEN argv -> always rmtree the tmpdir afterwards.
    staged_files = [{"path": r.virtual_path, "sha256": r.sha256} for r in refs]
    if refs:
        with staging_tmpdir() as stage_dir:
            run_argv = stage(run_argv_base, refs, stage_dir)
            result: ExecResult = await active_executor.execute(
                run_argv, clamped_timeout, env
            )
    else:
        result = await active_executor.execute(run_argv_base, clamped_timeout, env)

    # 7. output pipeline + audit meta (carries the staged manifest facts + literal secret scrub).
    return _format_result(result, cfg, tool_call_id, staged_files, secret_values)


def _local_secret_source(cfg: AppConfig) -> SecretSource:
    """The in-process ``{{secret:NAME}}`` backend for local mode (env-backed, optional prefix)."""
    return EnvSecretSource(prefix=cfg.executor.secret_env_prefix)


async def _run_command_remote(
    active_executor: Any,
    argv: list[str],
    timeout_s: int,
    cfg: AppConfig,
    decision: ExecDecision,
    tool_call_id: str | None,
    files: Mapping[str, Any] | None,
) -> str | ToolMessage | Command[Any]:
    """Remote path: gather staged CONTENT, hand the authorized argv to the RemoteExecutor client.

    ``build_env`` and secret resolution do NOT run here (the agent holds no credential/secret) —
    they run in the executor service. Staging RESOLUTION (reading the virtual files + sha) stays
    agent-side so the audit ``staged_files`` record is identical to the local path; only the
    MATERIALIZATION moves to the service (the file content travels in the request body). The signed
    token binds the ORIGINAL authorized argv; the service verifies it, then applies staging + secret
    resolution. The returned ``ExecResult`` goes through the SAME ``_format_result`` as local, so
    the ToolMessage / EXEC_META contract is identical (``secret_values=[]``: the service already
    scrubbed the values, which the agent never holds).
    """
    try:
        refs = resolve_file_refs(argv, files or {})
    except StagingError as exc:
        return f"staging refused: {exc}"
    staged_files = [{"path": r.virtual_path, "sha256": r.sha256} for r in refs]

    run_remote = getattr(active_executor, "run_remote", None)
    if run_remote is None:
        # Misconfiguration: executor.mode=remote but no RemoteExecutor wired. Fail closed.
        return "execution refused: remote executor not configured"
    try:
        result = await run_remote(
            argv, timeout_s, decision=decision, tool_call_id=tool_call_id, refs=refs
        )
    except RemoteExecutorError as exc:
        return f"execution refused: {exc}"
    return _format_result(result, cfg, tool_call_id, staged_files)


# --------------------------------------------------------------------------------------
# tool factory
# --------------------------------------------------------------------------------------


class _RunCommandArgs(BaseModel):
    """Model-facing schema for run_command (the injected ToolRuntime is not exposed)."""

    argv: list[str] = Field(
        description=(
            "The command as a list of arguments; argv[0] is the program (a bare name, "
            "resolved via PATH). No shell: pipes, redirects, globs, ';'/'&&' chaining and "
            "$(...) substitution are NOT interpreted — they are passed as literal arguments."
        )
    )
    timeout_s: int = Field(
        default=60,
        description="Wall-clock timeout in seconds (clamped to the configured maximum).",
    )


_TOOL_DESCRIPTION = (
    "Run a single command and return its combined stdout+stderr, prefixed with its exit "
    "code on the first line. argv-only: the first element is the program (a bare name "
    "resolved via PATH) and the rest are literal arguments. There is NO shell — no pipes, "
    "no redirection, no globbing, no ';'/'&&' chaining, no command substitution. Run one "
    "command per call; compose multiple steps across calls, and use the filesystem tools "
    "(write_file/read_file/grep) to search or slice large outputs rather than piping. Very "
    "large output is truncated (head+tail) with the full text spilled to /output/."
)


def _runtime_files(runtime: ToolRuntime[Any, Any]) -> Mapping[str, Any]:
    """Read the deepagents virtual-FS ``files`` state off the injected runtime (empty if absent).

    The same access path the spill uses, tolerant of a missing/None state (direct unit calls) or a
    state object that is dict-like vs attribute-like.
    """
    state = getattr(runtime, "state", None)
    if isinstance(state, Mapping):
        files = state.get("files")
    elif state is not None:
        files = getattr(state, "files", None)
    else:
        files = None
    return files if isinstance(files, Mapping) else {}


def make_run_command(cfg: AppConfig, executor: Any = None) -> BaseTool:
    """Build the ``run_command`` tool bound to *cfg* (a deepagents/langchain ``BaseTool``).

    ``executor`` selects the execution backend for ``cfg.executor.mode``: ``None`` (the default and
    what ``local`` mode uses) keeps the in-process default :class:`LocalExecutor` unchanged; a
    :class:`~opendevops.tools.executor.RemoteExecutor` (built by
    :func:`~opendevops.tools.executor.select_executor` for ``remote`` mode) routes each exec to
    the executor service. ``agent.py`` passes ``select_executor(cfg)``.
    """

    async def _run_command(
        argv: list[str],
        runtime: ToolRuntime[Any, Any],
        timeout_s: int = 60,
    ) -> str | ToolMessage | Command[Any]:
        tool_call_id = getattr(runtime, "tool_call_id", None)
        return await run_command_core(
            argv,
            timeout_s,
            cfg,
            tool_call_id=tool_call_id,
            executor=executor,
            files=_runtime_files(runtime),
        )

    return StructuredTool.from_function(
        coroutine=_run_command,
        name=RUN_COMMAND_NAME,
        description=_TOOL_DESCRIPTION,
        args_schema=_RunCommandArgs,
        infer_schema=False,
    )
