"""LocalExecutor + constructed-env / credential map for the argv-only run_command tool.

The executor runs a single ``argv`` (no shell) in its **own process group** with a fully
**constructed** environment — neither ``PATH`` nor any other ambient process value is inherited,
so the agent's own ``ANTHROPIC_API_KEY`` (and everything else in ``os.environ``) is physically
absent from the child. Exactly one credential is injected per exec, keyed by
``(tool_family, channel)``.

Constructed-env table (every child sees exactly these, nothing more):

===========================  ==================================================================
key                          value
===========================  ==================================================================
``PATH``                     fixed ``execution.trusted_path`` from validated configuration
``HOME``                     a **private per-executor sandbox** dir (NOT the operator's ``$HOME``),
                             so ``~/.kube/config`` / ``~/.aws/credentials`` / ``~/.config/gh``
                             are unreachable by executed tools
``KUBECONFIG``               the family kubeconfig when ``tool_family == "kubectl"``, else the
                             sentinel ``/dev/null`` — a mistagged kubectl call fails closed
                             ("no configuration provided") instead of using operator creds
``GH_TOKEN``                 the ``gh`` family PAT only — the READ PAT
                             (``targets.github.token_env``) on the ``ro`` channel, the WRITE PAT
                             (``targets.github.token_env_rw``) on ``rw``; exactly one,
                             absent for every other family
``AWS_*`` / ``GOOGLE_*`` /   the read-only cloud credential, injected ONLY for its own family:
``CLOUDSDK_*`` / ``AZURE_*`` the variables named by ``targets.{aws,gcloud,azure}.credential_env``
                             — each var's VALUE copied from the agent process (never another
                             family's credential; a missing/empty named var fails closed)
``NO_COLOR`` / ``PAGER`` /   fixed literals suppressing colour / pagers / interactive prompts
``AWS_PAGER`` / ...          (see :data:`_BASE_ENV_LITERALS`)
===========================  ==================================================================

``GH_HOST`` / ``GH_ENTERPRISE_TOKEN`` are never present. The sandbox ``HOME`` is created once
per :class:`LocalExecutor` instance (mode ``0o700``) and best-effort removed on GC / at process
exit via a :func:`weakref.finalize` (which covers both the ``__del__`` and ``atexit`` cases).
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import shlex
import shutil
import signal
import subprocess
import tempfile
import time
import weakref
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import httpx

    from opendevops.config import AppConfig
    from opendevops.tools.staging import FileRef


@dataclass(frozen=True)
class ExecResult:
    """Outcome of a single subprocess execution.

    ``scrub_count`` carries the AUTHORITATIVE secret-redaction count from whoever scrubbed the
    output. On the remote path the executor service scrubs and returns its count here; the local
    ``LocalExecutor`` (and ssh) leave it ``None``, and ``_format_result`` then uses its own
    in-process scrub count. This is audit fidelity — the value never affects what the model sees.
    """

    exit_code: int
    output: str
    duration_ms: int
    timed_out: bool
    scrub_count: int | None = None


class CredentialUnavailable(Exception):
    """Raised when a decision requests a credential that is not configured (e.g. rw kube)."""


# Base environment: literally nothing from os.environ (HOME is a private sandbox supplied
# per-executor, not inherited). Everything else here is a fixed literal that
# suppresses pagers / colour / interactive prompts across CLIs.
_BASE_ENV_LITERALS: dict[str, str] = {
    "NO_COLOR": "1",
    "PAGER": "cat",
    "AWS_PAGER": "",
    "GIT_TERMINAL_PROMPT": "0",
    "DEBIAN_FRONTEND": "noninteractive",
    "KUBECTL_INTERACTIVE_DELETE": "false",
}


# Families that talk to the cluster with kube credentials (same KUBECONFIG selection).
_KUBE_FAMILIES = frozenset({"kubectl", "helm"})

# Read-only cloud CLI families. Maps the credential family / argv0 to the config
# ``targets.<attr>`` that names its credential env vars. Note ``az`` -> ``azure`` (the Azure CLI
# binary and credential family are ``az``; the config target is spelled ``azure``).
_CLOUD_FAMILY_TARGET: dict[str, str] = {"aws": "aws", "gcloud": "gcloud", "az": "azure"}


def build_env(
    cfg: AppConfig, tool_family: str | None, channel: str, home: str
) -> dict[str, str]:
    """Construct the child env for one exec: fixed base + exactly one credential decision.

    ``PATH`` is the fixed, validated ``execution.trusted_path``; ``HOME`` is set to *home* — a
    private sandbox dir
    (supplied by the executor), never the operator's ``$HOME`` — so ambient config files like
    ``~/.kube/config`` / ``~/.aws/credentials`` / ``~/.config/gh/hosts.yml`` are unreachable.

    ``KUBECONFIG`` is **always** set explicitly, keyed by ``(tool_family, channel)``:
      * ``kubectl`` / ``helm`` + ``ro`` -> ``KUBECONFIG`` = ``targets.kubernetes.kubeconfig_ro``
        (``helm`` talks to the cluster with the same kube credentials as ``kubectl``)
      * ``kubectl`` / ``helm`` + ``rw`` -> ``KUBECONFIG`` = ``targets.kubernetes.kubeconfig_rw``
        (raises :class:`CredentialUnavailable` if that path is not configured)
      * any other / unknown family -> ``KUBECONFIG`` = ``/dev/null`` (the fail-closed sentinel:
        a mistagged kube call reports "no configuration provided" instead of silently falling
        back to the operator's cluster-admin kubeconfig).

    ``GH_TOKEN`` is injected **only** for the ``gh`` family, from the value of the agent-process
    env var named by ``cfg.targets.github.token_env`` on the ``ro`` channel or
    ``cfg.targets.github.token_env_rw`` on ``rw`` — exactly one PAT, never both, so a rw
    write call never sees the read PAT and vice versa; a missing/unset/empty selected variable
    raises :class:`CredentialUnavailable` (refusal, no exec). The token value never appears in any
    log or error message. A ``gh`` call still gets ``KUBECONFIG=/dev/null`` (the sentinel), and a
    ``kubectl``/``helm`` call never sees ``GH_TOKEN`` — exactly one credential family per exec.
    ``GH_HOST`` / ``GH_ENTERPRISE_TOKEN`` are never present.

    The read-only cloud families (``aws`` / ``gcloud`` / ``az``) inject **only** their own
    credential — the VALUES of the agent-process variables named by
    ``targets.{aws,gcloud,azure}.credential_env``. A missing/empty named variable, or an
    unconfigured (empty) list, raises :class:`CredentialUnavailable` (refusal, no exec); the values
    never appear in any log or error. Each still gets ``KUBECONFIG=/dev/null`` and never sees
    ``GH_TOKEN`` or another cloud family's variables — one credential family per exec.
    """
    safe_base = {"PATH": cfg.execution.trusted_path, "HOME": home}
    env = {name: safe_base[name] for name in cfg.execution.env_allowlist}
    env.update(_BASE_ENV_LITERALS)

    if tool_family in _KUBE_FAMILIES:
        k8s = cfg.targets.kubernetes
        if channel == "rw":
            if k8s.kubeconfig_rw is None:
                raise CredentialUnavailable("rw kubeconfig not configured")
            env["KUBECONFIG"] = str(Path(k8s.kubeconfig_rw).expanduser())
        else:
            env["KUBECONFIG"] = str(Path(k8s.kubeconfig_ro).expanduser())
    else:
        # Fail closed: never let a non-kube (or mistagged) call inherit ambient kube creds.
        env["KUBECONFIG"] = "/dev/null"

    if tool_family == "gh":
        env["GH_TOKEN"] = _gh_token(cfg, channel)
    elif tool_family in _CLOUD_FAMILY_TARGET:
        env.update(_cloud_env(cfg, tool_family))

    return env


def _cloud_env(cfg: AppConfig, tool_family: str) -> dict[str, str]:
    """Resolve a cloud family's credential: the VALUES of the vars named by ``credential_env``.

    Reads ``targets.<aws|gcloud|azure>.credential_env`` (the ``az`` family maps to ``azure``) and
    copies each named variable's value from the agent process. Raises :class:`CredentialUnavailable`
    (never echoing a value) when the list is empty (family unconfigured) or any named variable is
    unset/empty — the same fail-closed refusal pattern as :func:`_gh_token`.
    """
    target = getattr(cfg.targets, _CLOUD_FAMILY_TARGET[tool_family])
    names = target.credential_env
    if not names:
        raise CredentialUnavailable(
            f"{tool_family} credential env vars not configured "
            f"(targets.{_CLOUD_FAMILY_TARGET[tool_family]}.credential_env)"
        )
    resolved: dict[str, str] = {}
    for name in names:
        value = os.environ.get(name)
        if not value:
            raise CredentialUnavailable(
                f"{tool_family} credential env var {name!r} is unset or empty"
            )
        resolved[name] = value
    return resolved


def _gh_token(cfg: AppConfig, channel: str) -> str:
    """Resolve the ``gh`` credential for *channel*, keyed on the env var named in config.

    The ``rw`` channel (the gh-write pack: ``gh run rerun`` / ``gh pr create`` / the ``gh api``
    write allowlist) reads the WRITE PAT from ``targets.github.token_env_rw``; every other channel
    (``ro`` / ``None``) reads the READ PAT from ``targets.github.token_env``. Exactly one is
    injected per exec — the rw PAT is never used on ro and the ro PAT never on rw — so a mistagged
    channel can never smuggle the write credential. Raises :class:`CredentialUnavailable` (never
    echoing the token value) when the selected variable is unconfigured, unset, or empty; a rw gh
    rule firing with no ``token_env_rw`` configured therefore fails closed, matching the ro path.
    """
    github = cfg.targets.github
    if channel == "rw":
        token_env = github.token_env_rw
        if not token_env:
            raise CredentialUnavailable(
                "gh rw token env var not configured (targets.github.token_env_rw)"
            )
    else:
        token_env = github.token_env
        if not token_env:
            raise CredentialUnavailable(
                "gh token env var not configured (targets.github.token_env)"
            )
    value = os.environ.get(token_env)
    if not value:
        raise CredentialUnavailable(f"gh token env var {token_env!r} is unset or empty")
    return value


def _cleanup_home(path: str) -> None:
    """Best-effort removal of a sandbox HOME directory (used by the finalizer)."""
    shutil.rmtree(path, ignore_errors=True)


class LocalExecutor:
    """Runs one argv via ``subprocess.Popen`` in a new session, driven off the event loop.

    Each instance owns a private **sandbox HOME** directory (``tempfile.mkdtemp``, mode
    ``0o700``), created once at construction and used as ``HOME`` for every child env it runs.
    This keeps the operator's ``~/.kube``, ``~/.aws``, ``~/.config/gh`` etc. out of reach of
    executed tools. The directory is best-effort removed on GC / at interpreter exit via a
    :func:`weakref.finalize` (covering both the ``__del__`` and ``atexit`` cases).
    """

    def __init__(self) -> None:
        self._home = tempfile.mkdtemp(prefix="opendevops-home-")
        # mkdtemp already restricts to 0o700; set it explicitly to document the intent.
        os.chmod(self._home, 0o700)
        self._finalizer = weakref.finalize(self, _cleanup_home, self._home)

    @property
    def home(self) -> str:
        """The private sandbox HOME directory for children run by this executor."""
        return self._home

    async def execute(
        self, argv: list[str], timeout_s: int, env: dict[str, str]
    ) -> ExecResult:
        """Execute *argv* with *env*, capturing stdout+stderr, enforcing *timeout_s*.

        On timeout the whole process group is SIGKILLed, partial output is collected, and the
        result carries ``timed_out=True`` / ``exit_code=-9``. An unknown binary yields
        ``exit_code=127``.
        """
        start = time.monotonic()
        try:
            proc = subprocess.Popen(  # noqa: S603 - argv-only, no shell, constructed env
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
                env=env,
                text=True,
                encoding="utf-8",
                # Tools may emit non-UTF-8 bytes (binary blobs, latin-1 logs). Decode
                # leniently so a stray byte becomes U+FFFD instead of raising an uncaught
                # UnicodeDecodeError out of execute() — which would violate the module's
                # "never raises to the model" contract and bypass the scrubber.
                errors="replace",
            )
        except FileNotFoundError:
            duration_ms = int((time.monotonic() - start) * 1000)
            return ExecResult(
                exit_code=127,
                output=f"command not found: {argv[0]}",
                duration_ms=duration_ms,
                timed_out=False,
            )

        output, exit_code, timed_out = await asyncio.to_thread(
            _communicate, proc, timeout_s
        )
        duration_ms = int((time.monotonic() - start) * 1000)
        return ExecResult(
            exit_code=exit_code,
            output=output,
            duration_ms=duration_ms,
            timed_out=timed_out,
        )


# After SIGKILLing the process group on timeout we still drain the pipe to collect partial
# output, but bound that drain: a grandchild that called setsid() escaped the killed group and
# may hold the stdout pipe open, which would hang an unbounded communicate() forever.
_POST_KILL_DRAIN_S = 5


def _communicate(
    proc: subprocess.Popen[str], timeout_s: int
) -> tuple[str, int, bool]:
    """Block on *proc*, killing its process group on timeout. Runs off-thread."""
    try:
        output, _ = proc.communicate(timeout=timeout_s)
        return output or "", proc.returncode, False
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError):  # process group already gone
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        try:
            output, _ = proc.communicate(timeout=_POST_KILL_DRAIN_S)
            return output or "", -9, True
        except subprocess.TimeoutExpired:
            # A setsid()-escaped grandchild is still holding the pipe open. Stop waiting:
            # reap the (killed) direct child, salvage whatever was buffered, close the pipes
            # and return. Output may be truncated — that is the documented trade for not
            # hanging the executor indefinitely.
            proc.poll()
            partial = _drain_partial(proc)
            _close_streams(proc)
            return partial, -9, True


def _drain_partial(proc: subprocess.Popen[str]) -> str:
    """Salvage already-buffered stdout after a drain timeout (best-effort, no blocking).

    ``Popen`` accumulates read chunks in the private ``_fileobj2output`` mapping across
    ``communicate`` calls; recover them if present, else return ``""``. Guarded with
    ``getattr`` so a CPython internals change degrades to empty output rather than raising.
    """
    buffered = getattr(proc, "_fileobj2output", None)
    if not buffered:
        return ""
    parts: list[str] = []
    for chunks in buffered.values():
        for chunk in chunks:
            if isinstance(chunk, bytes):
                parts.append(chunk.decode("utf-8", "replace"))
            else:
                parts.append(str(chunk))
    return "".join(parts)


def _close_streams(proc: subprocess.Popen[str]) -> None:
    """Close any open child pipe handles (releases fds held by an escaped grandchild)."""
    for stream in (proc.stdout, proc.stderr, proc.stdin):
        if stream is not None:
            with contextlib.suppress(OSError):
                stream.close()


# --------------------------------------------------------------------------------------
# ssh remote-exec: the SshExecutor for the structured ssh_run tool
# --------------------------------------------------------------------------------------

# Host connection timeout (separate from the per-command timeout the model requests): bounds how
# long a connect/auth/host-key handshake may hang before we fail closed with a refusal.
_SSH_CONNECT_TIMEOUT_S = 15


class SshConnectionError(Exception):
    """Raised when an ssh connect / host-key verification / auth fails (fail-closed refusal).

    Distinct from a command that actually RAN (which returns an :class:`ExecResult`, including a
    per-command timeout): a connection or host-key-verification failure means NOTHING executed, so
    ``ssh_run`` turns this into a refusal with NO execution-audit event — the same posture as
    run_command's boundary refusals. Host-key verification is always ON (``known_hosts`` pinned), so
    an unknown/mismatched server key surfaces here and fails closed.
    """


@dataclass(frozen=True)
class SshCredential:
    """The config-pinned ssh credential for one ``ssh_run`` exec (never model-supplied)."""

    user: str
    key_path: str
    known_hosts_path: str
    port: int
    passphrase: str | None = None


def resolve_ssh_credential(cfg: AppConfig) -> SshCredential:
    """Resolve the config-pinned ssh credential, or raise :class:`CredentialUnavailable`.

    Fail-closed on every missing piece (the same refusal pattern as :func:`_gh_token`): an
    unconfigured/unset key env var, a missing pinned user, or a ``known_hosts`` file that is
    unconfigured OR configured-but-absent-on-disk (host-key verification must stay ON — there is no
    path that disables it; the on-disk pre-flight is Minor 1). Only the NAME of the key/passphrase
    env var lives in config; the VALUES are read here and never logged.
    """
    ssh = cfg.targets.ssh
    if not ssh.key_env:
        raise CredentialUnavailable("ssh key env var not configured (targets.ssh.key_env)")
    key_path = os.environ.get(ssh.key_env)
    if not key_path:
        raise CredentialUnavailable(f"ssh key env var {ssh.key_env!r} is unset or empty")
    if not ssh.user:
        raise CredentialUnavailable("ssh user not configured (targets.ssh.user)")
    if ssh.known_hosts_path is None:
        raise CredentialUnavailable(
            "ssh known_hosts not configured (targets.ssh.known_hosts_path); "
            "host-key verification cannot be disabled"
        )
    # Minor 1: pre-flight the configured file exists, so the documented "missing known_hosts ->
    # refuse" lands at credential resolution, not only at connect. An empty-but-present file stays
    # acceptably fail-closed at connect (asyncssh rejects all keys), so only presence is required.
    if not Path(ssh.known_hosts_path).is_file():
        raise CredentialUnavailable(
            f"ssh known_hosts file {str(ssh.known_hosts_path)!r} does not exist "
            "(targets.ssh.known_hosts_path); host-key verification cannot be disabled"
        )
    passphrase: str | None = None
    if ssh.key_passphrase_env:
        passphrase = os.environ.get(ssh.key_passphrase_env) or None
    return SshCredential(
        user=ssh.user,
        key_path=str(Path(key_path).expanduser()),
        known_hosts_path=str(ssh.known_hosts_path),
        port=ssh.port,
        passphrase=passphrase,
    )


def _ssh_output(value: object) -> str:
    """Coerce asyncssh's stdout (str under the default text encoding, or bytes) to str."""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value if isinstance(value, str) else ""


class SshExecutor:
    """Runs one remote ``argv`` over asyncssh with host-key verification pinned.

    Probe finding (asyncssh 2.24.0): the SSH protocol's ``exec`` channel carries a SINGLE command
    string — there is no argv-vector remote exec — which the remote sshd runs under the login user's
    shell. To keep the model's ``argv`` free of remote-shell interpretation, each element is
    shell-quoted with :func:`shlex.join` before it is sent: a token like ``a; rm -rf /`` or
    ``$(id)`` is single-quoted, so the remote shell parses the string back into EXACTLY the original
    argv with no metacharacter expansion (pipes / ``;`` / ``&&`` / globs / ``$(...)`` / redirects
    are all neutralized). THREAT-MODEL ASSUMPTION: ``shlex.join`` produces POSIX-``sh``
    single-quoted tokens, so the neutralization holds only against a POSIX-compatible remote login
    shell; a non-POSIX login shell (csh/tcsh, fish, or a Windows ``cmd.exe`` where single quotes do
    not quote) is out of the stated threat model (the Linux-tool read allowlist keeps the residual
    narrow). ``asyncssh`` is imported LAZILY so the ``ssh`` extra stays optional — nothing on the
    boot path imports it.

    Host-key verification is ON: ``known_hosts`` is the config-pinned file, so an unknown/mismatched
    server key raises (``asyncssh.HostKeyNotVerifiable`` ⊂ ``asyncssh.Error``) and is re-raised as
    :class:`SshConnectionError` — a refusal, no exec. A per-command timeout returns an
    :class:`ExecResult` with ``timed_out=True`` (the command DID start), mirroring
    :class:`LocalExecutor`.
    """

    async def execute(
        self, host: str, argv: list[str], timeout_s: int, cred: SshCredential
    ) -> ExecResult:
        """Connect to *host* (config creds), run *argv* shell-quoted, collect merged output."""
        import asyncssh

        command = shlex.join(argv)
        start = time.monotonic()
        try:
            async with asyncssh.connect(
                host,
                port=cred.port,
                username=cred.user,
                client_keys=[cred.key_path],
                passphrase=cred.passphrase,
                known_hosts=cred.known_hosts_path,
                connect_timeout=_SSH_CONNECT_TIMEOUT_S,
            ) as conn:
                try:
                    result = await conn.run(
                        command, stderr=asyncssh.STDOUT, timeout=timeout_s
                    )
                except (asyncssh.TimeoutError, TimeoutError) as exc:
                    duration_ms = int((time.monotonic() - start) * 1000)
                    return ExecResult(
                        exit_code=-9,
                        output=_ssh_output(getattr(exc, "stdout", "")),
                        duration_ms=duration_ms,
                        timed_out=True,
                    )
        except asyncssh.Error as exc:
            # Connect / auth / host-key-verification failure: nothing ran → refusal (no exec-meta).
            raise SshConnectionError(f"ssh connection to {host!r} failed: {exc}") from exc
        except OSError as exc:  # DNS failure / connection refused / host unreachable
            raise SshConnectionError(f"ssh connection to {host!r} failed: {exc}") from exc

        duration_ms = int((time.monotonic() - start) * 1000)
        code = result.returncode if isinstance(result.returncode, int) else 0
        return ExecResult(
            exit_code=code,
            output=_ssh_output(result.stdout),
            duration_ms=duration_ms,
            timed_out=False,
        )


# --------------------------------------------------------------------------------------
# RemoteExecutor client + Local/Remote selection (the executor split)
# --------------------------------------------------------------------------------------

# How long the client waits for the service beyond the per-command timeout (connect + service
# overhead + the drain the service itself allows on a timeout).
_REMOTE_OVERHEAD_S = 30


class RemoteExecutorError(Exception):
    """A remote execution could not be completed (transport failure or a service-side refusal).

    Raised by :class:`RemoteExecutor`; ``run_command_core`` turns it into a fail-closed refusal
    string (no execution audit event), mirroring the local boundary refusals.
    """


def _default_run_id() -> str:
    """The current run's ``run_id`` from the langgraph runtime — ambient, no threading required.

    ``get_runtime()`` reads the runtime langgraph stashes in a contextvar during node/tool
    execution; the tool coroutine's copied context inherits it, so ``RemoteExecutor`` (invoked from
    ``run_command_core``, inside the tool) can bind ``run_id`` into the signed token WITHOUT
    threading it through the middleware or the tool signature. Imported lazily so the executor
    service (which imports this module for ``build_env`` / ``LocalExecutor``) does not pull
    langgraph unless a RemoteExecutor actually runs.
    """
    from opendevops.context import AgentContext

    try:
        from langgraph.runtime import get_runtime

        runtime = get_runtime(AgentContext)
    except Exception as exc:  # noqa: BLE001 - outside a graph run there is no ambient runtime
        raise RemoteExecutorError(
            "no langgraph runtime available; cannot resolve run_id for the decision token"
        ) from exc
    run_id = getattr(getattr(runtime, "context", None), "run_id", None)
    if not run_id:
        raise RemoteExecutorError("no run_id in runtime context; cannot sign a decision token")
    return str(run_id)


def _ref_to_wire(ref: FileRef) -> dict[str, Any]:
    """Serialize a staged :class:`FileRef` for the request body (content travels to the service)."""
    return {
        "flag": ref.flag,
        "virtual_path": ref.virtual_path,
        "content": ref.content,
        "sha256": ref.sha256,
        "argv_index": ref.argv_index,
        "inline": ref.inline,
        "inline_prefix": ref.inline_prefix,
    }


class RemoteExecutor:
    """Signs each exec with an ed25519 decision token and POSTs it to the executor service.

    The agent process this runs in holds **no** infra credential and **no** secret value — only the
    ed25519 *private* signing key and the service URL. The request carries the authorized argv, the
    run/call correlation fields, the staged file CONTENT (materialization happens in the service),
    and the signed token; the service verifies the token, builds the credential env, resolves
    ``{{secret:NAME}}`` into the subprocess env, runs argv ``shell=False``, full-scrubs the output,
    and returns the same :class:`ExecResult` shape :class:`LocalExecutor` would — so the caller's
    ToolMessage / EXEC_META contract is identical on both paths.

    Injection seams (for the in-process round-trip test against a fake service, no real network):
    ``client`` (an ``httpx.AsyncClient``, e.g. over ``ASGITransport``), ``private_key``,
    ``run_id_provider`` and ``now`` (deterministic token ``exp``).
    """

    def __init__(
        self,
        cfg: AppConfig,
        *,
        client: httpx.AsyncClient | None = None,
        private_key: Any = None,
        run_id_provider: Callable[[], str] | None = None,
        now: Callable[[], float] = time.time,
    ) -> None:
        self._url = (cfg.executor.url or "").rstrip("/")
        self._signing_key_env = cfg.executor.signing_key_env
        self._private_key = private_key
        self._client = client
        self._run_id_provider = run_id_provider or _default_run_id
        self._now = now

    def _key(self) -> Any:
        if self._private_key is None:
            from opendevops.tools.signing import load_private_key_from_env

            self._private_key = load_private_key_from_env(self._signing_key_env)
        return self._private_key

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            import httpx

            self._client = httpx.AsyncClient()
        return self._client

    async def run_remote(
        self,
        argv: Sequence[str],
        timeout_s: int,
        *,
        decision: Any,
        tool_call_id: str | None,
        refs: Sequence[FileRef],
    ) -> ExecResult:
        """Sign the authorized argv + staging plan + tool_family, POST, then map the service reply.

        ``decision`` is the ``current_decision`` ExecDecision (duck-typed here to avoid importing
        ``run_command``): it supplies ``channel`` + ``tool_family``. The token binds the exact argv
        the decision gate authorized, the staged-file PLAN (content + rewrite metadata) the agent's
        ``resolve_file_refs`` produced, and the credential ``tool_family`` — so the service cannot
        materialize substituted content, apply a rewritten staging plan, or select a different
        credential than the policy engine authorized. Staging + secret resolution run in the service
        AFTER it re-verifies all of that.
        """
        from opendevops.tools.signing import sign_decision

        run_id = self._run_id_provider()
        channel = str(getattr(decision, "channel", "ro"))
        tool_family = getattr(decision, "tool_family", None)
        tcid = tool_call_id or ""
        token = sign_decision(
            argv, refs, run_id, tcid, channel, tool_family, self._key(), now=self._now
        )
        body = {
            "argv": list(argv),
            "run_id": run_id,
            "tool_call_id": tcid,
            "channel": channel,
            "tool_family": tool_family,
            "timeout_s": timeout_s,
            "staged_files": [_ref_to_wire(r) for r in refs],
            "token": token.to_dict(),
        }
        client = self._http()
        try:
            resp = await client.post(
                f"{self._url}/execute", json=body, timeout=timeout_s + _REMOTE_OVERHEAD_S
            )
        except Exception as exc:  # noqa: BLE001 - any transport failure is a fail-closed refusal
            raise RemoteExecutorError(f"executor service unreachable: {exc}") from exc

        if resp.status_code != 200:
            raise RemoteExecutorError(
                f"executor service refused the request ({resp.status_code}): {_safe_detail(resp)}"
            )
        data = resp.json()
        try:
            raw_count = data.get("scrub_count")
            return ExecResult(
                exit_code=int(data["exit_code"]),
                output=str(data["output"]),
                duration_ms=int(data["duration_ms"]),
                timed_out=bool(data["timed_out"]),
                # The service's AUTHORITATIVE secret-scrub count (M2); None-safe if absent.
                scrub_count=int(raw_count) if raw_count is not None else None,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise RemoteExecutorError(
                f"executor service returned a malformed result: {exc}"
            ) from exc


def _safe_detail(resp: httpx.Response) -> str:
    """A short, secret-free message from a non-200 response (never echoes a body that may leak)."""
    try:
        payload = resp.json()
    except Exception:  # noqa: BLE001 - non-JSON error body
        return resp.reason_phrase or "error"
    if isinstance(payload, dict):
        detail = payload.get("detail")
        if isinstance(detail, str):
            return detail
    return "error"


def select_executor(cfg: AppConfig) -> RemoteExecutor | None:
    """Choose the executor for ``run_command`` from ``cfg.executor.mode``.

    Returns a :class:`RemoteExecutor` for ``mode == "remote"``; returns ``None`` for ``local`` so
    ``run_command_core`` keeps using its in-process default :class:`LocalExecutor` UNCHANGED (the
    local path is byte-for-byte identical to before the split — the hard invariant).
    """
    if cfg.executor.mode == "remote":
        return RemoteExecutor(cfg)
    return None
