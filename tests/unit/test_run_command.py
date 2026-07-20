"""Tests for the argv-only run_command execution tool.

Covers the decision-gate contextvar, argv boundary rejection, the constructed
(never-inherited) env + credential map, the LocalExecutor (timeout / unknown
binary), the output pipeline (ANSI-strip -> scrub -> sha256 -> truncate), and the
virtual-FS spill on truncation.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
from deepagents.backends.utils import create_file_data
from langchain_core.messages import ToolMessage
from langchain_core.tools import BaseTool
from langgraph.types import Command

from opendevops.config import AppConfig, load_config
from opendevops.tools.executor import (
    CredentialUnavailable,
    ExecResult,
    LocalExecutor,
    build_env,
)
from opendevops.tools.run_command import (
    EXEC_META_KEY,
    ExecDecision,
    current_decision,
    make_run_command,
    run_command_core,
)
from opendevops.tools.scrub import (
    scrub,
    sha256_hex,
    strip_ansi,
    truncate_head_tail,
)

# --------------------------------------------------------------------------------------
# fixtures / helpers
# --------------------------------------------------------------------------------------

BASE_CONFIG: dict[str, Any] = {
    "targets": {
        "kubernetes": {
            "kubeconfig_ro": "/tmp/agent-kubeconfig-ro.yaml",
            "kubeconfig_rw": None,
            "allowed_contexts": [],
        }
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


@pytest.fixture
def make_cfg(tmp_path: Path) -> Callable[..., AppConfig]:
    """Build a validated AppConfig, letting a test override select fields."""
    import copy

    import yaml

    def _make(
        *,
        output_max_chars: int | None = None,
        cmd_timeout_seconds: int | None = None,
        kubeconfig_ro: str | None = None,
        kubeconfig_rw: str | None = None,
        github_token_env: str | None = None,
        github_token_env_rw: str | None = None,
        github_write_repos: list[str] | None = None,
        aws_credential_env: list[str] | None = None,
        gcloud_credential_env: list[str] | None = None,
        azure_credential_env: list[str] | None = None,
    ) -> AppConfig:
        cfg = copy.deepcopy(BASE_CONFIG)
        if output_max_chars is not None:
            cfg["execution"]["output_max_chars"] = output_max_chars
        if cmd_timeout_seconds is not None:
            cfg["execution"]["cmd_timeout_seconds"] = cmd_timeout_seconds
        if kubeconfig_ro is not None:
            cfg["targets"]["kubernetes"]["kubeconfig_ro"] = kubeconfig_ro
        if kubeconfig_rw is not None:
            cfg["targets"]["kubernetes"]["kubeconfig_rw"] = kubeconfig_rw
        gh_target: dict[str, Any] = {}
        if github_token_env is not None:
            gh_target["token_env"] = github_token_env
        if github_token_env_rw is not None:
            gh_target["token_env_rw"] = github_token_env_rw
        if github_write_repos is not None:
            gh_target["write_repos"] = github_write_repos
        if gh_target:
            cfg["targets"]["github"] = gh_target
        if aws_credential_env is not None:
            cfg["targets"]["aws"] = {"credential_env": aws_credential_env}
        if gcloud_credential_env is not None:
            cfg["targets"]["gcloud"] = {"credential_env": gcloud_credential_env}
        if azure_credential_env is not None:
            cfg["targets"]["azure"] = {"credential_env": azure_credential_env}
        cdir = tmp_path / "config"
        cdir.mkdir(parents=True, exist_ok=True)
        (cdir / "config.yaml").write_text(yaml.safe_dump(cfg))
        (cdir / "models.yaml").write_text(yaml.safe_dump(BASE_MODELS))
        (cdir / "budgets.yaml").write_text(yaml.safe_dump(BASE_BUDGETS))
        return load_config(tmp_path)

    return _make


@pytest.fixture(autouse=True)
def _reset_decision() -> Any:
    """Keep the decision contextvar from leaking between tests."""
    token = current_decision.set(None)
    yield
    current_decision.reset(token)


@contextmanager
def decision(dec: ExecDecision | None) -> Any:
    tok = current_decision.set(dec)
    try:
        yield
    finally:
        current_decision.reset(tok)


class SpyExecutor:
    """Records whether execute() was ever reached (proves the gate blocks it)."""

    # run_command_core reads active_executor.home to build the sandbox HOME env; a plain
    # string is enough here since this double never actually spawns a process.
    home = "/tmp/spy-sandbox-home"

    def __init__(self) -> None:
        self.called = False

    async def execute(
        self, argv: list[str], timeout_s: int, env: dict[str, str]
    ) -> ExecResult:
        self.called = True
        return ExecResult(exit_code=0, output="ran", duration_ms=1, timed_out=False)


def _mk_decision(
    argv: tuple[str, ...],
    *,
    channel: str = "ro",
    family: str | None = None,
    tool_call_id: str = "call_1",
) -> ExecDecision:
    return ExecDecision(
        tool_call_id=tool_call_id, channel=channel, tool_family=family, argv=argv
    )


def _exec_meta(out: Any) -> dict[str, Any] | None:
    """Read run_command's per-exec meta off the returned ToolMessage (direct or inside a Command).

    The tool now carries its audit facts on the ToolMessage's ``additional_kwargs[EXEC_META_KEY]``
    (a return-value channel that survives langchain's tool boundary), not a ContextVar.
    """
    msg: ToolMessage | None = None
    if isinstance(out, ToolMessage):
        msg = out
    elif isinstance(out, Command):
        for m in out.update.get("messages", []):
            if isinstance(m, ToolMessage):
                msg = m
                break
    return None if msg is None else msg.additional_kwargs.get(EXEC_META_KEY)


# --------------------------------------------------------------------------------------
# tool construction / boundary
# --------------------------------------------------------------------------------------


def test_make_run_command_returns_named_tool(make_cfg: Callable[..., AppConfig]) -> None:
    tool = make_run_command(make_cfg())
    assert isinstance(tool, BaseTool)
    assert tool.name == "run_command"
    desc = tool.description.lower()
    assert "argv" in desc
    assert "shell" in desc  # documents no-shell contract
    schema = tool.args
    assert "argv" in schema
    assert "timeout_s" in schema
    # the injected ToolRuntime must NOT be advertised to the model
    assert "runtime" not in schema
    assert set(tool.tool_call_schema.model_fields) == {"argv", "timeout_s"}


async def test_boundary_rejects_empty_argv(make_cfg: Callable[..., AppConfig]) -> None:
    spy = SpyExecutor()
    with decision(_mk_decision(())):
        out = await run_command_core([], 60, make_cfg(), tool_call_id="call_1", executor=spy)
    assert isinstance(out, str)
    assert "argv" in out.lower()
    assert not spy.called


async def test_boundary_rejects_non_string_element(
    make_cfg: Callable[..., AppConfig],
) -> None:
    spy = SpyExecutor()
    with decision(_mk_decision(("kubectl", "get"))):
        out = await run_command_core(
            ["kubectl", 5], 60, make_cfg(), tool_call_id="call_1", executor=spy  # type: ignore[list-item]
        )
    assert isinstance(out, str)
    assert not spy.called


async def test_boundary_rejects_slash_in_argv0(
    make_cfg: Callable[..., AppConfig],
) -> None:
    spy = SpyExecutor()
    for bad in ["/usr/bin/env", "../evil", "./local"]:
        with decision(_mk_decision((bad,))):
            out = await run_command_core(
                [bad], 60, make_cfg(), tool_call_id="call_1", executor=spy
            )
        assert isinstance(out, str)
        assert "/" in out or "bare" in out.lower()
        assert not spy.called


# --------------------------------------------------------------------------------------
# decision gate
# --------------------------------------------------------------------------------------


async def test_gate_refuses_without_decision(make_cfg: Callable[..., AppConfig]) -> None:
    spy = SpyExecutor()
    # no decision set (default None)
    out = await run_command_core(
        ["true"], 60, make_cfg(), tool_call_id="call_1", executor=spy
    )
    assert out == "execution refused: no policy decision"
    assert not spy.called


async def test_gate_refuses_on_argv_mismatch(
    make_cfg: Callable[..., AppConfig],
) -> None:
    spy = SpyExecutor()
    with decision(_mk_decision(("kubectl", "get", "pods"))):
        out = await run_command_core(
            ["kubectl", "delete", "pods"], 60, make_cfg(), tool_call_id="call_1", executor=spy
        )
    assert out == "execution refused: no policy decision"
    assert not spy.called


async def test_gate_refuses_on_tool_call_id_mismatch(
    make_cfg: Callable[..., AppConfig],
) -> None:
    spy = SpyExecutor()
    with decision(_mk_decision(("true",), tool_call_id="call_A")):
        out = await run_command_core(
            ["true"], 60, make_cfg(), tool_call_id="call_B", executor=spy
        )
    assert out == "execution refused: no policy decision"
    assert not spy.called


async def test_gate_allows_matching_decision(
    make_cfg: Callable[..., AppConfig],
) -> None:
    spy = SpyExecutor()
    with decision(_mk_decision(("true",), tool_call_id="call_1")):
        out = await run_command_core(
            ["true"], 60, make_cfg(), tool_call_id="call_1", executor=spy
        )
    assert spy.called
    # With a tool_call_id, run_command returns a ToolMessage carrying the exec meta.
    assert isinstance(out, ToolMessage)
    assert out.content.startswith("exit_code: 0")
    meta = _exec_meta(out)
    assert meta is not None
    assert meta["exit_code"] == 0


async def test_gate_allows_when_runtime_provides_no_tool_call_id(
    make_cfg: Callable[..., AppConfig],
) -> None:
    """tool_call_id check only applies when the runtime provides one."""
    spy = SpyExecutor()
    with decision(_mk_decision(("true",), tool_call_id="whatever")):
        out = await run_command_core(
            ["true"], 60, make_cfg(), tool_call_id=None, executor=spy
        )
    assert spy.called
    assert out.startswith("exit_code: 0")


# --------------------------------------------------------------------------------------
# constructed env + credential map (executor-level, boundary bypassed legitimately)
# --------------------------------------------------------------------------------------

_EXPECTED_BASE_KEYS = {
    "PATH",
    "HOME",
    "NO_COLOR",
    "PAGER",
    "AWS_PAGER",
    "GIT_TERMINAL_PROMPT",
    "DEBIAN_FRONTEND",
    "KUBECTL_INTERACTIVE_DELETE",
}


# A stand-in sandbox HOME for the pure build_env unit tests (the real one is per-executor).
_SANDBOX_HOME = "/tmp/opendevops-sandbox-home"


def test_build_env_base_keys_only(make_cfg: Callable[..., AppConfig]) -> None:
    env = build_env(make_cfg(), None, None, _SANDBOX_HOME)
    # KUBECONFIG is now always set (to the /dev/null sentinel when no kubectl cred applies).
    assert set(env) == _EXPECTED_BASE_KEYS | {"KUBECONFIG"}
    # HOME is the sandbox dir, never the operator's $HOME.
    assert env["HOME"] == _SANDBOX_HOME
    assert env["HOME"] != os.environ.get("HOME")
    assert env["KUBECONFIG"] == "/dev/null"
    assert env["NO_COLOR"] == "1"
    assert env["PAGER"] == "cat"
    assert env["AWS_PAGER"] == ""
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["DEBIAN_FRONTEND"] == "noninteractive"
    assert env["KUBECTL_INTERACTIVE_DELETE"] == "false"


def test_build_env_kubectl_ro_adds_kubeconfig(
    make_cfg: Callable[..., AppConfig],
) -> None:
    cfg = make_cfg(kubeconfig_ro="/tmp/fake-ro.yaml")
    env = build_env(cfg, "kubectl", "ro", _SANDBOX_HOME)
    assert env["KUBECONFIG"] == "/tmp/fake-ro.yaml"
    # exactly one credential added
    assert set(env) == _EXPECTED_BASE_KEYS | {"KUBECONFIG"}
    assert "GH_TOKEN" not in env


def test_build_env_kubectl_rw(make_cfg: Callable[..., AppConfig]) -> None:
    cfg = make_cfg(kubeconfig_rw="/tmp/fake-rw.yaml")
    env = build_env(cfg, "kubectl", "rw", _SANDBOX_HOME)
    assert env["KUBECONFIG"] == "/tmp/fake-rw.yaml"


def test_build_env_kubectl_rw_none_raises(
    make_cfg: Callable[..., AppConfig],
) -> None:
    cfg = make_cfg()  # kubeconfig_rw is None
    with pytest.raises(CredentialUnavailable):
        build_env(cfg, "kubectl", "rw", _SANDBOX_HOME)


def test_build_env_unknown_family_kubeconfig_sentinel(
    make_cfg: Callable[..., AppConfig],
) -> None:
    # A non-kubectl (or mistagged) family gets KUBECONFIG=/dev/null so it fails closed
    # instead of silently using the operator's ambient kubeconfig.
    env = build_env(make_cfg(), "github", "ro", _SANDBOX_HOME)
    assert set(env) == _EXPECTED_BASE_KEYS | {"KUBECONFIG"}
    assert env["KUBECONFIG"] == "/dev/null"
    assert "GH_TOKEN" not in env
    assert "GH_HOST" not in env
    assert "GH_ENTERPRISE_TOKEN" not in env


# Keys some platforms inject into *any* child regardless of the passed env: macOS
# CoreFoundation adds __CF_USER_TEXT_ENCODING and CPython's C-locale coercion (PEP 538)
# sets LC_CTYPE. These are regenerated by the OS/runtime, not inherited parent VALUES —
# the security-critical property (no parent env value leaks) still holds and is asserted.
_OS_INJECTED_KEYS = {"LC_CTYPE", "__CF_USER_TEXT_ENCODING"}


async def test_executor_env_is_never_inherited(
    make_cfg: Callable[..., AppConfig], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Run a real subprocess dumping os.environ; nothing from the parent env is inherited."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-secret-should-not-leak")
    monkeypatch.setenv("SOME_OTHER_SECRET", "leaky")
    # Sentinels on the OS-injected keys too: prove even those are regenerated, not inherited.
    monkeypatch.setenv("LC_CTYPE", "PARENT-SENTINEL")
    monkeypatch.setenv("__CF_USER_TEXT_ENCODING", "PARENT-SENTINEL")
    cfg = make_cfg(kubeconfig_ro="/tmp/fake-ro.yaml")
    ex = LocalExecutor()
    env = build_env(cfg, "kubectl", "ro", ex.home)
    res = await ex.execute(
        ["python3", "-c", "import os,json;print(json.dumps(dict(os.environ)))"],
        10,
        env,
    )
    assert res.exit_code == 0
    child_env = json.loads(res.output)
    # every constructed key is present with the constructed value
    assert set(child_env) >= _EXPECTED_BASE_KEYS
    assert child_env["KUBECONFIG"] == "/tmp/fake-ro.yaml"
    assert child_env["NO_COLOR"] == "1"
    assert child_env["AWS_PAGER"] == ""
    # HOME in the child is the private sandbox dir, NOT the operator's HOME.
    assert child_env["HOME"] == ex.home
    assert child_env["HOME"] != os.environ["HOME"]
    # no parent secret leaks
    assert "ANTHROPIC_API_KEY" not in child_env
    assert "SOME_OTHER_SECRET" not in child_env
    # the only extras are OS/runtime-injected keys, and even they carry fresh (not parent) values
    extras = set(child_env) - _EXPECTED_BASE_KEYS - {"KUBECONFIG"}
    assert extras <= _OS_INJECTED_KEYS, f"unexpected inherited keys: {extras}"
    for key in extras:
        assert child_env[key] != "PARENT-SENTINEL"


async def test_executor_env_no_credential_kubeconfig_sentinel(
    make_cfg: Callable[..., AppConfig],
) -> None:
    ex = LocalExecutor()
    env = build_env(make_cfg(), None, None, ex.home)
    res = await ex.execute(
        ["python3", "-c", "import os,json;print(json.dumps(dict(os.environ)))"],
        10,
        env,
    )
    child_env = json.loads(res.output)
    # KUBECONFIG is always set; with no kubectl credential it is the fail-closed sentinel.
    assert child_env["KUBECONFIG"] == "/dev/null"
    assert child_env["HOME"] == ex.home


# --------------------------------------------------------------------------------------
# LocalExecutor: timeout / unknown binary
# --------------------------------------------------------------------------------------


async def test_executor_timeout(make_cfg: Callable[..., AppConfig]) -> None:
    ex = LocalExecutor()
    env = build_env(make_cfg(), None, None, ex.home)
    res = await ex.execute(["sleep", "5"], 1, env)
    assert res.timed_out is True
    assert res.exit_code == -9
    assert 500 <= res.duration_ms <= 4000  # ~1s, generous bounds


async def test_executor_unknown_binary(make_cfg: Callable[..., AppConfig]) -> None:
    ex = LocalExecutor()
    env = build_env(make_cfg(), None, None, ex.home)
    res = await ex.execute(["this-binary-does-not-exist-xyz-123"], 5, env)
    assert res.exit_code == 127
    assert "command not found" in res.output


async def test_executor_captures_stderr_via_stdout(
    make_cfg: Callable[..., AppConfig],
) -> None:
    ex = LocalExecutor()
    env = build_env(make_cfg(), None, None, ex.home)
    res = await ex.execute(
        ["python3", "-c", "import sys;sys.stderr.write('errline\\n');sys.exit(3)"],
        10,
        env,
    )
    assert res.exit_code == 3
    assert "errline" in res.output


async def test_executor_non_utf8_output_is_replaced_not_raised(
    make_cfg: Callable[..., AppConfig],
) -> None:
    """Invalid UTF-8 on stdout must not raise out of execute(); bytes become U+FFFD."""
    ex = LocalExecutor()
    env = build_env(make_cfg(), None, None, ex.home)
    # Emits raw bytes 0xff 0xfe (invalid UTF-8) followed by "hello".
    res = await ex.execute(
        ["python3", "-c", r"import sys; sys.stdout.buffer.write(b'\xff\xfehello')"],
        10,
        env,
    )
    assert res.exit_code == 0
    assert res.timed_out is False
    assert "�" in res.output  # the replacement character
    assert "hello" in res.output


async def test_pipeline_survives_non_utf8_output(
    make_cfg: Callable[..., AppConfig],
) -> None:
    """The full run_command pipeline (scrub/sha/truncate) runs over replacement-char output."""
    argv = ["python3", "-c", r"import sys; sys.stdout.buffer.write(b'\xff\xfehello')"]
    with decision(_mk_decision(tuple(argv))):
        out = await run_command_core(argv, 10, make_cfg(), tool_call_id="call_1")
    assert isinstance(out, ToolMessage)
    assert out.content.splitlines()[0] == "exit_code: 0"
    assert "hello" in out.content
    assert "�" in out.content
    meta = _exec_meta(out)
    assert meta is not None
    assert "stdout_sha256" in meta
    assert meta["exit_code"] == 0


# --------------------------------------------------------------------------------------
# scrubber (table-driven)
# --------------------------------------------------------------------------------------

_SECRETS = [
    ("aws_akia", "AKIAIOSFODNN7EXAMPLE"),
    ("github_ghp", "ghp_A1b2C3d4E5f6G7h8I9j0K1L2m3N4o5P6q7R8"),
    ("github_pat", "github_pat_11ABCDE0Y0abcdefghij_klmnopqrstuvwxyz0123456789ABCDEFGH"),
    ("github_gho", "gho_A1b2C3d4E5f6G7h8I9j0K1L2m3N4o5P6q7R8"),
    ("github_ghu", "ghu_A1b2C3d4E5f6G7h8I9j0K1L2m3N4o5P6q7R8"),
    ("github_ghs", "ghs_A1b2C3d4E5f6G7h8I9j0K1L2m3N4o5P6q7R8"),
    ("github_ghr", "ghr_A1b2C3d4E5f6G7h8I9j0K1L2m3N4o5P6q7R8"),
    # Split literal: GitHub push protection flags contiguous xoxb-shaped strings.
    ("slack_xoxb", "xoxb-1234567890-" "0987654321-AbCdEfGhIjKlMnOp"),
    ("slack_xoxp", "xoxp-1234567890-abcdefghij"),
    (
        "jwt",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    ),
    ("anthropic", "sk-ant-api03-abcdefghijklmnopqrstuvwxyz012345"),
    ("openai", "sk-abcdefghijklmnopqrstuvwxyz0123456789AB"),
]


@pytest.mark.parametrize("name,secret", _SECRETS, ids=[s[0] for s in _SECRETS])
def test_scrub_replaces_known_secret(name: str, secret: str) -> None:
    text = f"prefix {secret} suffix"
    out, count = scrub(text)
    assert secret not in out, f"{name} leaked: {out!r}"
    assert "***" in out
    assert count >= 1
    assert "prefix" in out and "suffix" in out


def test_scrub_pem_private_key_multiline() -> None:
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n"
        "KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwEC\n"
        "-----END RSA PRIVATE KEY-----"
    )
    text = f"here is a key:\n{pem}\ndone"
    out, count = scrub(text)
    assert "PRIVATE KEY" not in out
    assert "MIIBOgIBAA" not in out
    assert count >= 1
    assert "here is a key" in out and "done" in out


def test_scrub_exempts_pure_hex_digest() -> None:
    # a sha256 image digest / pod-template-hash: ubiquitous, not a secret
    digest = "a3f5c9e1b7d24680a3f5c9e1b7d24680a3f5c9e1b7d24680a3f5c9e1b7d24680"
    assert len(digest) == 64
    text = f"image: nginx@sha256:{digest}"
    out, count = scrub(text)
    assert digest in out
    assert count == 0


def test_scrub_exempts_uppercase_hex_digest() -> None:
    digest = "A3F5C9E1B7D24680A3F5C9E1B7D24680A3F5C9E1B7D24680A3F5C9E1B7D24680"
    out, count = scrub(f"digest {digest}")
    assert digest in out
    assert count == 0


def test_scrub_exempts_short_strings() -> None:
    text = "the quick brown fox jumps over abcdef1234567890 tiny"
    out, count = scrub(text)
    assert count == 0
    assert out == text


def test_scrub_exempts_paths_starting_with_slash() -> None:
    path = "/var/lib/kubelet/pods/abcdef0123456789abcdef0123456789/volumes"
    out, count = scrub(f"mounted at {path} ok")
    assert path in out
    assert count == 0


def test_scrub_high_entropy_catchall() -> None:
    # a random-looking 43-char base64url token (mixed case + digits, high entropy)
    token = "Zk9pQ2xr7mNvB3wXt5Yh8gJd1Fs6Ua4Ie0Oc2Pb9Lz"
    ent = _shannon(token)
    assert ent > 4.5, f"test token entropy too low: {ent}"
    out, count = scrub(f"token={token} end")
    assert token not in out
    assert count >= 1


def test_scrub_returns_tuple_and_counts() -> None:
    text = "AKIAIOSFODNN7EXAMPLE and AKIAIOSFODNN7EXAMPLZ"
    out, count = scrub(text)
    assert isinstance(out, str)
    assert isinstance(count, int)
    assert count == 2


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# --------------------------------------------------------------------------------------
# ANSI strip / sha256 / truncation
# --------------------------------------------------------------------------------------


def test_strip_ansi_removes_color_codes() -> None:
    assert strip_ansi("\x1b[31mred\x1b[0m text") == "red text"
    assert strip_ansi("plain") == "plain"
    assert strip_ansi("\x1b[1;32mbold green\x1b[0m") == "bold green"


def test_sha256_stability() -> None:
    assert (
        sha256_hex("hello")
        == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    )
    assert sha256_hex("hello") == sha256_hex("hello")
    assert sha256_hex("a") != sha256_hex("b")


def test_truncate_no_op_when_short() -> None:
    text = "short output"
    out, truncated, dropped = truncate_head_tail(text, 1000, None)
    assert out == text
    assert truncated is False
    assert dropped == 0


def test_truncate_head_tail_with_marker() -> None:
    head = "H" * 600
    tail = "T" * 400
    middle = "M" * 500
    text = head + middle + tail
    out, truncated, dropped = truncate_head_tail(text, 100, "/output/call_1.txt")
    assert truncated is True
    assert dropped == len(text) - 100
    # 60% head / 40% tail of 100 chars
    assert out.startswith("H" * 60)
    assert out.endswith("T" * 40)
    assert "/output/call_1.txt" in out
    assert "truncated" in out.lower()


def test_truncate_head_tail_without_fs_path() -> None:
    text = "X" * 500
    out, truncated, dropped = truncate_head_tail(text, 100, None)
    assert truncated is True
    assert "truncated" in out.lower()
    assert str(dropped) in out
    assert "/output/" not in out


# --------------------------------------------------------------------------------------
# full pipeline via run_command_core
# --------------------------------------------------------------------------------------


async def test_pipeline_exit_code_first_line(
    make_cfg: Callable[..., AppConfig],
) -> None:
    with decision(_mk_decision(("python3", "-c", "print('hi')"))):
        out = await run_command_core(
            ["python3", "-c", "print('hi')"],
            10,
            make_cfg(),
            tool_call_id="call_1",
        )
    assert isinstance(out, ToolMessage)
    assert out.content.splitlines()[0] == "exit_code: 0"
    assert "hi" in out.content
    meta = _exec_meta(out)
    assert meta is not None
    assert meta["exit_code"] == 0
    assert meta["truncated"] is False
    assert "stdout_sha256" in meta
    assert "duration_ms" in meta
    assert meta["scrub_count"] == 0


async def test_pipeline_scrubs_secret_and_hashes_scrubbed(
    make_cfg: Callable[..., AppConfig],
) -> None:
    argv = ["python3", "-c", "print('key AKIAIOSFODNN7EXAMPLE here')"]
    with decision(_mk_decision(tuple(argv))):
        out = await run_command_core(argv, 10, make_cfg(), tool_call_id="call_1")
    assert isinstance(out, ToolMessage)
    assert "AKIAIOSFODNN7EXAMPLE" not in out.content
    assert "***" in out.content
    meta = _exec_meta(out)
    assert meta is not None
    assert meta["scrub_count"] >= 1
    # sha256 is over the SCRUBBED text -> equals hash of the scrubbed body
    assert meta["stdout_sha256"] == sha256_hex("key *** here\n")


async def test_pipeline_ansi_stripped(make_cfg: Callable[..., AppConfig]) -> None:
    argv = ["python3", "-c", r"print('\x1b[31mRED\x1b[0m')"]
    with decision(_mk_decision(tuple(argv))):
        out = await run_command_core(argv, 10, make_cfg(), tool_call_id="call_1")
    assert isinstance(out, ToolMessage)
    assert "RED" in out.content
    assert "\x1b[31m" not in out.content


async def test_pipeline_truncation_spills_to_virtual_fs(
    make_cfg: Callable[..., AppConfig],
) -> None:
    # produce > output_max_chars of output; expect a Command spilling full text
    argv = ["python3", "-c", "print('A' * 5000)"]
    cfg = make_cfg(output_max_chars=200)
    with decision(_mk_decision(tuple(argv))):
        out = await run_command_core(argv, 10, cfg, tool_call_id="call_1")
    assert isinstance(out, Command), f"expected Command spill, got {type(out)}"
    files = out.update["files"]
    path = "/output/call_1.txt"
    assert path in files
    full = files[path]["content"]
    assert "A" * 5000 in full  # full scrubbed text spilled
    # the ToolMessage content references the spill path + carries the truncation marker
    msg = out.update["messages"][0]
    assert path in msg.content
    assert "truncated" in msg.content.lower()
    assert msg.content.splitlines()[0] == "exit_code: 0"
    assert msg.tool_call_id == "call_1"
    meta = _exec_meta(out)
    assert meta is not None
    assert meta["truncated"] is True


async def test_pipeline_truncation_without_tool_call_id_returns_string(
    make_cfg: Callable[..., AppConfig],
) -> None:
    # no tool_call_id -> cannot spill and cannot bind a ToolMessage to carry meta; degrade to a
    # bare-string in-band truncation marker (this path is never middleware-wrapped in the graph).
    argv = ["python3", "-c", "print('B' * 5000)"]
    cfg = make_cfg(output_max_chars=200)
    with decision(_mk_decision(tuple(argv))):
        out = await run_command_core(argv, 10, cfg, tool_call_id=None)
    assert isinstance(out, str)
    assert "truncated" in out.lower()
    assert out.splitlines()[0] == "exit_code: 0"
    # no tool_call_id => no ToolMessage => no exec-meta channel
    assert _exec_meta(out) is None


async def test_pipeline_clamps_timeout(make_cfg: Callable[..., AppConfig]) -> None:
    # cmd_timeout_seconds max is 60; asking for 9999 clamps down (does not raise)
    spy = SpyExecutor()

    class RecordingExecutor(SpyExecutor):
        def __init__(self) -> None:
            super().__init__()
            self.timeout_seen = -1

        async def execute(
            self, argv: list[str], timeout_s: int, env: dict[str, str]
        ) -> ExecResult:
            self.timeout_seen = timeout_s
            return await super().execute(argv, timeout_s, env)

    rec = RecordingExecutor()
    with decision(_mk_decision(("true",))):
        await run_command_core(["true"], 9999, make_cfg(), tool_call_id="call_1", executor=rec)
    assert rec.timeout_seen == 60
    with decision(_mk_decision(("true",))):
        await run_command_core(["true"], 0, make_cfg(), tool_call_id="call_1", executor=rec)
    assert rec.timeout_seen == 1
    assert spy is not rec


async def test_pipeline_rw_kubeconfig_missing_refuses(
    make_cfg: Callable[..., AppConfig],
) -> None:
    """A kubectl rw decision with no rw kubeconfig configured is refused, not executed."""
    spy = SpyExecutor()
    argv = ["kubectl", "get", "pods"]
    with decision(_mk_decision(tuple(argv), channel="rw", family="kubectl")):
        out = await run_command_core(
            argv, 10, make_cfg(), tool_call_id="call_1", executor=spy
        )
    assert isinstance(out, str)
    assert "refused" in out.lower()
    assert not spy.called


def _bindable_fake(tool_calls: list[dict[str, Any]]) -> Any:
    """A GenericFakeChatModel that emits one tool-calling turn then a final message."""
    from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
    from langchain_core.messages import AIMessage

    class BindableFake(GenericFakeChatModel):  # type: ignore[misc]
        def bind_tools(self, tools: Any, **kwargs: Any) -> Any:
            return self

    return BindableFake(
        messages=iter(
            [
                AIMessage(content="", tool_calls=tool_calls),
                AIMessage(content="done"),
            ]
        )
    )


async def test_make_run_command_runs_in_real_graph(
    make_cfg: Callable[..., AppConfig],
) -> None:
    """End-to-end through create_deep_agent: ToolRuntime is injected and the tool executes.

    This is the real wiring test — a bare ``tool.ainvoke`` cannot inject ToolRuntime; only the
    graph's ToolNode does. It also confirms the decision contextvar propagates into the graph.
    """
    from deepagents import create_deep_agent
    from deepagents.backends import StateBackend
    from langchain_core.messages import ToolMessage

    cfg = make_cfg()
    tool = make_run_command(cfg)
    argv = ["python3", "-c", "print('graph-ok')"]
    model = _bindable_fake(
        [{"name": "run_command", "args": {"argv": argv, "timeout_s": 10}, "id": "call_g"}]
    )
    agent = create_deep_agent(model=model, tools=[tool], backend=StateBackend())
    with decision(_mk_decision(tuple(argv), tool_call_id="call_g")):
        out = await agent.ainvoke({"messages": [("user", "go")]})
    msgs = [
        m
        for m in out["messages"]
        if isinstance(m, ToolMessage) and m.tool_call_id == "call_g"
    ]
    assert msgs, "run_command tool message not found in graph output"
    content = msgs[0].content
    assert content.splitlines()[0] == "exit_code: 0"
    assert "graph-ok" in content


async def test_make_run_command_gate_refuses_in_real_graph(
    make_cfg: Callable[..., AppConfig],
) -> None:
    """With no policy decision set, the in-graph tool refuses without executing."""
    from deepagents import create_deep_agent
    from deepagents.backends import StateBackend
    from langchain_core.messages import ToolMessage

    tool = make_run_command(make_cfg())
    argv = ["python3", "-c", "print('should-not-run')"]
    model = _bindable_fake(
        [{"name": "run_command", "args": {"argv": argv, "timeout_s": 10}, "id": "call_x"}]
    )
    agent = create_deep_agent(model=model, tools=[tool], backend=StateBackend())
    # no `with decision(...)`: the autouse fixture leaves current_decision = None
    out = await agent.ainvoke({"messages": [("user", "go")]})
    msgs = [
        m
        for m in out["messages"]
        if isinstance(m, ToolMessage) and m.tool_call_id == "call_x"
    ]
    assert msgs
    assert msgs[0].content == "execution refused: no policy decision"


async def test_truncation_spill_persists_and_is_readable_in_graph(
    make_cfg: Callable[..., AppConfig],
) -> None:
    """The spilled /output file lands in the virtual FS and read_file reads it back verbatim.

    This is the durable end-to-end proof of the spill mechanism: run_command truncates and
    returns a Command(files=...); a later read_file call retrieves the full scrubbed output.
    """
    from deepagents import create_deep_agent
    from deepagents.backends import StateBackend
    from langchain_core.messages import ToolMessage

    cfg = make_cfg(output_max_chars=200)
    tool = make_run_command(cfg)
    argv = ["python3", "-c", "print('Z' * 5000)"]
    spill_path = "/output/call_big.txt"
    model = _bindable_fake(
        [{"name": "run_command", "args": {"argv": argv, "timeout_s": 10}, "id": "call_big"}]
    )
    # extend the fake with a second turn that reads the spill file back
    from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
    from langchain_core.messages import AIMessage

    class BindableFake(GenericFakeChatModel):  # type: ignore[misc]
        def bind_tools(self, tools: Any, **kwargs: Any) -> Any:
            return self

    model = BindableFake(
        messages=iter(
            [
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "run_command",
                            "args": {"argv": argv, "timeout_s": 10},
                            "id": "call_big",
                        }
                    ],
                ),
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "read_file",
                            "args": {"file_path": spill_path},
                            "id": "call_read",
                        }
                    ],
                ),
                AIMessage(content="done"),
            ]
        )
    )
    agent = create_deep_agent(model=model, tools=[tool], backend=StateBackend())
    with decision(_mk_decision(tuple(argv), tool_call_id="call_big")):
        out = await agent.ainvoke({"messages": [("user", "go")]})

    # spilled file present in state
    assert spill_path in out["files"]
    assert "Z" * 5000 in out["files"][spill_path]["content"]

    # read_file returned the (line-numbered) full content
    reads = [
        m
        for m in out["messages"]
        if isinstance(m, ToolMessage) and m.tool_call_id == "call_read"
    ]
    assert reads
    assert "Z" * 100 in reads[0].content  # the big line is retrievable in full

    # the run_command ToolMessage referenced the spill path + truncation marker
    runs = [
        m
        for m in out["messages"]
        if isinstance(m, ToolMessage) and m.tool_call_id == "call_big"
    ]
    assert runs
    assert spill_path in runs[0].content
    assert "truncated" in runs[0].content.lower()


def test_os_environ_unchanged_after_build_env(
    make_cfg: Callable[..., AppConfig],
) -> None:
    """build_env must not mutate the parent process environment."""
    before = dict(os.environ)
    build_env(make_cfg(kubeconfig_ro="/tmp/x.yaml"), "kubectl", "ro", _SANDBOX_HOME)
    assert dict(os.environ) == before


def test_executor_sandbox_home_is_private_and_isolated() -> None:
    """Each executor owns a private 0o700 sandbox HOME distinct from the operator's HOME."""
    ex = LocalExecutor()
    home = Path(ex.home)
    assert home.is_dir()
    assert home != Path(os.environ["HOME"])
    assert home.name.startswith("opendevops-home-")
    # created mode 0o700 (owner-only): no group/other bits
    assert (home.stat().st_mode & 0o077) == 0
    # two executors get independent sandboxes
    ex2 = LocalExecutor()
    assert ex2.home != ex.home


async def test_executor_bounds_post_kill_drain_on_escaped_grandchild(
    make_cfg: Callable[..., AppConfig], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A setsid()-escaped grandchild holding the pipe must not hang the executor.

    The child forks a grandchild that calls setsid() (escaping the process group we SIGKILL)
    and keeps stdout open. Without the bounded post-kill drain the second communicate() would
    block until the grandchild exits; the drain bound makes execute() return promptly with
    timed_out=True instead.
    """
    monkeypatch.setattr(
        "opendevops.tools.executor._POST_KILL_DRAIN_S", 1, raising=True
    )
    ex = LocalExecutor()
    env = build_env(make_cfg(), None, None, ex.home)
    prog = (
        "import os, time\n"
        "if os.fork() == 0:\n"
        "    os.setsid()\n"  # grandchild escapes the killed process group
        "    time.sleep(10)\n"  # keeps the inherited stdout pipe open past the drain bound
        "    os._exit(0)\n"
        "time.sleep(10)\n"  # parent stays alive until SIGKILL
    )
    res = await ex.execute(["python3", "-c", prog], 1, env)
    assert res.timed_out is True
    assert res.exit_code == -9
    # ~1s first timeout + ~1s bounded drain (proves the drain branch fired: a single timeout
    # would be ~1s), and must NOT wait for the 10s grandchild sleep (proves the bound works).
    assert 1500 <= res.duration_ms <= 6000


# --------------------------------------------------------------------------------------
# staging bridge: virtual-FS manifest -> per-call tmpdir -> rewritten argv + staged_files meta
# --------------------------------------------------------------------------------------

_MANIFEST = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n"


class StagingCapturingExecutor:
    """Records the argv it received AND reads back the staged file's content during execute().

    Reading during ``execute`` (before run_command_core's ``finally`` rmtree) proves the file was
    materialized on disk at exec time; the captured content proves the round-trip.
    """

    home = "/tmp/staging-spy-home"

    def __init__(self) -> None:
        self.called = False
        self.argv: list[str] | None = None
        self.staged_path: str | None = None
        self.staged_content: str | None = None
        self.existed_at_exec = False

    async def execute(
        self, argv: list[str], timeout_s: int, env: dict[str, str]
    ) -> ExecResult:
        self.called = True
        self.argv = list(argv)
        idx = argv.index("--filename")
        self.staged_path = argv[idx + 1]
        p = Path(self.staged_path)
        self.existed_at_exec = p.exists()
        if self.existed_at_exec:
            self.staged_content = p.read_text()
        return ExecResult(exit_code=0, output="applied", duration_ms=1, timed_out=False)


async def test_staging_materializes_file_and_records_meta(
    make_cfg: Callable[..., AppConfig],
) -> None:
    files = {"/manifests/deploy.yaml": create_file_data(_MANIFEST)}
    argv = ["kubectl", "apply", "--filename", "/manifests/deploy.yaml", "-n", "web"]
    spy = StagingCapturingExecutor()
    with decision(_mk_decision(tuple(argv), family="kubectl")):
        out = await run_command_core(
            argv, 30, make_cfg(), tool_call_id="call_1", executor=spy, files=files
        )
    assert spy.called
    # executor received a REAL temp path, not the virtual path.
    assert spy.staged_path is not None
    assert spy.staged_path != "/manifests/deploy.yaml"
    assert "opendevops-stage-" in spy.staged_path
    assert spy.existed_at_exec is True
    assert spy.staged_content == _MANIFEST  # content round-trips
    # the rest of argv is preserved.
    assert spy.argv is not None
    assert spy.argv[:3] == ["kubectl", "apply", "--filename"]
    assert spy.argv[4:] == ["-n", "web"]
    # EXEC_META carries staged_files with the right virtual path + content sha.
    meta = _exec_meta(out)
    assert meta is not None
    assert meta["staged_files"] == [
        {
            "path": "/manifests/deploy.yaml",
            "sha256": hashlib.sha256(_MANIFEST.encode("utf-8")).hexdigest(),
        }
    ]
    # the tmpdir is cleaned up after the call (the staged path no longer exists).
    assert not Path(spy.staged_path).exists()


async def test_staging_missing_file_refuses_without_exec(
    make_cfg: Callable[..., AppConfig],
) -> None:
    argv = ["kubectl", "apply", "-f", "/manifests/missing.yaml"]
    spy = SpyExecutor()
    with decision(_mk_decision(tuple(argv), family="kubectl")):
        out = await run_command_core(
            argv, 30, make_cfg(), tool_call_id="call_1", executor=spy, files={}
        )
    assert isinstance(out, str)
    assert out.startswith("staging refused")
    assert "/manifests/missing.yaml" in out
    assert not spy.called
    assert _exec_meta(out) is None  # no exec-meta on a staging refusal


async def test_staging_kustomize_refused(make_cfg: Callable[..., AppConfig]) -> None:
    argv = ["kubectl", "apply", "-k", "/overlays/prod"]
    spy = SpyExecutor()
    with decision(_mk_decision(tuple(argv), family="kubectl")):
        out = await run_command_core(
            argv, 30, make_cfg(), tool_call_id="call_1", executor=spy, files={}
        )
    assert isinstance(out, str)
    assert out.startswith("staging refused")
    assert "kustomize" in out.lower()
    assert not spy.called


async def test_no_file_flags_no_staging_meta_empty(
    make_cfg: Callable[..., AppConfig],
) -> None:
    argv = ["kubectl", "get", "pods", "-n", "web"]
    spy = SpyExecutor()
    with decision(_mk_decision(tuple(argv), family="kubectl")):
        out = await run_command_core(
            argv, 30, make_cfg(), tool_call_id="call_1", executor=spy, files={}
        )
    assert spy.called
    meta = _exec_meta(out)
    assert meta is not None
    assert meta["staged_files"] == []


class RaisingExecutor:
    """Raises during execute() to prove the staging tmpdir is cleaned up on an exec exception."""

    home = "/tmp/raising-spy-home"

    def __init__(self) -> None:
        self.staged_path: str | None = None

    async def execute(
        self, argv: list[str], timeout_s: int, env: dict[str, str]
    ) -> ExecResult:
        idx = argv.index("--filename")
        self.staged_path = argv[idx + 1]
        assert Path(self.staged_path).exists()  # staged before we blow up
        raise RuntimeError("boom during exec")


async def test_staging_tmpdir_cleaned_on_executor_exception(
    make_cfg: Callable[..., AppConfig],
) -> None:
    files = {"/manifests/deploy.yaml": create_file_data(_MANIFEST)}
    argv = ["kubectl", "apply", "--filename", "/manifests/deploy.yaml"]
    ex = RaisingExecutor()
    with decision(_mk_decision(tuple(argv), family="kubectl")), pytest.raises(RuntimeError):
        await run_command_core(
            argv, 30, make_cfg(), tool_call_id="call_1", executor=ex, files=files
        )
    # even though execute() raised, the staging_tmpdir finally rmtree'd the dir.
    assert ex.staged_path is not None
    assert not Path(ex.staged_path).exists()


# --------------------------------------------------------------------------------------
# credential families: helm (kube creds) + gh (GH_TOKEN from operator env var)
# --------------------------------------------------------------------------------------


def test_build_env_helm_ro_gets_kubeconfig(make_cfg: Callable[..., AppConfig]) -> None:
    cfg = make_cfg(kubeconfig_ro="/tmp/fake-ro.yaml")
    env = build_env(cfg, "helm", "ro", _SANDBOX_HOME)
    assert env["KUBECONFIG"] == "/tmp/fake-ro.yaml"
    assert "GH_TOKEN" not in env


def test_build_env_helm_rw_gets_rw_kubeconfig(make_cfg: Callable[..., AppConfig]) -> None:
    cfg = make_cfg(kubeconfig_rw="/tmp/fake-rw.yaml")
    env = build_env(cfg, "helm", "rw", _SANDBOX_HOME)
    assert env["KUBECONFIG"] == "/tmp/fake-rw.yaml"


def test_build_env_helm_rw_missing_raises(make_cfg: Callable[..., AppConfig]) -> None:
    with pytest.raises(CredentialUnavailable):
        build_env(make_cfg(), "helm", "rw", _SANDBOX_HOME)


def test_build_env_gh_token_present(
    make_cfg: Callable[..., AppConfig], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OPENDEVOPS_GH_TOKEN", "ghp_secret_value_must_not_leak_anywhere")
    cfg = make_cfg(github_token_env="OPENDEVOPS_GH_TOKEN")
    env = build_env(cfg, "gh", "ro", _SANDBOX_HOME)
    assert env["GH_TOKEN"] == "ghp_secret_value_must_not_leak_anywhere"
    # gh still gets the fail-closed kube sentinel, never a real kubeconfig.
    assert env["KUBECONFIG"] == "/dev/null"
    assert set(env) == _EXPECTED_BASE_KEYS | {"KUBECONFIG", "GH_TOKEN"}
    assert "GH_HOST" not in env
    assert "GH_ENTERPRISE_TOKEN" not in env


def test_build_env_gh_token_env_unset_raises(
    make_cfg: Callable[..., AppConfig], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("OPENDEVOPS_GH_TOKEN", raising=False)
    cfg = make_cfg(github_token_env="OPENDEVOPS_GH_TOKEN")
    with pytest.raises(CredentialUnavailable) as exc:
        build_env(cfg, "gh", "ro", _SANDBOX_HOME)
    # the message names the VARIABLE, never a token value.
    assert "OPENDEVOPS_GH_TOKEN" in str(exc.value)


def test_build_env_gh_token_env_empty_raises(
    make_cfg: Callable[..., AppConfig], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OPENDEVOPS_GH_TOKEN", "")
    cfg = make_cfg(github_token_env="OPENDEVOPS_GH_TOKEN")
    with pytest.raises(CredentialUnavailable):
        build_env(cfg, "gh", "ro", _SANDBOX_HOME)


def test_build_env_gh_token_env_not_configured_raises(
    make_cfg: Callable[..., AppConfig],
) -> None:
    # default cfg: targets.github.token_env is None -> gh family always refuses.
    with pytest.raises(CredentialUnavailable):
        build_env(make_cfg(), "gh", "ro", _SANDBOX_HOME)


async def test_gh_family_missing_token_refuses_via_core(
    make_cfg: Callable[..., AppConfig], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("OPENDEVOPS_GH_TOKEN", raising=False)
    argv = ["gh", "pr", "list"]
    spy = SpyExecutor()
    cfg = make_cfg(github_token_env="OPENDEVOPS_GH_TOKEN")
    with decision(_mk_decision(tuple(argv), family="gh")):
        out = await run_command_core(
            argv, 30, cfg, tool_call_id="call_1", executor=spy, files={}
        )
    assert isinstance(out, str)
    assert out.startswith("execution refused")
    assert not spy.called


async def test_gh_family_child_env_has_token(
    make_cfg: Callable[..., AppConfig], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A real subprocess for the gh family sees GH_TOKEN + KUBECONFIG=/dev/null, nothing else."""
    monkeypatch.setenv("OPENDEVOPS_GH_TOKEN", "ghp_child_env_token_value")
    cfg = make_cfg(github_token_env="OPENDEVOPS_GH_TOKEN")
    ex = LocalExecutor()
    env = build_env(cfg, "gh", "ro", ex.home)
    res = await ex.execute(
        ["python3", "-c", "import os,json;print(json.dumps(dict(os.environ)))"], 10, env
    )
    child_env = json.loads(res.output)
    assert child_env["GH_TOKEN"] == "ghp_child_env_token_value"
    assert child_env["KUBECONFIG"] == "/dev/null"


# --------------------------------------------------------------------------------------
# gh WRITE channel: rw -> rw PAT, ro -> ro PAT, never both, missing rw -> refuse
# --------------------------------------------------------------------------------------


def test_build_env_gh_rw_uses_rw_token(
    make_cfg: Callable[..., AppConfig], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OPENDEVOPS_GH_TOKEN", "ro_pat_must_not_be_used_on_rw")
    monkeypatch.setenv("OPENDEVOPS_GH_TOKEN_RW", "rw_pat_the_only_one_injected")
    cfg = make_cfg(
        github_token_env="OPENDEVOPS_GH_TOKEN",
        github_token_env_rw="OPENDEVOPS_GH_TOKEN_RW",
    )
    env = build_env(cfg, "gh", "rw", _SANDBOX_HOME)
    # rw channel injects the WRITE PAT, never the read PAT — and exactly one GH_TOKEN key.
    assert env["GH_TOKEN"] == "rw_pat_the_only_one_injected"
    assert env["KUBECONFIG"] == "/dev/null"
    assert set(env) == _EXPECTED_BASE_KEYS | {"KUBECONFIG", "GH_TOKEN"}


def test_build_env_gh_ro_uses_ro_token_when_both_configured(
    make_cfg: Callable[..., AppConfig], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OPENDEVOPS_GH_TOKEN", "ro_pat_for_the_ro_channel")
    monkeypatch.setenv("OPENDEVOPS_GH_TOKEN_RW", "rw_pat_must_not_leak_to_ro")
    cfg = make_cfg(
        github_token_env="OPENDEVOPS_GH_TOKEN",
        github_token_env_rw="OPENDEVOPS_GH_TOKEN_RW",
    )
    env = build_env(cfg, "gh", "ro", _SANDBOX_HOME)
    assert env["GH_TOKEN"] == "ro_pat_for_the_ro_channel"


def test_build_env_gh_rw_missing_token_raises(
    make_cfg: Callable[..., AppConfig], monkeypatch: pytest.MonkeyPatch
) -> None:
    # ro token configured but no rw token: a rw gh decision must fail closed (not fall back to ro).
    monkeypatch.setenv("OPENDEVOPS_GH_TOKEN", "ro_pat_present")
    cfg = make_cfg(github_token_env="OPENDEVOPS_GH_TOKEN")
    with pytest.raises(CredentialUnavailable) as exc:
        build_env(cfg, "gh", "rw", _SANDBOX_HOME)
    assert "token_env_rw" in str(exc.value)


def test_build_env_gh_rw_token_env_unset_raises(
    make_cfg: Callable[..., AppConfig], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("OPENDEVOPS_GH_TOKEN_RW", raising=False)
    cfg = make_cfg(github_token_env_rw="OPENDEVOPS_GH_TOKEN_RW")
    with pytest.raises(CredentialUnavailable) as exc:
        build_env(cfg, "gh", "rw", _SANDBOX_HOME)
    # names the VARIABLE, never a token value.
    assert "OPENDEVOPS_GH_TOKEN_RW" in str(exc.value)


async def test_gh_rw_missing_token_refuses_via_core(
    make_cfg: Callable[..., AppConfig], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("OPENDEVOPS_GH_TOKEN_RW", raising=False)
    argv = ["gh", "pr", "create", "--title", "fix"]
    spy = SpyExecutor()
    cfg = make_cfg(github_token_env="OPENDEVOPS_GH_TOKEN")
    with decision(_mk_decision(tuple(argv), channel="rw", family="gh")):
        out = await run_command_core(
            argv, 30, cfg, tool_call_id="call_1", executor=spy, files={}
        )
    assert isinstance(out, str)
    assert out.startswith("execution refused")
    assert not spy.called


async def test_gh_rw_input_staging_records_staged_file(
    make_cfg: Callable[..., AppConfig], monkeypatch: pytest.MonkeyPatch
) -> None:
    """`gh api ... --input <virtual-fs>` on rw materializes + records the staged_files sha."""
    monkeypatch.setenv("OPENDEVOPS_GH_TOKEN_RW", "rw_pat_value")
    body = '{"title":"fix","head":"patch","base":"main"}\n'
    body_sha = hashlib.sha256(body.encode("utf-8")).hexdigest()
    files = {"/manifests/pr.json": create_file_data(body)}
    argv = [
        "gh", "api", "-X", "POST", "/repos/octo-org/staging-app/pulls",
        "--input", "/manifests/pr.json",
    ]
    spy = SpyExecutor()
    cfg = make_cfg(github_token_env_rw="OPENDEVOPS_GH_TOKEN_RW")
    with decision(_mk_decision(tuple(argv), channel="rw", family="gh")):
        out = await run_command_core(
            argv, 30, cfg, tool_call_id="call_1", executor=spy, files=files
        )
    assert spy.called
    meta = _exec_meta(out)
    assert meta is not None
    assert meta["staged_files"] == [{"path": "/manifests/pr.json", "sha256": body_sha}]


async def test_gh_rw_input_stdin_refused_via_core(
    make_cfg: Callable[..., AppConfig], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A non-file `--input -` (stdin) operand refuses fail-closed with no execution."""
    monkeypatch.setenv("OPENDEVOPS_GH_TOKEN_RW", "rw_pat_value")
    argv = [
        "gh", "api", "-X", "POST", "/repos/octo-org/staging-app/pulls", "--input", "-",
    ]
    spy = SpyExecutor()
    cfg = make_cfg(github_token_env_rw="OPENDEVOPS_GH_TOKEN_RW")
    with decision(_mk_decision(tuple(argv), channel="rw", family="gh")):
        out = await run_command_core(
            argv, 30, cfg, tool_call_id="call_1", executor=spy, files={}
        )
    assert isinstance(out, str)
    assert out.startswith("staging refused")
    assert not spy.called


# --------------------------------------------------------------------------------------
# credential families: cloud (aws / gcloud / az) — env-var-name credential map
# --------------------------------------------------------------------------------------


def test_build_env_aws_injects_only_its_vars(
    make_cfg: Callable[..., AppConfig], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIA_do_not_leak")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret_do_not_leak")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    cfg = make_cfg(
        aws_credential_env=["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION"]
    )
    env = build_env(cfg, "aws", "ro", _SANDBOX_HOME)
    assert env["AWS_ACCESS_KEY_ID"] == "AKIA_do_not_leak"
    assert env["AWS_SECRET_ACCESS_KEY"] == "secret_do_not_leak"
    assert env["AWS_REGION"] == "us-east-1"
    # cloud families still get the fail-closed kube sentinel and never a gh token.
    assert env["KUBECONFIG"] == "/dev/null"
    assert "GH_TOKEN" not in env
    assert set(env) == _EXPECTED_BASE_KEYS | {
        "KUBECONFIG",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_REGION",
    }


def test_build_env_gcloud_injects_only_its_vars(
    make_cfg: Callable[..., AppConfig], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/run/secrets/gcp-sa.json")
    cfg = make_cfg(gcloud_credential_env=["GOOGLE_APPLICATION_CREDENTIALS"])
    env = build_env(cfg, "gcloud", "ro", _SANDBOX_HOME)
    assert env["GOOGLE_APPLICATION_CREDENTIALS"] == "/run/secrets/gcp-sa.json"
    assert env["KUBECONFIG"] == "/dev/null"
    assert set(env) == _EXPECTED_BASE_KEYS | {"KUBECONFIG", "GOOGLE_APPLICATION_CREDENTIALS"}


def test_build_env_az_reads_azure_target(
    make_cfg: Callable[..., AppConfig], monkeypatch: pytest.MonkeyPatch
) -> None:
    # family "az" resolves its credential from the config target spelled "azure".
    monkeypatch.setenv("AZURE_CLIENT_ID", "client-id")
    monkeypatch.setenv("AZURE_TENANT_ID", "tenant-id")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "sp-secret-do-not-leak")
    cfg = make_cfg(
        azure_credential_env=["AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_CLIENT_SECRET"]
    )
    env = build_env(cfg, "az", "ro", _SANDBOX_HOME)
    assert env["AZURE_CLIENT_ID"] == "client-id"
    assert env["AZURE_TENANT_ID"] == "tenant-id"
    assert env["AZURE_CLIENT_SECRET"] == "sp-secret-do-not-leak"
    assert env["KUBECONFIG"] == "/dev/null"


def test_build_env_cloud_no_cross_family_leakage(
    make_cfg: Callable[..., AppConfig], monkeypatch: pytest.MonkeyPatch
) -> None:
    """An aws exec must never see gcloud/az/gh credentials, and vice versa."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "aws-key")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws-secret")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/gcp.json")
    monkeypatch.setenv("AZURE_CLIENT_ID", "az-id")
    monkeypatch.setenv("OPENDEVOPS_GH_TOKEN", "ghp_token")
    cfg = make_cfg(
        github_token_env="OPENDEVOPS_GH_TOKEN",
        aws_credential_env=["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"],
        gcloud_credential_env=["GOOGLE_APPLICATION_CREDENTIALS"],
        azure_credential_env=["AZURE_CLIENT_ID"],
    )
    aws_env = build_env(cfg, "aws", "ro", _SANDBOX_HOME)
    assert "GOOGLE_APPLICATION_CREDENTIALS" not in aws_env
    assert "AZURE_CLIENT_ID" not in aws_env
    assert "GH_TOKEN" not in aws_env
    gcloud_env = build_env(cfg, "gcloud", "ro", _SANDBOX_HOME)
    assert "AWS_ACCESS_KEY_ID" not in gcloud_env
    assert "AZURE_CLIENT_ID" not in gcloud_env
    # a kube exec never sees any cloud credential either.
    kube_env = build_env(make_cfg(kubeconfig_ro="/tmp/ro.yaml"), "kubectl", "ro", _SANDBOX_HOME)
    assert "AWS_ACCESS_KEY_ID" not in kube_env
    assert "GOOGLE_APPLICATION_CREDENTIALS" not in kube_env


def test_build_env_aws_unconfigured_raises(make_cfg: Callable[..., AppConfig]) -> None:
    # default cfg: targets.aws.credential_env is [] -> the aws family always refuses.
    with pytest.raises(CredentialUnavailable) as exc:
        build_env(make_cfg(), "aws", "ro", _SANDBOX_HOME)
    assert "aws" in str(exc.value)


def test_build_env_cloud_missing_var_raises(
    make_cfg: Callable[..., AppConfig], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "present")
    cfg = make_cfg(aws_credential_env=["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"])
    with pytest.raises(CredentialUnavailable) as exc:
        build_env(cfg, "aws", "ro", _SANDBOX_HOME)
    # the message names the missing VARIABLE, never a credential value.
    assert "AWS_SECRET_ACCESS_KEY" in str(exc.value)
    assert "present" not in str(exc.value)


def test_build_env_cloud_empty_var_raises(
    make_cfg: Callable[..., AppConfig], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AZURE_CLIENT_ID", "")
    cfg = make_cfg(azure_credential_env=["AZURE_CLIENT_ID"])
    with pytest.raises(CredentialUnavailable):
        build_env(cfg, "az", "ro", _SANDBOX_HOME)


async def test_aws_family_child_env_has_only_its_creds(
    make_cfg: Callable[..., AppConfig], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A real subprocess for the aws family sees only its AWS_* vars + KUBECONFIG=/dev/null."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIA_child")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "child-secret")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/should-not-appear.json")
    cfg = make_cfg(
        aws_credential_env=["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"],
        gcloud_credential_env=["GOOGLE_APPLICATION_CREDENTIALS"],
    )
    ex = LocalExecutor()
    env = build_env(cfg, "aws", "ro", ex.home)
    res = await ex.execute(
        ["python3", "-c", "import os,json;print(json.dumps(dict(os.environ)))"], 10, env
    )
    child_env = json.loads(res.output)
    assert child_env["AWS_ACCESS_KEY_ID"] == "AKIA_child"
    assert child_env["AWS_SECRET_ACCESS_KEY"] == "child-secret"
    assert child_env["KUBECONFIG"] == "/dev/null"
    assert "GOOGLE_APPLICATION_CREDENTIALS" not in child_env


async def test_cloud_family_missing_cred_refuses_via_core(
    make_cfg: Callable[..., AppConfig], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    argv = ["aws", "sts", "get-caller-identity"]
    spy = SpyExecutor()
    cfg = make_cfg(aws_credential_env=["AWS_ACCESS_KEY_ID"])
    with decision(_mk_decision(tuple(argv), family="aws")):
        out = await run_command_core(
            argv, 30, cfg, tool_call_id="call_1", executor=spy, files={}
        )
    assert isinstance(out, str)
    assert out.startswith("execution refused")
    assert not spy.called


async def test_staging_runs_in_real_graph_with_prior_write_file(
    make_cfg: Callable[..., AppConfig],
) -> None:
    """A virtual file written by write_file is staged for a later run_command apply -f call.

    Middleware is not wired here, so the exec-meta (with staged shas) is observable directly on the
    run_command ToolMessage's additional_kwargs. kubectl need not be installed — even a 127 exec
    still records the staged manifest facts (staging happens before exec).
    """
    from deepagents import create_deep_agent
    from deepagents.backends import StateBackend
    from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
    from langchain_core.messages import AIMessage

    cfg = make_cfg()
    tool = make_run_command(cfg)
    manifest = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: web\n"
    manifest_path = "/manifests/cm.yaml"
    apply_argv = ["kubectl", "apply", "-f", manifest_path]

    class BindableFake(GenericFakeChatModel):  # type: ignore[misc]
        def bind_tools(self, tools: Any, **kwargs: Any) -> Any:
            return self

    model = BindableFake(
        messages=iter(
            [
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "write_file",
                            "args": {"file_path": manifest_path, "content": manifest},
                            "id": "call_write",
                        }
                    ],
                ),
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "run_command",
                            "args": {"argv": apply_argv, "timeout_s": 10},
                            "id": "call_apply",
                        }
                    ],
                ),
                AIMessage(content="done"),
            ]
        )
    )
    agent = create_deep_agent(model=model, tools=[tool], backend=StateBackend())
    with decision(_mk_decision(tuple(apply_argv), tool_call_id="call_apply", family="kubectl")):
        out = await agent.ainvoke({"messages": [("user", "go")]})

    # the manifest landed in the virtual FS.
    assert manifest_path in out["files"]

    runs = [
        m
        for m in out["messages"]
        if isinstance(m, ToolMessage) and m.tool_call_id == "call_apply"
    ]
    assert runs
    run_msg = runs[0]
    assert run_msg.content.splitlines()[0].startswith("exit_code:")
    meta = run_msg.additional_kwargs.get(EXEC_META_KEY)
    assert meta is not None
    assert meta["staged_files"] == [
        {
            "path": manifest_path,
            "sha256": hashlib.sha256(manifest.encode("utf-8")).hexdigest(),
        }
    ]
