"""SSH corpus: the structured ssh_run(host, argv) tool over the shipped policy.

Same contract as ``test_corpus.py`` / ``test_corpus_cloud.py``: the REAL ``config/policy/`` dir is
driven through :class:`YamlRuleEngine`, asserting BOTH the effect AND the exact ``rule_id`` in
BOTH ``staging`` and ``prod``. ssh_run is matched by ``tool_name`` + the structured predicates
(host allowlist + the remote-command-PATH allowlist), distinct from the run_command argv0 pipeline
— which must stay unchanged.

These tests pin the pack's central hazard: a read-only ssh pack that pinned only ``argv[0]``
would authorize remote MUTATIONS (``systemctl restart/poweroff``, ``journalctl --vacuum-*``,
``hostname <name>``, ``ss -K``). The shipped design is a fail-CLOSED positive allowlist on the
remote command PATH (argv0 + read subcommand) for multi-mode binaries, an argv0 pin for the
vetted single-mode binaries, and a compensating DENY for journalctl's mutation flags. Every
exploit argv below MUST deny.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from opendevops.policy.engine import YamlRuleEngine
from opendevops.policy.loader import load_policy
from opendevops.policy.schema import Decision, ToolCallCtx

REPO_ROOT = Path(__file__).resolve().parents[3]
SHIPPED_POLICY_DIR = REPO_ROOT / "config" / "policy"

ALLOWED_HOST = "allowed.host.internal"
ALLOWED_CONTEXTS = ["kind-opendevops"]


def _resolver(ref: str) -> list[str]:
    if ref == "${targets.kubernetes.allowed_contexts}":
        return ALLOWED_CONTEXTS
    if ref == "${targets.ssh.hosts}":
        return [ALLOWED_HOST]
    if ref == "${targets.github.write_repos}":  # gh-write repo allowlist ref
        return ["octo-org/staging-app"]
    raise AssertionError(f"unexpected config ref {ref!r}")


@pytest.fixture(scope="module")
def engine() -> YamlRuleEngine:
    return YamlRuleEngine(load_policy(SHIPPED_POLICY_DIR), _resolver)


def _ssh(host: Any, argv: Any, environment: str = "staging") -> ToolCallCtx:
    return ToolCallCtx(
        tool_name="ssh_run",
        args={"host": host, "argv": argv},
        environment=environment,
        principal="tester",
        run_id="run-corpus-ssh",
    )


async def _decide(engine: YamlRuleEngine, ctx: ToolCallCtx) -> Decision:
    return await engine.decide(ctx)


# --------------------------------------------------------------------------------------
# ALLOW — multi-mode binaries pinned to their READ command PATH
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("environment", ["staging", "prod"])
@pytest.mark.parametrize(
    "argv",
    [
        ["systemctl", "status", "nginx"],
        ["systemctl", "show"],
        ["systemctl", "list-units"],
        ["journalctl", "-u", "nginx", "-n", "100"],
    ],
)
async def test_ssh_allow_multimode_read_paths(
    engine: YamlRuleEngine, argv: list[str], environment: str
) -> None:
    d = await _decide(engine, _ssh(ALLOWED_HOST, argv, environment))
    assert d.effect == "allow", argv
    assert d.rule_id == "ssh-run-read-commands-multimode", argv
    assert d.channel == "ro"


# --------------------------------------------------------------------------------------
# ALLOW — vetted pure-read single-mode binaries (argv0 pin)
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("environment", ["staging", "prod"])
@pytest.mark.parametrize(
    "argv",
    [
        ["df", "-h"],
        ["ps", "aux"],
        ["uptime"],
        ["lsblk"],
    ],
)
async def test_ssh_allow_singlemode_read_binaries(
    engine: YamlRuleEngine, argv: list[str], environment: str
) -> None:
    d = await _decide(engine, _ssh(ALLOWED_HOST, argv, environment))
    assert d.effect == "allow", argv
    assert d.rule_id == "ssh-run-read-commands-singlemode", argv
    assert d.channel == "ro"


# --------------------------------------------------------------------------------------
# DENY — the exact Critical exploits (every one MUST deny)
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("environment", ["staging", "prod"])
@pytest.mark.parametrize(
    "argv",
    [
        ["journalctl", "--vacuum-time=1s"],  # deletes journal logs (value form)
        ["journalctl", "--vacuum-time", "1s"],  # space form
        ["journalctl", "--vacuum-size=100M"],  # --vacuum-* family
        ["journalctl", "--rotate"],
        ["journalctl", "--flush"],
        ["journalctl", "--VACUUM-TIME=1s"],  # case-insensitive deny (not reliant on getopt)
        ["journalctl", "--Rotate"],
    ],
)
async def test_ssh_deny_journalctl_mutation_flags(
    engine: YamlRuleEngine, argv: list[str], environment: str
) -> None:
    """journalctl's mutating FLAGS are pinned out by the compensating deny (deny > allow)."""
    d = await _decide(engine, _ssh(ALLOWED_HOST, argv, environment))
    assert d.effect == "deny", argv
    assert d.rule_id == "ssh-run-no-remote-mutation-flags", argv


@pytest.mark.parametrize("environment", ["staging", "prod"])
@pytest.mark.parametrize(
    "argv",
    [
        ["systemctl", "restart", "nginx"],  # DoS: restarts a unit
        ["systemctl", "stop", "firewalld"],  # DoS: stops the firewall
        ["systemctl", "poweroff"],  # DoS: powers the host off
        ["systemctl", "reboot"],  # DoS: reboots the host
        ["systemctl", "mask", "sshd"],  # can lock out remote admin
        ["systemctl", "--user", "restart", "x"],  # flag-before-verb: matches no read path
        ["hostname", "evil"],  # SETS the hostname (dropped from allowlist)
        ["ss", "-K"],  # kills sockets (dropped from allowlist)
        ["frobnicate"],  # unknown argv0
    ],
)
async def test_ssh_deny_default_deny_mutations(
    engine: YamlRuleEngine, argv: list[str], environment: str
) -> None:
    """Mutating/unknown remote commands are simply absent from the allowlist -> default-deny."""
    d = await _decide(engine, _ssh(ALLOWED_HOST, argv, environment))
    assert d.effect == "deny", argv
    assert d.rule_id == "__default_deny__", argv


# --------------------------------------------------------------------------------------
# DENY — host predicate (unchanged)
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("environment", ["staging", "prod"])
async def test_ssh_deny_allowlisted_command_wrong_host(
    engine: YamlRuleEngine, environment: str
) -> None:
    """An allowlisted READ command to a NON-allowlisted host still denies (host predicate)."""
    d = await _decide(engine, _ssh("evil.example.com", ["systemctl", "status"], environment))
    assert d.effect == "deny"
    assert d.rule_id == "__default_deny__"


async def test_ssh_deny_host_not_allowlisted(engine: YamlRuleEngine) -> None:
    d = await _decide(engine, _ssh("evil.example.com", ["systemctl", "status"]))
    assert d.effect == "deny"
    assert d.rule_id == "__default_deny__"


async def test_ssh_deny_remote_argv0_not_allowlisted(engine: YamlRuleEngine) -> None:
    """A dangerous remote program (not in the read-command allowlist) default-denies."""
    for argv in (["rm", "-rf", "/"], ["bash", "-c", "id"], ["cat", "/etc/shadow"]):
        d = await _decide(engine, _ssh(ALLOWED_HOST, argv))
        assert d.effect == "deny", argv
        assert d.rule_id == "__default_deny__", argv


async def test_ssh_deny_missing_or_empty_host(engine: YamlRuleEngine) -> None:
    for host in ("", None):
        d = await _decide(engine, _ssh(host, ["systemctl", "status"]))
        assert d.effect == "deny"


async def test_ssh_deny_empty_argv(engine: YamlRuleEngine) -> None:
    d = await _decide(engine, _ssh(ALLOWED_HOST, []))
    assert d.effect == "deny"


async def test_ssh_deny_non_str_argv_element_fails_closed(engine: YamlRuleEngine) -> None:
    """A non-str argv element fails CLOSED on BOTH ssh predicates (single-mode + multimode).

    The engine guards every argv element is a str before an allow can fire, so a malformed argv
    default-denies rather than matching on argv[0] alone. (The tool boundary also rejects a non-str
    argv, but the engine must fail closed in isolation — no reliance on downstream containment.)
    """
    for argv in (["df", 3], ["systemctl", "status", 3]):
        d = await _decide(engine, _ssh(ALLOWED_HOST, argv))
        assert d.effect == "deny", argv
        assert d.rule_id == "__default_deny__", argv


async def test_ssh_unknown_tool_still_unknown(engine: YamlRuleEngine) -> None:
    """A truly-unregistered tool (no rule references it) stays __unknown_tool__, not default."""
    ctx = ToolCallCtx(
        tool_name="totally_unknown_tool",
        args={"host": ALLOWED_HOST, "argv": ["df"]},
        environment="staging",
        principal="tester",
        run_id="run-corpus-ssh",
    )
    d = await _decide(engine, ctx)
    assert d.effect == "deny"
    assert d.rule_id == "__unknown_tool__"


async def test_run_command_unaffected_by_ssh_pack(engine: YamlRuleEngine) -> None:
    """Regression: the run_command argv0 pipeline is untouched by the ssh pack."""
    allow = await _decide(
        engine,
        ToolCallCtx(
            tool_name="run_command",
            args={"argv": ["kubectl", "get", "pods"]},
            environment="staging",
            principal="tester",
            run_id="run-corpus-ssh",
        ),
    )
    assert allow.effect == "allow"
    assert allow.rule_id == "kubectl-read-verbs"

    # `ssh` as a run_command argv0 is still hard-denied (interpreters-hard-deny), NOT laundered
    # through the ssh_run predicates.
    deny = await _decide(
        engine,
        ToolCallCtx(
            tool_name="run_command",
            args={"argv": ["ssh", ALLOWED_HOST, "df"]},
            environment="staging",
            principal="tester",
            run_id="run-corpus-ssh",
        ),
    )
    assert deny.effect == "deny"
    assert deny.rule_id == "interpreters-hard-deny"
