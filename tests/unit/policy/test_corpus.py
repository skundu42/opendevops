"""CI-blocking bypass corpus (T4): the shipped policy must deny every known bypass.

This loads the *real* ``config/policy/`` dir and drives it through :class:`YamlRuleEngine`.
Each deny case asserts BOTH the effect AND the exact ``rule_id`` — a rule id drifting is as
much a regression as an effect flipping. Positive cases assert the read-only allow. If a new
bypass is discovered, add its argv here first (red), then tighten policy until it denies.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from opendevops.policy.engine import RULE_BUILTIN_FS, YamlRuleEngine
from opendevops.policy.loader import load_policy
from opendevops.policy.schema import Decision, ToolCallCtx

REPO_ROOT = Path(__file__).resolve().parents[3]
SHIPPED_POLICY_DIR = REPO_ROOT / "config" / "policy"

# The resolver the shipped policy expects: allowed_contexts -> a single kind cluster.
ALLOWED_CONTEXTS = ["kind-opendevops"]


def _resolver(ref: str) -> list[str]:
    if ref == "${targets.kubernetes.allowed_contexts}":
        return ALLOWED_CONTEXTS
    if ref == "${targets.ssh.hosts}":  # P5b ssh_run host allowlist ref
        return ["allowed.host.internal"]
    if ref == "${targets.github.write_repos}":  # P5f gh-write repo allowlist ref
        return ["octo-org/staging-app"]
    raise AssertionError(f"unexpected config ref {ref!r}")


@pytest.fixture(scope="module")
def engine() -> YamlRuleEngine:
    return YamlRuleEngine(load_policy(SHIPPED_POLICY_DIR), _resolver)


def _cmd(argv: object, environment: str = "staging") -> ToolCallCtx:
    return ToolCallCtx(
        tool_name="run_command",
        args={"argv": argv},
        environment=environment,
        principal="tester",
        run_id="run-corpus",
    )


def _tool(tool_name: str, environment: str = "staging") -> ToolCallCtx:
    return ToolCallCtx(
        tool_name=tool_name,
        args={},
        environment=environment,
        principal="tester",
        run_id="run-corpus",
    )


def _task(args: dict[str, object], environment: str = "staging") -> ToolCallCtx:
    """A deepagents ``task`` (subagent-spawner) call with the given args (P5c)."""
    return ToolCallCtx(
        tool_name="task",
        args=args,
        environment=environment,
        principal="tester",
        run_id="run-corpus",
    )


# --------------------------------------------------------------------------- deny corpus

# (argv, expected_rule_id)
INTERPRETERS = [
    ["bash", "-c", "kubectl get pods"],
    ["sh"],
    ["python3", "-c", "..."],
    ["awk", 'BEGIN{system("id")}'],
    ["sed", "-e", "1e id"],
    ["find", ".", "-exec", "rm", "{}", ";"],
    ["xargs", "rm"],
    ["env", "KUBECONFIG=/x", "kubectl", "get", "pods"],
    ["curl", "http://x"],
    ["ssh", "host"],
    ["sudo", "kubectl", "get", "pods"],
]

CRED_OVERRIDE_KUBECTL = [
    ["kubectl", "--kubeconfig", "/x", "get", "pods"],
    ["kubectl", "--token", "abc", "get", "pods"],
    ["kubectl", "-s", "https://attacker.example", "get", "pods"],
    ["kubectl", "--server=https://attacker.example", "get", "pods"],
    ["kubectl", "--as", "admin", "get", "pods"],
]

SECRET_READS = [
    ["kubectl", "get", "secrets"],
    ["kubectl", "get", "secret/foo"],
    ["kubectl", "describe", "secret", "foo"],
    ["kubectl", "get", "po,secrets"],
]

DEFAULT_DENY = [
    ["rm", "-rf", "/"],
    ["unknownbinary", "x"],
]

FAIL_CLOSED = [
    [],
    ["kubectl", 123],  # non-string element
    ["kubectl", "-Z", "get", "pods"],  # unparseable (unknown short flag) on a known binary
]

POSITIVE = [
    ["kubectl", "get", "pods", "-n", "web"],
    ["kubectl", "describe", "pod", "api-0", "--namespace", "web"],
    ["kubectl", "logs", "api-0", "--previous", "--tail", "200"],
    ["kubectl", "get", "pods", "--context", "kind-opendevops"],
    ["kubectl", "auth", "can-i", "get", "pods"],
    ["kubectl", "top", "pods"],
    ["kubectl", "events", "-n", "web"],
]


async def _decide(engine: YamlRuleEngine, ctx: ToolCallCtx) -> Decision:
    return await engine.decide(ctx)


@pytest.mark.parametrize("argv", INTERPRETERS)
async def test_interpreters_hard_deny(engine: YamlRuleEngine, argv: list[object]) -> None:
    d = await _decide(engine, _cmd(argv))
    assert d.effect == "deny"
    assert d.rule_id == "interpreters-hard-deny"


@pytest.mark.parametrize("argv", CRED_OVERRIDE_KUBECTL)
async def test_kubectl_no_cred_override(engine: YamlRuleEngine, argv: list[object]) -> None:
    d = await _decide(engine, _cmd(argv))
    assert d.effect == "deny"
    assert d.rule_id == "kubectl-no-cred-override"


async def test_helm_no_cred_override(engine: YamlRuleEngine) -> None:
    d = await _decide(engine, _cmd(["helm", "--kubeconfig", "/x", "list"]))
    assert d.effect == "deny"
    assert d.rule_id == "helm-no-cred-override"


async def test_gh_no_host_override(engine: YamlRuleEngine) -> None:
    d = await _decide(engine, _cmd(["gh", "--hostname", "evil.example", "pr", "list"]))
    assert d.effect == "deny"
    assert d.rule_id == "gh-no-host-override"


@pytest.mark.parametrize("argv", SECRET_READS)
async def test_no_secret_reads(engine: YamlRuleEngine, argv: list[object]) -> None:
    d = await _decide(engine, _cmd(argv))
    assert d.effect == "deny"
    assert d.rule_id == "no-secret-reads"


async def test_context_not_in_allowlist(engine: YamlRuleEngine) -> None:
    d = await _decide(engine, _cmd(["kubectl", "--context", "prod-real", "get", "pods"]))
    assert d.effect == "deny"
    assert d.rule_id == "kubectl-context-allowlist"


async def test_flag_not_allowed(engine: YamlRuleEngine) -> None:
    # --watch is an allowed verb (get) but a flag deliberately outside flags_allowed.
    d = await _decide(engine, _cmd(["kubectl", "get", "pods", "--watch"]))
    assert d.effect == "deny"
    assert d.rule_id == "__flag_not_allowed__"
    assert "--watch" in d.reason


async def test_log_summarizer_subagent_allowed(engine: YamlRuleEngine) -> None:
    """P5c: the one named subagent is permitted at the engine level (``__subagent_allowed__``)."""
    d = await _decide(
        engine, _task({"description": "digest these logs", "subagent_type": "log-summarizer"})
    )
    assert d.effect == "allow"
    assert d.rule_id == "__subagent_allowed__"


@pytest.mark.parametrize(
    "args",
    [
        {"description": "d", "subagent_type": "general-purpose"},  # a different named subagent
        {"description": "d", "subagent_type": "log-summarizer-evil"},  # near-miss name
        {"description": "d", "subagent_type": ""},  # empty
        {"description": "d"},  # MISSING subagent_type -> fail-closed
        {"description": "d", "subagent_type": 123},  # non-string -> fail-closed
    ],
)
async def test_arbitrary_subagent_denied(engine: YamlRuleEngine, args: dict[str, object]) -> None:
    """P5c: any subagent_type other than the log-summarizer — incl. absent/malformed — is denied."""
    d = await _decide(engine, _task(args))
    assert d.effect == "deny"
    assert d.rule_id == "no-arbitrary-subagents"


async def test_compact_conversation_denied(engine: YamlRuleEngine) -> None:
    """P5c: manual conversation compaction stays hard-denied (fail-closed, its own rule)."""
    d = await _decide(engine, _tool("compact_conversation"))
    assert d.effect == "deny"
    assert d.rule_id == "no-compaction-tool"


async def test_no_builtin_shell_execute(engine: YamlRuleEngine) -> None:
    d = await _decide(engine, _tool("execute"))
    assert d.effect == "deny"
    assert d.rule_id == "no-builtin-shell-execute"


@pytest.mark.parametrize("argv", DEFAULT_DENY)
async def test_default_deny(engine: YamlRuleEngine, argv: list[object]) -> None:
    d = await _decide(engine, _cmd(argv))
    assert d.effect == "deny"
    assert d.rule_id == "__default_deny__"


@pytest.mark.parametrize("argv", FAIL_CLOSED)
async def test_fail_closed(engine: YamlRuleEngine, argv: list[object]) -> None:
    d = await _decide(engine, _cmd(argv))
    assert d.effect == "deny"
    assert d.rule_id == "__fail_closed__"


@pytest.mark.parametrize("argv", POSITIVE)
async def test_positive_read_verbs(engine: YamlRuleEngine, argv: list[object]) -> None:
    d = await _decide(engine, _cmd(argv))
    assert d.effect == "allow"
    assert d.channel == "ro"
    assert d.rule_id == "kubectl-read-verbs"


@pytest.mark.parametrize("tool_name", ["read_file", "grep", "write_todos"])
async def test_builtin_fs_allowed(engine: YamlRuleEngine, tool_name: str) -> None:
    d = await _decide(engine, _tool(tool_name))
    assert d.effect == "allow"
    assert d.rule_id == RULE_BUILTIN_FS
    assert d.channel is None
