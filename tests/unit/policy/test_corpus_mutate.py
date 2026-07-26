"""Mutation corpus: staging mutations (kubectl apply/rollout/scale), helm read, gh read.

Same contract as ``test_corpus.py``: the *real* ``config/policy/`` dir is driven through
:class:`YamlRuleEngine`, and every case asserts BOTH the effect AND the exact ``rule_id``.
Environment matters here — the staging-only mutate allows must fall through to
``__default_deny__`` in prod.

Two engine behaviors these cases additionally pin:
  * case-fold: the engine lowercases its pre-parse ``argv0``, so a mixed-case
    interpreter/binary hits its real rule id instead of ``__default_deny__``.
  * first_positional: ``Match.first_positional`` is enforced, so a mutating gh
    sub-subcommand (``gh pr merge``) does not match a read rule on ``verb`` alone.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from opendevops.policy.engine import YamlRuleEngine
from opendevops.policy.loader import load_policy
from opendevops.policy.schema import Decision, ToolCallCtx

REPO_ROOT = Path(__file__).resolve().parents[3]
SHIPPED_POLICY_DIR = REPO_ROOT / "config" / "policy"

ALLOWED_CONTEXTS = ["kind-opendevops"]


def _resolver(ref: str) -> list[str]:
    if ref == "${targets.kubernetes.allowed_contexts}":
        return ALLOWED_CONTEXTS
    if ref == "${targets.ssh.hosts}":  # ssh_run host allowlist ref
        return ["allowed.host.internal"]
    if ref == "${targets.github.write_repos}":  # gh-write repo allowlist ref
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
        run_id="run-corpus-p2",
    )


async def _decide(engine: YamlRuleEngine, ctx: ToolCallCtx) -> Decision:
    return await engine.decide(ctx)


# --------------------------------------------------------------------------- staging allows

# (argv, expected_rule_id, expected_channel)
STAGING_ALLOWS = [
    # Dry-run enforcement: a BARE apply is rewritten to --dry-run=server (see
    # test_dry_run_enforcement.py), so the plain-allow case carries an explicit server dry-run.
    (
        ["kubectl", "apply", "--dry-run=server", "--filename", "/manifests/x.yaml", "-n", "web"],
        "kubectl-apply",
        "rw",
    ),
    (["kubectl", "rollout", "undo", "deployment/api", "-n", "web"], "kubectl-rollout", "rw"),
    (["kubectl", "scale", "--replicas", "3", "deployment/api", "-n", "web"], "kubectl-scale", "rw"),
    (["helm", "list", "-n", "web"], "helm-read-verbs", "ro"),
    (["helm", "get", "values", "x", "-n", "web"], "helm-read-verbs", "ro"),
    (["gh", "pr", "view", "123", "--repo", "org/x"], "gh-read-pr", "ro"),
    (["gh", "run", "view", "--log-failed", "12345"], "gh-read-run", "ro"),
]


@pytest.mark.parametrize(("argv", "rule_id", "channel"), STAGING_ALLOWS)
async def test_staging_allows(
    engine: YamlRuleEngine, argv: list[object], rule_id: str, channel: str
) -> None:
    d = await _decide(engine, _cmd(argv, "staging"))
    assert d.effect == "allow"
    assert d.rule_id == rule_id
    assert d.channel == channel


# --------------------------------------------------------------------------- prod: no mutate allows

# The staging-only mutate allows must not fire in prod — they fall through to default-deny.
PROD_MUTATE_DEFAULT_DENY = [
    ["kubectl", "apply", "--filename", "/manifests/x.yaml", "-n", "web"],
    ["kubectl", "rollout", "undo", "deployment/api", "-n", "web"],
    ["kubectl", "scale", "--replicas", "3", "deployment/api", "-n", "web"],
]


@pytest.mark.parametrize(
    ("argv", "effect"),
    [
        (PROD_MUTATE_DEFAULT_DENY[0], "rewrite"),
        (PROD_MUTATE_DEFAULT_DENY[1], "allow"),
        (PROD_MUTATE_DEFAULT_DENY[2], "allow"),
    ],
)
async def test_prod_mutations_reach_structural_policy_before_runtime_change_control(
    engine: YamlRuleEngine, argv: list[object], effect: str
) -> None:
    d = await _decide(engine, _cmd(argv, "prod"))
    assert d.effect == effect


# --------------------------------------------------------------------------- explicit denials


async def test_apply_force_denied(engine: YamlRuleEngine) -> None:
    d = await _decide(engine, _cmd(["kubectl", "apply", "--force", "-f", "/manifests/x.yaml"]))
    assert d.effect == "deny"
    assert d.rule_id == "kubectl-mutate-no-force"


async def test_delete_workload_escalates_in_staging(engine: YamlRuleEngine) -> None:
    # delete has no allow — the ONLY path is human approval (escalate) in staging. The
    # execution channel (rw) lives on the escalate rule; the middleware resolves it on approve.
    d = await _decide(engine, _cmd(["kubectl", "delete", "pod", "x"], "staging"))
    assert d.effect == "escalate"
    assert d.rule_id == "kubectl-delete-workload-escalate"


async def test_delete_escalates_in_prod_before_runtime_grant_gate(
    engine: YamlRuleEngine,
) -> None:
    d = await _decide(engine, _cmd(["kubectl", "delete", "pod", "x"], "prod"))
    assert d.effect == "escalate"
    assert d.rule_id == "kubectl-delete-workload-escalate"


async def test_delete_force_denied_in_staging(engine: YamlRuleEngine) -> None:
    # --force is caught by kubectl-mutate-no-force (deny > escalate), so it never escalates.
    d = await _decide(engine, _cmd(["kubectl", "delete", "pod", "x", "--force"], "staging"))
    assert d.effect == "deny"
    assert d.rule_id == "kubectl-mutate-no-force"


@pytest.mark.parametrize("environment", ["staging", "prod"])
async def test_gh_api_denied(engine: YamlRuleEngine, environment: str) -> None:
    d = await _decide(engine, _cmd(["gh", "api", "/repos/x"], environment))
    assert d.effect == "deny"
    assert d.rule_id == "gh-no-api"


async def test_gh_web_flag_not_allowed(engine: YamlRuleEngine) -> None:
    # --web is a read sub-subcommand (view) but the flag is dropped from gh flags_allowed.
    d = await _decide(engine, _cmd(["gh", "pr", "view", "--web"]))
    assert d.effect == "deny"
    assert d.rule_id == "__flag_not_allowed__"
    assert "--web" in d.reason


async def test_helm_install_default_deny(engine: YamlRuleEngine) -> None:
    d = await _decide(engine, _cmd(["helm", "install", "x", "chart"]))
    assert d.effect == "deny"
    assert d.rule_id == "__default_deny__"


# ---------------------------------------- engine-enforced (landed via controller integration)


async def test_gh_pr_merge_default_deny(engine: YamlRuleEngine) -> None:
    # `gh pr merge` is a mutation: verb=pr, first_positional=merge (not in the read set), so it
    # must default-deny. Until the engine reads first_positional it matches gh-read-pr on verb.
    d = await _decide(engine, _cmd(["gh", "pr", "merge", "123"]))
    assert d.effect == "deny"
    assert d.rule_id == "__default_deny__"


async def test_gh_run_watch_default_deny(engine: YamlRuleEngine) -> None:
    # `gh run watch` hangs a non-interactive run and is excluded from the read set.
    d = await _decide(engine, _cmd(["gh", "run", "watch", "123"]))
    assert d.effect == "deny"
    assert d.rule_id == "__default_deny__"


async def test_case_fold_bash_interpreter_deny(engine: YamlRuleEngine) -> None:
    d = await _decide(engine, _cmd(["BASH", "-c", "id"]))
    assert d.effect == "deny"
    assert d.rule_id == "interpreters-hard-deny"


async def test_case_fold_kubectl_secret_read_deny(engine: YamlRuleEngine) -> None:
    d = await _decide(engine, _cmd(["KUBECTL", "get", "secrets"]))
    assert d.effect == "deny"
    assert d.rule_id == "no-secret-reads"
