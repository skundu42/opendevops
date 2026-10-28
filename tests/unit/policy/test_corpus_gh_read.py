"""Repository/release reads stay on ro; mutations and unsafe flags remain denied."""

from __future__ import annotations

from pathlib import Path

import pytest

from opendevops.policy.engine import YamlRuleEngine
from opendevops.policy.loader import load_policy
from opendevops.policy.schema import ToolCallCtx

SHIPPED_POLICY_DIR = Path(__file__).resolve().parents[3] / "config" / "policy"


def _resolver(ref: str) -> list[str]:
    values = {
        "${targets.kubernetes.allowed_contexts}": ["kind-opendevops"],
        "${targets.ssh.hosts}": ["allowed.host.internal"],
        "${targets.github.write_repos}": ["octo-org/staging-app"],
    }
    return values[ref]


@pytest.fixture(scope="module")
def engine() -> YamlRuleEngine:
    return YamlRuleEngine(load_policy(SHIPPED_POLICY_DIR), _resolver)


def _cmd(argv: list[str], environment: str) -> ToolCallCtx:
    return ToolCallCtx(
        tool_name="run_command",
        args={"argv": argv},
        environment=environment,
        principal="tester",
        run_id="run-corpus-gh-read",
    )


@pytest.mark.parametrize("environment", ["staging", "prod"])
@pytest.mark.parametrize(
    ("argv", "rule_id"),
    [
        (["gh", "repo", "view", "octo-org/staging-app"], "gh-read-repo"),
        (
            ["gh", "repo", "view", "octo-org/staging-app", "--branch", "main"],
            "gh-read-repo",
        ),
        (
            ["gh", "repo", "view", "octo-org/staging-app", "--json", "name", "--jq", ".name"],
            "gh-read-repo",
        ),
        (["gh", "repo", "list", "octo-org", "--limit", "10"], "gh-read-repo"),
        (["gh", "repo", "list", "octo-org", "-L", "10", "--json", "name"], "gh-read-repo"),
        (["gh", "release", "view", "--repo", "octo-org/staging-app"], "gh-read-release"),
        (
            ["gh", "release", "view", "v0.4.0", "--repo", "octo-org/staging-app"],
            "gh-read-release",
        ),
        (["gh", "release", "list", "-R", "octo-org/staging-app", "-L", "10"], "gh-read-release"),
        (
            ["gh", "--repo=octo-org/staging-app", "release", "list", "--json", "tagName"],
            "gh-read-release",
        ),
        # The write allowlist must not turn a read into a write or prevent token-scoped reads.
        (["gh", "release", "list", "--repo", "octo-org/other-app"], "gh-read-release"),
    ],
)
async def test_repository_and_release_reads(
    engine: YamlRuleEngine, environment: str, argv: list[str], rule_id: str
) -> None:
    decision = await engine.decide(_cmd(argv, environment))
    assert decision.effect == "allow"
    assert decision.rule_id == rule_id
    assert decision.channel == "ro"


@pytest.mark.parametrize("environment", ["staging", "prod"])
@pytest.mark.parametrize(
    "argv",
    [
        ["gh", "repo", "create", "view"],
        ["gh", "repo", "delete", "octo-org/staging-app"],
        ["gh", "repo", "edit", "octo-org/staging-app"],
        ["gh", "repo", "clone", "octo-org/staging-app"],
        ["gh", "repo", "fork", "octo-org/staging-app"],
        ["gh", "repo", "archive", "octo-org/staging-app"],
        ["gh", "repo", "rename", "list"],
        ["gh", "repo", "sync", "octo-org/staging-app"],
        ["gh", "repo", "deploy-key", "list"],
        ["gh", "release", "create", "view"],
        ["gh", "release", "delete", "v0.4.0"],
        ["gh", "release", "delete-asset", "v0.4.0", "asset.zip"],
        ["gh", "release", "edit", "v0.4.0"],
        ["gh", "release", "upload", "v0.4.0", "asset.zip"],
        ["gh", "release", "download", "v0.4.0"],
        # A read token inside a flag value or later positional cannot authorize a mutation.
        ["gh", "repo", "--json", "view", "create", "list"],
        ["gh", "release", "--repo", "view", "create", "list"],
        ["gh", "repo"],
        ["gh", "release"],
    ],
)
async def test_repository_and_release_non_reads_denied(
    engine: YamlRuleEngine, environment: str, argv: list[str]
) -> None:
    decision = await engine.decide(_cmd(argv, environment))
    assert decision.effect == "deny"
    assert decision.rule_id == "__default_deny__"


@pytest.mark.parametrize("environment", ["staging", "prod"])
@pytest.mark.parametrize("verb", ["repo", "release"])
@pytest.mark.parametrize("action", ["view", "list"])
@pytest.mark.parametrize(
    ("flags", "rule_id"),
    [
        (["--web"], "__flag_not_allowed__"),
        (["--hostname", "evil.example"], "gh-no-host-override"),
        (["--hostname=evil.example"], "gh-no-host-override"),
        (["--template", "{{.name}}"], "__flag_not_allowed__"),
        (["--unknown"], "__flag_not_allowed__"),
        (["--method", "POST"], "__flag_not_allowed__"),
    ],
)
async def test_repository_and_release_flags_denied(
    engine: YamlRuleEngine,
    environment: str,
    verb: str,
    action: str,
    flags: list[str],
    rule_id: str,
) -> None:
    decision = await engine.decide(_cmd(["gh", verb, action, *flags], environment))
    assert decision.effect == "deny"
    assert decision.rule_id == rule_id
