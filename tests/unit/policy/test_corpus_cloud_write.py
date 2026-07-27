"""Cloud-write corpus: curated aws/gcloud/az rw allows + dry-run escalate hybrid.

Pins BOTH sides for the write packs (aws-write / gcloud-write / az-write):
  * ALLOW — curated scale/update/rollout actions with ``--dry-run`` present (channel rw).
  * ESCALATE — the same actions without ``--dry-run`` (escalate > allow).
  * DENY — IAM/secret/destroy and non-allowlisted mutations still fail closed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from opendevops.policy.engine import YamlRuleEngine
from opendevops.policy.loader import load_policy
from opendevops.policy.schema import Decision, ToolCallCtx

REPO_ROOT = Path(__file__).resolve().parents[3]
SHIPPED_POLICY_DIR = REPO_ROOT / "config" / "policy"


def _resolver(ref: str) -> list[str]:
    if ref == "${targets.kubernetes.allowed_contexts}":
        return ["kind-opendevops"]
    if ref == "${targets.ssh.hosts}":
        return ["allowed.host.internal"]
    if ref == "${targets.github.write_repos}":
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
        run_id="run-corpus-cloud-write",
    )


async def _decide(engine: YamlRuleEngine, ctx: ToolCallCtx) -> Decision:
    return await engine.decide(ctx)


# --------------------------------------------------------------------------- allow (rw + dry-run)

STAGING_ALLOWS = [
    (
        ["aws", "ecs", "update-service", "--cluster", "c", "--service", "s", "--dry-run"],
        "aws-write-safe-ops",
    ),
    (
        ["aws", "autoscaling", "set-desired-capacity", "--auto-scaling-group-name", "g",
         "--desired-capacity", "2", "--dry-run"],
        "aws-write-safe-ops",
    ),
    (
        ["gcloud", "run", "services", "update-traffic", "svc", "--to-latest", "--dry-run"],
        "gcloud-write-run",
    ),
    (
        ["gcloud", "container", "clusters", "resize", "c", "--num-nodes", "3", "--dry-run"],
        "gcloud-write-container",
    ),
    (
        ["az", "webapp", "restart", "--name", "app", "--resource-group", "rg", "--dry-run"],
        "az-write-webapp",
    ),
    (
        ["az", "aks", "scale", "--name", "cluster", "--resource-group", "rg",
         "--node-count", "3", "--dry-run"],
        "az-write-aks",
    ),
]


@pytest.mark.parametrize(("argv", "rule_id"), STAGING_ALLOWS)
async def test_cloud_write_dry_run_allows(
    engine: YamlRuleEngine, argv: list[object], rule_id: str
) -> None:
    d = await _decide(engine, _cmd(argv))
    assert d.effect == "allow", f"{argv} -> {d.effect}/{d.rule_id}"
    assert d.rule_id == rule_id
    assert d.channel == "rw"


@pytest.mark.parametrize(("argv", "rule_id"), STAGING_ALLOWS)
async def test_cloud_write_dry_run_allows_in_prod(
    engine: YamlRuleEngine, argv: list[object], rule_id: str
) -> None:
    d = await _decide(engine, _cmd(argv, environment="prod"))
    assert d.effect == "allow"
    assert d.rule_id == rule_id
    assert d.channel == "rw"


# --------------------------------------------------------------------------- escalate (no dry-run)

STAGING_ESCALATES = [
    (
        ["aws", "ecs", "update-service", "--cluster", "c", "--service", "s"],
        "aws-write-require-approval-without-dry-run",
    ),
    (
        ["gcloud", "run", "services", "update-traffic", "svc", "--to-latest"],
        "gcloud-write-require-approval-without-dry-run",
    ),
    (
        ["az", "webapp", "restart", "--name", "app", "--resource-group", "rg"],
        "az-write-require-approval-without-dry-run",
    ),
]


@pytest.mark.parametrize(("argv", "rule_id"), STAGING_ESCALATES)
async def test_cloud_write_without_dry_run_escalates(
    engine: YamlRuleEngine, argv: list[object], rule_id: str
) -> None:
    d = await _decide(engine, _cmd(argv))
    assert d.effect == "escalate", f"{argv} -> {d.effect}/{d.rule_id}"
    assert d.rule_id == rule_id


# --------------------------------------------------------------------------- still denied

STILL_DENIED = [
    (["aws", "ec2", "terminate-instances", "--instance-ids", "i-1"], "aws-no-terminate-instances"),
    (["aws", "iam", "create-user", "--user-name", "x"], "aws-no-iam"),
    (["aws", "ec2", "run-instances", "--image-id", "ami-1"], "__default_deny__"),
    (["gcloud", "compute", "instances", "delete", "x"], "gcloud-no-delete"),
    (["gcloud", "compute", "instances", "set-machine-type", "x"], "__default_deny__"),
    (["az", "vm", "delete", "--name", "x", "--resource-group", "rg"], "az-no-delete"),
    (["az", "vm", "create", "--name", "x", "--resource-group", "rg"], "az-no-mutations"),
]


@pytest.mark.parametrize(("argv", "rule_id"), STILL_DENIED)
async def test_cloud_write_does_not_open_destructive(
    engine: YamlRuleEngine, argv: list[object], rule_id: str
) -> None:
    d = await _decide(engine, _cmd(argv))
    assert d.effect == "deny", f"{argv} -> {d.effect}/{d.rule_id}"
    assert d.rule_id == rule_id
