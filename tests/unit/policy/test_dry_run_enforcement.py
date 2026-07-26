"""Engine + real-pack integration for dry-run enforcement.

Drives the *real* shipped ``config/policy/`` through :class:`YamlRuleEngine` (staging env) and
asserts the final Decision effect / rule_id / rewritten_argv for each row of the composition —
the whole point being that ``force-server-dry-run-first`` (rewrite), the
``require-dry-run-before-real-apply`` hook, and the ``kubectl-apply`` allow compose under the
engine's ``deny > escalate > hook > rewrite > allow`` precedence + hook-abstain re-pass exactly
as designed. The hook is registered by importing the policy package (see policy/__init__.py).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from deepagents.backends.utils import create_file_data

from opendevops.policy.engine import YamlRuleEngine
from opendevops.policy.loader import load_policy
from opendevops.policy.schema import ToolCallCtx
from opendevops.tools.staging import resolve_file_refs

REPO_ROOT = Path(__file__).resolve().parents[3]
SHIPPED_POLICY_DIR = REPO_ROOT / "config" / "policy"

MANIFEST = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: demo\n"
PATH = "/manifests/deploy.yaml"
FILES: dict[str, Any] = {PATH: create_file_data(MANIFEST)}
SHA = resolve_file_refs(["kubectl", "apply", "-f", PATH], FILES)[0].sha256


def _resolver(ref: str) -> list[str]:
    if ref == "${targets.kubernetes.allowed_contexts}":
        return ["kind-opendevops"]
    if ref == "${targets.ssh.hosts}":  # ssh_run host allowlist ref
        return ["allowed.host.internal"]
    if ref == "${targets.github.write_repos}":  # gh-write repo allowlist ref
        return ["octo-org/staging-app"]
    raise AssertionError(f"unexpected config ref {ref!r}")


@pytest.fixture(scope="module")
def engine() -> YamlRuleEngine:
    return YamlRuleEngine(load_policy(SHIPPED_POLICY_DIR), _resolver)


def _ctx(
    argv: list[str],
    *,
    environment: str = "staging",
    files: Any = FILES,
    dry_run_ok: Any = None,
) -> ToolCallCtx:
    return ToolCallCtx(
        tool_name="run_command",
        args={"argv": argv},
        environment=environment,
        principal="tester",
        run_id="run-dry",
        files=files,
        dry_run_ok=dry_run_ok,
    )


async def test_row1_bare_apply_is_rewritten_to_server_dry_run(engine: YamlRuleEngine) -> None:
    d = await engine.decide(_ctx(["kubectl", "apply", "-f", PATH]))
    assert d.effect == "rewrite"
    assert d.rule_id == "force-server-dry-run-first"
    assert d.rewritten_argv == ["kubectl", "apply", "-f", PATH, "--dry-run=server"]
    assert d.channel == "rw"  # carried from the winning kubectl-apply allow


async def test_row2_explicit_server_dry_run_allows(engine: YamlRuleEngine) -> None:
    d = await engine.decide(_ctx(["kubectl", "apply", "-f", PATH, "--dry-run=server"]))
    assert d.effect == "allow"
    assert d.rule_id == "kubectl-apply"
    assert d.channel == "rw"


async def test_row3_real_apply_without_recorded_dry_run_is_denied(
    engine: YamlRuleEngine,
) -> None:
    d = await engine.decide(
        _ctx(["kubectl", "apply", "-f", PATH, "--dry-run=none"], dry_run_ok={})
    )
    assert d.effect == "deny"
    assert d.rule_id == "require-dry-run-before-real-apply"


async def test_row4_real_apply_with_recorded_dry_run_allows(engine: YamlRuleEngine) -> None:
    # dry_run_ok keys are RUN-SCOPED (``{run_id}:{sha}``); _ctx uses run_id="run-dry".
    d = await engine.decide(
        _ctx(
            ["kubectl", "apply", "-f", PATH, "--dry-run=none"],
            dry_run_ok={f"run-dry:{SHA}": True},
        )
    )
    assert d.effect == "allow"
    assert d.rule_id == "kubectl-apply"


async def test_row5_client_dry_run_is_denied(engine: YamlRuleEngine) -> None:
    d = await engine.decide(_ctx(["kubectl", "apply", "-f", PATH, "--dry-run=client"]))
    assert d.effect == "deny"
    assert d.rule_id == "require-dry-run-before-real-apply"


async def test_row6_file_less_apply_is_denied(engine: YamlRuleEngine) -> None:
    d = await engine.decide(_ctx(["kubectl", "apply", "-k", "/manifests/"]))
    assert d.effect == "deny"
    assert d.rule_id == "require-dry-run-before-real-apply"
    assert "--filename" in d.reason


async def test_prod_apply_is_rewritten_to_dry_run_before_control_plane_gate(
    engine: YamlRuleEngine,
) -> None:
    # The structural policy performs the dry-run rewrite in prod. PolicyMiddleware then requires
    # an active capability grant and independent approval before any real rw execution.
    d = await engine.decide(_ctx(["kubectl", "apply", "-f", PATH], environment="prod"))
    assert d.effect == "rewrite"
    assert d.rule_id == "force-server-dry-run-first"
    assert d.rewritten_argv is not None
    assert "--dry-run=server" in d.rewritten_argv


async def test_explicit_server_dry_run_flag_still_flag_checked(engine: YamlRuleEngine) -> None:
    # A disallowed flag on an otherwise-permitted apply is still rejected by the allow post-check
    # (proves the permit really flows through kubectl-apply + its flags_allowed, not the hook).
    d = await engine.decide(
        _ctx(["kubectl", "apply", "-f", PATH, "--dry-run=server", "--wait"])
    )
    assert d.effect == "deny"
    assert d.rule_id == "__flag_not_allowed__"
    assert "--wait" in d.reason
