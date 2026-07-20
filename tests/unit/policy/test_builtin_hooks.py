"""Unit tests for the ``dry_run_before_apply`` gatekeeper hook.

Drives the hook directly with hand-built :class:`ToolCallCtx`s (a ``files`` mapping + a
``dry_run_ok`` sha map), covering every row of the decision table plus the fail-closed paths.
Pins the gatekeeper convention: the hook only ever ABSTAINS (``None``) or DENIES — never allows.
"""

from __future__ import annotations

from typing import Any

import pytest
from deepagents.backends.utils import create_file_data

from opendevops.policy.builtin_hooks import dry_run_before_apply
from opendevops.policy.schema import RULE_FAIL_CLOSED, Decision, ToolCallCtx
from opendevops.tools.staging import resolve_file_refs

_RULE_ID = "require-dry-run-before-real-apply"

MANIFEST = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: demo\n"
PATH = "/manifests/deploy.yaml"
FILES: dict[str, Any] = {PATH: create_file_data(MANIFEST)}
# Derive the manifest sha exactly as the staging bridge does (the hook keys on the same value).
SHA = resolve_file_refs(["kubectl", "apply", "-f", PATH], FILES)[0].sha256


def _ctx(
    argv: list[str],
    *,
    files: Any = FILES,
    dry_run_ok: Any = None,
) -> ToolCallCtx:
    return ToolCallCtx(
        tool_name="run_command",
        args={"argv": argv},
        environment="staging",
        principal="tester",
        run_id="run-hook",
        files=files,
        dry_run_ok=dry_run_ok,
    )


# --------------------------------------------------------------------------- the 6 flow rows


async def test_row1_bare_apply_abstains_for_the_rewrite() -> None:
    # No --dry-run yet: abstain so force-server-dry-run-first can inject --dry-run=server.
    assert await dry_run_before_apply(_ctx(["kubectl", "apply", "-f", PATH])) is None


async def test_row2_explicit_server_dry_run_abstains() -> None:
    d = await dry_run_before_apply(_ctx(["kubectl", "apply", "-f", PATH, "--dry-run=server"]))
    assert d is None


async def test_row3_real_apply_without_recorded_sha_denies() -> None:
    d = await dry_run_before_apply(
        _ctx(["kubectl", "apply", "-f", PATH, "--dry-run=none"], dry_run_ok={})
    )
    assert d is not None
    assert d.effect == "deny"
    assert d.rule_id == _RULE_ID
    assert d.hint is not None
    assert "--dry-run=server" in d.hint


async def test_row4_real_apply_with_recorded_sha_abstains() -> None:
    # dry_run_ok keys are RUN-SCOPED (``{run_id}:{sha}``); _ctx uses run_id="run-hook".
    d = await dry_run_before_apply(
        _ctx(
            ["kubectl", "apply", "-f", PATH, "--dry-run=none"],
            dry_run_ok={f"run-hook:{SHA}": True},
        )
    )
    assert d is None


async def test_row4_recorded_sha_from_another_run_is_ignored() -> None:
    # A bare (un-scoped) or foreign-run sha must NOT satisfy the gate — run-scoping is the point.
    for stale in ({SHA: True}, {f"other-run:{SHA}": True}):
        d = await dry_run_before_apply(
            _ctx(["kubectl", "apply", "-f", PATH, "--dry-run=none"], dry_run_ok=stale)
        )
        assert d is not None
        assert d.effect == "deny"
        assert d.rule_id == _RULE_ID


async def test_row5_client_dry_run_denies_wants_server() -> None:
    d = await dry_run_before_apply(_ctx(["kubectl", "apply", "-f", PATH, "--dry-run=client"]))
    assert d is not None
    assert d.effect == "deny"
    assert d.rule_id == _RULE_ID
    assert d.hint is not None
    assert "--dry-run=server" in d.hint


async def test_row6_kustomize_no_filename_denies() -> None:
    # `apply -k <dir>` has no --filename to verify (kustomize unsupported).
    d = await dry_run_before_apply(_ctx(["kubectl", "apply", "-k", "/manifests/"]))
    assert d is not None
    assert d.effect == "deny"
    assert d.rule_id == _RULE_ID
    assert "--filename" in d.reason


async def test_row6_no_filename_denies_regardless_of_dry_run_value() -> None:
    # A file-less apply is denied even with --dry-run=none (nothing to verify).
    d = await dry_run_before_apply(_ctx(["kubectl", "apply", "--dry-run=none"], dry_run_ok={}))
    assert d is not None
    assert d.effect == "deny"
    assert d.rule_id == _RULE_ID
    assert "--filename" in d.reason


# --------------------------------------------------------------------------- fail-closed paths


async def test_real_apply_with_unresolvable_manifest_fails_closed() -> None:
    # --dry-run=none referencing a path absent from the virtual FS => cannot verify => deny.
    d = await dry_run_before_apply(
        _ctx(["kubectl", "apply", "-f", "/missing.yaml", "--dry-run=none"], files={})
    )
    assert d is not None
    assert d.effect == "deny"
    assert d.rule_id == RULE_FAIL_CLOSED


async def test_real_apply_without_files_state_fails_closed() -> None:
    d = await dry_run_before_apply(
        _ctx(["kubectl", "apply", "-f", PATH, "--dry-run=none"], files=None, dry_run_ok={SHA: True})
    )
    assert d is not None
    assert d.effect == "deny"
    assert d.rule_id == RULE_FAIL_CLOSED


async def test_unreadable_argv_fails_closed() -> None:
    d = await dry_run_before_apply(_ctx([]))  # type: ignore[arg-type]
    assert d is not None
    assert d.effect == "deny"
    assert d.rule_id == RULE_FAIL_CLOSED


# --------------------------------------------------------------------------- gatekeeper invariant


_ALL_CASES: list[dict[str, Any]] = [
    {"argv": ["kubectl", "apply", "-f", PATH]},
    {"argv": ["kubectl", "apply", "-f", PATH, "--dry-run=server"]},
    {"argv": ["kubectl", "apply", "-f", PATH, "--dry-run=none"], "dry_run_ok": {}},
    {"argv": ["kubectl", "apply", "-f", PATH, "--dry-run=none"], "dry_run_ok": {SHA: True}},
    {"argv": ["kubectl", "apply", "-f", PATH, "--dry-run=client"]},
    {"argv": ["kubectl", "apply", "-k", "/manifests/"]},
    {"argv": ["kubectl", "apply", "--dry-run=none"], "dry_run_ok": {}},
    {"argv": ["kubectl", "apply", "-f", "/missing.yaml", "--dry-run=none"], "files": {}},
]


@pytest.mark.parametrize("case", _ALL_CASES)
async def test_hook_never_returns_allow(case: dict[str, Any]) -> None:
    """A gatekeeper hook returns a deny Decision or None — never an allow (or any other effect)."""
    result = await dry_run_before_apply(_ctx(**case))
    assert result is None or (isinstance(result, Decision) and result.effect == "deny")
