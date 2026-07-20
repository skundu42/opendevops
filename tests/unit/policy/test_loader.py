"""Loader + lint tests (T3): shipped dir loads clean, stable hash, lint failures aggregate."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from opendevops.policy.loader import (
    LoadedPolicy,
    PolicyLintError,
    check_credential_coverage,
    load_policy,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
SHIPPED_POLICY_DIR = REPO_ROOT / "config" / "policy"


def _meta(name: str) -> dict[str, Any]:
    return {"name": name, "owner": "test", "updated": "2026-07-18"}


def _write(dir_: Path, rel: str, doc: dict[str, Any]) -> None:
    path = dir_ / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(doc))


def _base_only(dir_: Path) -> None:
    _write(
        dir_,
        "base.yaml",
        {
            "version": 1,
            "metadata": _meta("base"),
            "acknowledged_default_deny": [],
            "rules": [
                {
                    "id": "deny-bash",
                    "match": {"argv0": "bash"},
                    "effect": "deny",
                    "reason": "no",
                }
            ],
        },
    )


# --------------------------------------------------------------------------- shipped dir


def test_shipped_dir_loads_clean() -> None:
    loaded = load_policy(SHIPPED_POLICY_DIR)
    assert isinstance(loaded, LoadedPolicy)
    # base + pack rules present
    assert "interpreters-hard-deny" in loaded.rules_by_id
    assert "no-builtin-shell-execute" in loaded.rules_by_id
    assert "kubectl-read-verbs" in loaded.rules_by_id
    # flags merged from the pack
    assert "kubectl" in loaded.flags_allowed_merged
    assert "--namespace" in loaded.flags_allowed_merged["kubectl"]
    assert "--watch" not in loaded.flags_allowed_merged["kubectl"]
    # the allow rule is bound to its credential family
    assert loaded.tool_family_by_rule["kubectl-read-verbs"] == "kubectl"
    # a base deny rule has no tool_family
    assert loaded.tool_family_by_rule["interpreters-hard-deny"] is None
    assert loaded.acknowledged_default_deny == []


def test_policy_version_stable() -> None:
    v1 = load_policy(SHIPPED_POLICY_DIR).policy_version
    v2 = load_policy(SHIPPED_POLICY_DIR).policy_version
    assert v1 == v2
    assert v1.startswith("sha256:")


def test_shipped_execute_deny_present() -> None:
    loaded = load_policy(SHIPPED_POLICY_DIR)
    rule = loaded.rules_by_id["no-builtin-shell-execute"]
    assert rule.effect == "deny"
    assert rule.match.tool_name is not None
    assert rule.match.tool_name.matches("execute")


# --------------------------------------------------------------------------- lint failures


def test_duplicate_id_across_files_fails(tmp_path: Path) -> None:
    _base_only(tmp_path)
    _write(
        tmp_path,
        "packs/dup.yaml",
        {
            "version": 1,
            "metadata": _meta("dup"),
            "rules": [
                {
                    "id": "deny-bash",  # collides with base.yaml
                    "match": {"argv0": "sh"},
                    "effect": "deny",
                    "reason": "no",
                }
            ],
        },
    )
    with pytest.raises(PolicyLintError) as ei:
        load_policy(tmp_path)
    assert any("deny-bash" in p for p in ei.value.problems)


def test_allow_in_overlay_fails(tmp_path: Path) -> None:
    _base_only(tmp_path)
    _write(
        tmp_path,
        "envs/staging.yaml",
        {
            "version": 1,
            "metadata": _meta("staging"),
            "rules": [
                {
                    "id": "sneaky-allow",
                    "match": {"argv0": "kubectl", "verb": "get"},
                    "effect": "allow",
                    "channel": "ro",
                }
            ],
        },
    )
    with pytest.raises(PolicyLintError) as ei:
        load_policy(tmp_path)
    assert any("overlay" in p.lower() for p in ei.value.problems)


def test_overlay_with_flags_allowed_fails(tmp_path: Path) -> None:
    _base_only(tmp_path)
    _write(
        tmp_path,
        "envs/staging.yaml",
        {
            "version": 1,
            "metadata": _meta("staging"),
            # loosening-capable field: an overlay must never carry this
            "flags_allowed": {"kubectl": ["--watch"]},
            "rules": [
                {
                    "id": "staging-deny",
                    "match": {"argv0": "kubectl", "verb": "delete"},
                    "effect": "deny",
                    "reason": "no deletes in staging",
                }
            ],
        },
    )
    with pytest.raises(PolicyLintError) as ei:
        load_policy(tmp_path)
    assert any("flags_allowed" in p and "overlay" in p.lower() for p in ei.value.problems)


def test_overlay_with_tool_family_fails(tmp_path: Path) -> None:
    _base_only(tmp_path)
    _write(
        tmp_path,
        "envs/staging.yaml",
        {
            "version": 1,
            "metadata": _meta("staging"),
            # loosening-capable field: an overlay must never carry this
            "tool_family": "kubectl",
            "rules": [
                {
                    "id": "staging-deny",
                    "match": {"argv0": "kubectl", "verb": "delete"},
                    "effect": "deny",
                    "reason": "no deletes in staging",
                }
            ],
        },
    )
    with pytest.raises(PolicyLintError) as ei:
        load_policy(tmp_path)
    assert any("tool_family" in p and "overlay" in p.lower() for p in ei.value.problems)


def test_overlay_with_acknowledged_default_deny_fails(tmp_path: Path) -> None:
    _base_only(tmp_path)
    _write(
        tmp_path,
        "envs/staging.yaml",
        {
            "version": 1,
            "metadata": _meta("staging"),
            # loosening-capable field: an overlay must never carry this
            "acknowledged_default_deny": ["some-tool"],
            "rules": [
                {
                    "id": "staging-deny",
                    "match": {"argv0": "kubectl", "verb": "delete"},
                    "effect": "deny",
                    "reason": "no deletes in staging",
                }
            ],
        },
    )
    with pytest.raises(PolicyLintError) as ei:
        load_policy(tmp_path)
    assert any(
        "acknowledged_default_deny" in p and "overlay" in p.lower() for p in ei.value.problems
    )


def test_overlay_with_deny_rule_accepted(tmp_path: Path) -> None:
    # Positive case: a well-formed overlay that only adds a deny rule, and carries none
    # of the loosening-capable fields, must load clean.
    _base_only(tmp_path)
    _write(
        tmp_path,
        "envs/staging.yaml",
        {
            "version": 1,
            "metadata": _meta("staging"),
            "rules": [
                {
                    "id": "staging-deny-delete",
                    "match": {"argv0": "kubectl", "verb": "delete"},
                    "effect": "deny",
                    "reason": "no deletes in staging",
                }
            ],
        },
    )
    loaded = load_policy(tmp_path)
    assert "staging-deny-delete" in loaded.rules_by_id
    assert loaded.rules_by_id["staging-deny-delete"].effect == "deny"
    assert loaded.tool_family_by_rule["staging-deny-delete"] is None


def test_pack_allow_missing_tool_family_fails(tmp_path: Path) -> None:
    _base_only(tmp_path)
    _write(
        tmp_path,
        "packs/kubectl.yaml",
        {
            "version": 1,
            "metadata": _meta("kubectl"),
            # no tool_family
            "flags_allowed": {"kubectl": ["--namespace"]},
            "rules": [
                {
                    "id": "kubectl-allow",
                    "match": {"argv0": "kubectl", "verb": "get"},
                    "effect": "allow",
                    "channel": "ro",
                }
            ],
        },
    )
    with pytest.raises(PolicyLintError) as ei:
        load_policy(tmp_path)
    assert any("tool_family" in p for p in ei.value.problems)


def test_allow_binary_missing_flags_allowed_fails(tmp_path: Path) -> None:
    _base_only(tmp_path)
    _write(
        tmp_path,
        "packs/kubectl.yaml",
        {
            "version": 1,
            "metadata": _meta("kubectl"),
            "tool_family": "kubectl",
            # flags_allowed missing the kubectl entry
            "rules": [
                {
                    "id": "kubectl-allow",
                    "match": {"argv0": "kubectl", "verb": "get"},
                    "effect": "allow",
                    "channel": "ro",
                }
            ],
        },
    )
    with pytest.raises(PolicyLintError) as ei:
        load_policy(tmp_path)
    assert any("flags_allowed" in p for p in ei.value.problems)


def test_schema_invalid_file_reported(tmp_path: Path) -> None:
    _base_only(tmp_path)
    _write(
        tmp_path,
        "packs/bad.yaml",
        {
            "version": 1,
            "metadata": _meta("bad"),
            "rules": [
                # allow without channel -> schema invalid
                {"id": "bad-allow", "match": {"argv0": "kubectl"}, "effect": "allow"}
            ],
        },
    )
    with pytest.raises(PolicyLintError) as ei:
        load_policy(tmp_path)
    assert any("bad.yaml" in p for p in ei.value.problems)


def test_all_errors_reported_together(tmp_path: Path) -> None:
    _base_only(tmp_path)
    # overlay with an allow (overlay violation + missing tool_family)
    _write(
        tmp_path,
        "envs/prod.yaml",
        {
            "version": 1,
            "metadata": _meta("prod"),
            "rules": [
                {
                    "id": "deny-bash",  # duplicate id (collides with base)
                    "match": {"argv0": "kubectl", "verb": "get"},
                    "effect": "allow",
                    "channel": "ro",
                }
            ],
        },
    )
    with pytest.raises(PolicyLintError) as ei:
        load_policy(tmp_path)
    # at least the duplicate-id and overlay-allow problems both surface
    assert len(ei.value.problems) >= 2


# --------------------------------------------------------------------------- credential coverage


def test_check_credential_coverage_missing() -> None:
    loaded = load_policy(SHIPPED_POLICY_DIR)
    problems = check_credential_coverage(loaded, set())
    assert any("kubectl" in p for p in problems)


def test_check_credential_coverage_ok() -> None:
    # P2 adds helm-read + gh-read; P5a adds aws/gcloud/az-read; P5b adds ssh (ssh_run); P5f adds
    # gh-write, whose rw allows also need the "gh-rw" write pseudo-family. Full coverage needs all.
    loaded = load_policy(SHIPPED_POLICY_DIR)
    assert (
        check_credential_coverage(
            loaded, {"kubectl", "helm", "gh", "gh-rw", "aws", "gcloud", "az", "ssh"}
        )
        == []
    )


def test_check_credential_coverage_gh_rw_write_gate() -> None:
    # P5f: the gh-write pack's rw allows require the "gh-rw" write pseudo-family. With the ro gh
    # token configured but no rw write PAT, gh-write surfaces as a "gh-rw" coverage gap while
    # gh-read (ro) stays covered.
    loaded = load_policy(SHIPPED_POLICY_DIR)
    problems = check_credential_coverage(
        loaded, {"kubectl", "helm", "gh", "aws", "gcloud", "az", "ssh"}
    )
    assert any("gh-rw" in p for p in problems)
    # gh (ro) is covered, so the ONLY gh-family gap is the write pseudo-family, not gh itself.
    assert not any(p for p in problems if "'gh'" in p)


def test_check_credential_coverage_p2_families_needed() -> None:
    # With only kubectl configured, the new helm/gh allow packs surface as coverage gaps.
    loaded = load_policy(SHIPPED_POLICY_DIR)
    problems = check_credential_coverage(loaded, {"kubectl"})
    assert any("helm" in p for p in problems)
    assert any("gh" in p for p in problems)


def test_check_credential_coverage_p5_cloud_families_needed() -> None:
    # With k8s + gh configured but no cloud, the aws/gcloud/az-read packs surface as coverage gaps.
    loaded = load_policy(SHIPPED_POLICY_DIR)
    problems = check_credential_coverage(loaded, {"kubectl", "helm", "gh"})
    assert any("aws" in p for p in problems)
    assert any("gcloud" in p for p in problems)
    assert any("az" in p for p in problems)


def test_shipped_dir_loads_p5_cloud_packs() -> None:
    loaded = load_policy(SHIPPED_POLICY_DIR)
    for rid in (
        "aws-read-actions",
        "aws-no-iam",
        "aws-no-terminate-instances",
        "aws-no-secret-reads",
        "aws-no-ssm-decrypt",
        "aws-no-endpoint-override",
        "gcloud-read-compute",
        "gcloud-no-delete",
        "gcloud-no-secret-access",
        "gcloud-no-cred-override",
        "az-read-vm",
        "az-no-delete",
        "az-no-secret-reads",
        "az-no-subscription-override",
    ):
        assert rid in loaded.rules_by_id, rid
    # each cloud pack contributes its own flags_allowed to the merged view
    assert "--region" in loaded.flags_allowed_merged["aws"]
    assert "--project" in loaded.flags_allowed_merged["gcloud"]
    assert "--resource-group" in loaded.flags_allowed_merged["az"]
    # the allow rules bind to their credential families; the base denies carry none
    assert loaded.tool_family_by_rule["aws-read-actions"] == "aws"
    assert loaded.tool_family_by_rule["gcloud-read-compute"] == "gcloud"
    assert loaded.tool_family_by_rule["az-read-vm"] == "az"
    assert loaded.tool_family_by_rule["aws-no-secret-reads"] is None


def test_shipped_dir_loads_p2_packs() -> None:
    loaded = load_policy(SHIPPED_POLICY_DIR)
    for rid in (
        "kubectl-apply",
        "kubectl-rollout",
        "kubectl-scale",
        "kubectl-mutate-no-force",
        "helm-read-verbs",
        "gh-read-run",
        "gh-read-pr",
        "gh-read-issue",
        "gh-no-api",
    ):
        assert rid in loaded.rules_by_id, rid
    # each new allow pack contributes its own flags_allowed to the merged view
    assert "helm" in loaded.flags_allowed_merged
    assert "--max" in loaded.flags_allowed_merged["helm"]
    assert "gh" in loaded.flags_allowed_merged
    assert "--json" in loaded.flags_allowed_merged["gh"]
    # --web is deliberately NOT in the gh allowlist (interactive browser)
    assert "--web" not in loaded.flags_allowed_merged["gh"]
    # the new allow rules bind to their credential families
    assert loaded.tool_family_by_rule["helm-read-verbs"] == "helm"
    assert loaded.tool_family_by_rule["gh-read-pr"] == "gh"
    assert loaded.tool_family_by_rule["kubectl-apply"] == "kubectl"


def test_shipped_dir_loads_gh_write_pack() -> None:
    # P5f: the gh-write pack ships its three rw allows + the airtight `gh api` denies, and binds
    # to the gh credential family. The write flags land in the merged gh allowlist.
    loaded = load_policy(SHIPPED_POLICY_DIR)
    for rid in (
        "gh-write-run-rerun",
        "gh-write-pr-create",
        "gh-api-write",
        "gh-api-no-delete",
        "gh-api-no-secrets",
        "gh-api-no-orgs",
    ):
        assert rid in loaded.rules_by_id, rid
    assert loaded.tool_family_by_rule["gh-api-write"] == "gh"
    assert loaded.rules_by_id["gh-api-write"].channel == "rw"
    assert loaded.rules_by_id["gh-api-no-secrets"].effect == "deny"
    for flag in ("--title", "--body", "--method", "--input"):
        assert flag in loaded.flags_allowed_merged["gh"], flag
