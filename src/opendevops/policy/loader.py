"""YAML policy loader + lint.

Loads the shipped policy directory in a fixed order — ``base.yaml``, then ``packs/*.yaml``
(sorted), then ``envs/*.yaml`` (sorted) as overlays — validates every file against the
:mod:`~opendevops.policy.schema` models, and runs a batch of cross-file lints. All lint
problems are collected and raised together as a single :class:`PolicyLintError` so an
operator sees every issue at once, not one-per-fix-cycle.

``load_policy`` is pure and side-effect free apart from reading files; the engine and
boot sequence consume its :class:`LoadedPolicy` result without needing changes here.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from opendevops.policy.schema import PolicyFile, Rule


class PolicyLintError(Exception):
    """Raised when policy files fail validation or lint. Carries *all* problems found."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = problems
        joined = "\n  - ".join(problems)
        super().__init__(f"policy lint failed ({len(problems)} problem(s)):\n  - {joined}")


@dataclass(frozen=True)
class LoadedPolicy:
    """The fully-loaded, lint-clean policy: everything the engine needs, precomputed."""

    files: dict[str, PolicyFile]
    rules_by_id: dict[str, Rule]
    flags_allowed_merged: dict[str, list[str]]
    tool_family_by_rule: dict[str, str | None]
    policy_version: str
    acknowledged_default_deny: list[str] = field(default_factory=list)


def _discover_files(dir_: Path) -> list[Path]:
    """Enumerate policy files in load order: base.yaml, packs/*.yaml, envs/*.yaml (sorted)."""
    paths: list[Path] = []
    base = dir_ / "base.yaml"
    if base.is_file():
        paths.append(base)
    paths.extend(sorted((dir_ / "packs").glob("*.yaml")))
    paths.extend(sorted((dir_ / "envs").glob("*.yaml")))
    return paths


def _is_overlay(dir_: Path, path: Path) -> bool:
    return path.parent == (dir_ / "envs")


def load_policy(dir_: Path) -> LoadedPolicy:
    """Load, validate, and lint every policy file under ``dir_``.

    Raises :class:`PolicyLintError` (listing every problem) on any schema violation,
    duplicate rule id, overlay-rule violation (a non deny/escalate rule, or a
    loosening-capable field: ``flags_allowed``, ``tool_family``, or
    ``acknowledged_default_deny``), missing ``tool_family`` on an allow pack, or an allowed
    binary that lacks a ``flags_allowed`` entry in its pack.
    """
    dir_ = Path(dir_)
    paths = _discover_files(dir_)
    problems: list[str] = []

    if not paths:
        raise PolicyLintError([f"no policy files found under {dir_}"])

    files: dict[str, PolicyFile] = {}
    raw_by_path: dict[str, Any] = {}

    # --- per-file parse + schema validation ------------------------------------------
    for path in paths:
        rel = str(path.relative_to(dir_))
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            problems.append(f"{rel}: invalid YAML: {exc}")
            continue
        if not isinstance(raw, dict):
            problems.append(f"{rel}: top-level document must be a mapping")
            continue
        raw_by_path[rel] = raw
        try:
            files[rel] = PolicyFile.model_validate(raw)
        except ValidationError as exc:
            problems.append(f"{rel}: schema-invalid file: {exc}")

    # --- cross-file lints (only over files that parsed) ------------------------------
    rules_by_id: dict[str, Rule] = {}
    tool_family_by_rule: dict[str, str | None] = {}

    for path in paths:
        rel = str(path.relative_to(dir_))
        pf = files.get(rel)
        if pf is None:
            continue
        overlay = _is_overlay(dir_, path)

        # duplicate rule ids across all files
        for rule in pf.rules:
            if rule.id in rules_by_id:
                problems.append(f"{rel}: duplicate rule id {rule.id!r} (already defined)")
                continue
            rules_by_id[rule.id] = rule
            tool_family_by_rule[rule.id] = pf.tool_family

        # overlays may contain ONLY deny/escalate rules, and may not carry any
        # loosening-capable field. `flags_allowed` and `acknowledged_default_deny` are
        # merged across every file the loader loads (see the merge pass below), and
        # `tool_family` is what binds an allow rule to a credential family — an overlay
        # that snuck any of these in could silently widen what's permitted, which
        # breaks the "overlays only tighten" contract just as surely as an `allow` rule
        # would. Reject all of it here, batched with the other lints.
        if overlay:
            for rule in pf.rules:
                if rule.effect not in ("deny", "escalate"):
                    problems.append(
                        f"{rel}: overlay files may only add deny/escalate rules, "
                        f"but rule {rule.id!r} has effect {rule.effect!r}"
                    )
            if pf.flags_allowed is not None:
                problems.append(
                    f"{rel}: overlay files may not carry 'flags_allowed' "
                    "(overlays only tighten policy, never loosen it)"
                )
            if pf.tool_family is not None:
                problems.append(
                    f"{rel}: overlay files may not carry 'tool_family' "
                    "(overlays only tighten policy, never loosen it)"
                )
            if pf.acknowledged_default_deny is not None:
                problems.append(
                    f"{rel}: overlay files may not carry 'acknowledged_default_deny' "
                    "(overlays only tighten policy, never loosen it)"
                )

        has_allow = any(r.effect == "allow" for r in pf.rules)

        # a file with allow rules must declare its credential tool_family
        if has_allow and pf.tool_family is None:
            problems.append(f"{rel}: contains allow rule(s) but is missing 'tool_family'")

        # every binary an allow rule targets must have a flags_allowed entry in that pack
        flags_allowed = pf.flags_allowed or {}
        for rule in pf.rules:
            if rule.effect != "allow" or rule.match.argv0 is None:
                continue
            for binary in rule.match.argv0.values():
                if binary not in flags_allowed:
                    problems.append(
                        f"{rel}: allow rule {rule.id!r} targets binary {binary!r} "
                        f"which has no 'flags_allowed' entry in this pack"
                    )

    if problems:
        raise PolicyLintError(problems)

    # --- merges (only reached when lint-clean) ---------------------------------------
    flags_allowed_merged: dict[str, list[str]] = {}
    acknowledged: list[str] = []
    for pf in files.values():
        for binary, allowed in (pf.flags_allowed or {}).items():
            merged = flags_allowed_merged.setdefault(binary, [])
            for flag in allowed:
                if flag not in merged:
                    merged.append(flag)
        for tool in pf.acknowledged_default_deny or []:
            if tool not in acknowledged:
                acknowledged.append(tool)

    policy_version = _policy_version(raw_by_path)

    return LoadedPolicy(
        files=files,
        rules_by_id=rules_by_id,
        flags_allowed_merged=flags_allowed_merged,
        tool_family_by_rule=tool_family_by_rule,
        policy_version=policy_version,
        acknowledged_default_deny=acknowledged,
    )


def _policy_version(raw_by_path: dict[str, Any]) -> str:
    """Content hash over the canonicalized YAML of every file (order-independent, stable)."""
    canonical = [yaml.safe_dump(doc, sort_keys=True) for doc in raw_by_path.values()]
    digest = hashlib.sha256("".join(sorted(canonical)).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


# Families whose WRITE (rw) channel is gated at BOOT on a *distinct* rw credential — not merely
# the family's ro credential. ``gh`` is the only such family: the gh-write pack's rw allows
# require ``targets.github.token_env_rw`` at boot (surfaced as the ``"gh-rw"`` pseudo-family in
# ``_configured_credential_families``), mirroring the ro gh gate. kubectl/helm rw (kubectl-mutate)
# deliberately stay ro-gated at boot and fail closed at EXEC on a missing rw kubeconfig — that
# long-standing behavior is intentionally unchanged, so only ``gh`` is listed here.
_RW_BOOT_GATED_FAMILIES: frozenset[str] = frozenset({"gh"})


def check_credential_coverage(loaded: LoadedPolicy, credential_families: set[str]) -> list[str]:
    """Report any allow-rule pack whose credential (family, or rw sub-credential) is unconfigured.

    Pure function (the boot sequence wires it and decides whether to fail). Returns a list of
    human-readable problems; an empty list means every allow pack's credential is covered.

    A pack with allow rules needs its ``tool_family`` configured. For a family in
    :data:`_RW_BOOT_GATED_FAMILIES` (``gh``), a pack that carries any ``channel: rw`` allow ALSO
    needs the ``"{family}-rw"`` pseudo-family — the rw credential — configured, so a gh-write pack
    whose write PAT is unset refuses to boot rather than fail only at first exec.
    """
    needed: set[str] = set()
    for pf in loaded.files.values():
        family = pf.tool_family
        if not family:
            continue
        allows = [r for r in pf.rules if r.effect == "allow"]
        if not allows:
            continue
        needed.add(family)
        if family in _RW_BOOT_GATED_FAMILIES and any(r.channel == "rw" for r in allows):
            needed.add(f"{family}-rw")
    return [
        f"tool_family {fam!r} has allow rules but no credential entry configured"
        for fam in sorted(needed)
        if fam not in credential_families
    ]
