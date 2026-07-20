"""Engine unit tests (T4): precedence, environments, rewrite, hooks, fail-closed.

These build small in-memory ``PolicyFile`` fixtures and a synthetic ``LoadedPolicy`` (bypassing
the loader) to exercise the decision engine in isolation from the shipped YAML.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from opendevops.policy import engine as engine_mod
from opendevops.policy.engine import YamlRuleEngine
from opendevops.policy.hooks import policy_hook
from opendevops.policy.loader import LoadedPolicy
from opendevops.policy.schema import Decision, PolicyFile, ToolCallCtx

# --------------------------------------------------------------------------- hook fixtures
# Registered once at import time under globally-unique names (the registry is process-global).


@policy_hook("t4_hook_abstain")
async def _hook_abstain(ctx: ToolCallCtx) -> Decision | None:
    return None


@policy_hook("t4_hook_deny")
async def _hook_deny(ctx: ToolCallCtx) -> Decision | None:
    return Decision.deny("hook-said-no", "the hook denied this call")


@policy_hook("t4_hook_sleep")
async def _hook_sleep(ctx: ToolCallCtx) -> Decision | None:
    await asyncio.sleep(5.0)
    return None  # pragma: no cover - cancelled by the timeout


@policy_hook("t4_hook_raise")
async def _hook_raise(ctx: ToolCallCtx) -> Decision | None:
    raise RuntimeError("boom in hook")


# --------------------------------------------------------------------------- builders


def _meta(name: str) -> dict[str, str]:
    return {"name": name, "owner": "test", "updated": "2026-07-18"}


def _pf(name: str, rules: list[dict[str, Any]], **extra: Any) -> PolicyFile:
    return PolicyFile.model_validate(
        {"version": 1, "metadata": _meta(name), "rules": rules, **extra}
    )


def _loaded(*files: PolicyFile) -> LoadedPolicy:
    ordered = {pf.metadata.name: pf for pf in files}
    rules_by_id = {}
    tool_family_by_rule = {}
    flags_allowed_merged: dict[str, list[str]] = {}
    for pf in ordered.values():
        for rule in pf.rules:
            rules_by_id[rule.id] = rule
            tool_family_by_rule[rule.id] = pf.tool_family
        for binary, flags in (pf.flags_allowed or {}).items():
            merged = flags_allowed_merged.setdefault(binary, [])
            for flag in flags:
                if flag not in merged:
                    merged.append(flag)
    return LoadedPolicy(
        files=ordered,
        rules_by_id=rules_by_id,
        flags_allowed_merged=flags_allowed_merged,
        tool_family_by_rule=tool_family_by_rule,
        policy_version="sha256:test",
    )


def _no_refs(_ref: str) -> list[str]:  # resolver for fixtures with no flag_value_not_in
    raise AssertionError("resolver should not be called")


def _cmd(argv: list[str], environment: str = "staging") -> ToolCallCtx:
    return ToolCallCtx(
        tool_name="run_command",
        args={"argv": argv},
        environment=environment,
        principal="tester",
        run_id="run-engine",
    )


# --------------------------------------------------------------------------- precedence


async def test_deny_beats_allow_on_same_match() -> None:
    pf = _pf(
        "pack",
        tool_family="kubectl",
        flags_allowed={"kubectl": ["--namespace"]},
        rules=[
            {
                "id": "allow-get",
                "match": {"argv0": "kubectl", "verb": "get"},
                "effect": "allow",
                "channel": "ro",
            },
            {
                "id": "deny-get",
                "match": {"argv0": "kubectl", "verb": "get"},
                "effect": "deny",
                "reason": "nope",
            },
        ],
    )
    eng = YamlRuleEngine(_loaded(pf), _no_refs)
    d = await eng.decide(_cmd(["kubectl", "get", "pods"]))
    assert d.effect == "deny"
    assert d.rule_id == "deny-get"


async def test_escalate_beats_rewrite_and_allow() -> None:
    pf = _pf(
        "pack",
        tool_family="kubectl",
        flags_allowed={"kubectl": ["--namespace"]},
        rules=[
            {
                "id": "allow-get",
                "match": {"argv0": "kubectl", "verb": "get"},
                "effect": "allow",
                "channel": "ro",
            },
            {
                "id": "rewrite-get",
                "match": {"argv0": "kubectl", "verb": "get"},
                "effect": "rewrite",
                "rewrite": {"inject_flags": ["--namespace=web"]},
            },
            {
                "id": "escalate-get",
                "match": {"argv0": "kubectl", "verb": "get"},
                "effect": "escalate",
                "channel": "rw",
                "escalation": {"timeout_s": 300, "on_timeout": "deny"},
                "reason": "needs a human",
            },
        ],
    )
    eng = YamlRuleEngine(_loaded(pf), _no_refs)
    d = await eng.decide(_cmd(["kubectl", "get", "pods"]))
    assert d.effect == "escalate"
    assert d.rule_id == "escalate-get"


async def test_hook_abstain_falls_through_to_allow() -> None:
    pf = _pf(
        "pack",
        tool_family="kubectl",
        flags_allowed={"kubectl": ["--namespace"]},
        rules=[
            {
                "id": "hook-get",
                "match": {"argv0": "kubectl", "verb": "get"},
                "effect": "hook",
                "hook": "t4_hook_abstain",
            },
            {
                "id": "allow-get",
                "match": {"argv0": "kubectl", "verb": "get"},
                "effect": "allow",
                "channel": "ro",
            },
        ],
    )
    eng = YamlRuleEngine(_loaded(pf), _no_refs)
    d = await eng.decide(_cmd(["kubectl", "get", "pods"]))
    assert d.effect == "allow"
    assert d.rule_id == "allow-get"
    assert d.channel == "ro"


async def test_hook_decision_wins_in_hook_slot() -> None:
    pf = _pf(
        "pack",
        tool_family="kubectl",
        flags_allowed={"kubectl": ["--namespace"]},
        rules=[
            {
                "id": "hook-get",
                "match": {"argv0": "kubectl", "verb": "get"},
                "effect": "hook",
                "hook": "t4_hook_deny",
            },
            {
                "id": "allow-get",
                "match": {"argv0": "kubectl", "verb": "get"},
                "effect": "allow",
                "channel": "ro",
            },
        ],
    )
    eng = YamlRuleEngine(_loaded(pf), _no_refs)
    d = await eng.decide(_cmd(["kubectl", "get", "pods"]))
    assert d.effect == "deny"
    assert d.rule_id == "hook-said-no"


# --------------------------------------------------------------------------- environments


async def test_prod_only_rule_does_not_fire_in_staging() -> None:
    pf = _pf(
        "pack",
        tool_family="kubectl",
        flags_allowed={"kubectl": ["--namespace"]},
        rules=[
            {
                "id": "deny-prod-only",
                "match": {"argv0": "kubectl", "verb": "get"},
                "effect": "deny",
                "environments": ["prod"],
                "reason": "prod locked down",
            },
            {
                "id": "allow-get",
                "match": {"argv0": "kubectl", "verb": "get"},
                "effect": "allow",
                "channel": "ro",
                "environments": ["staging", "prod"],
            },
        ],
    )
    eng = YamlRuleEngine(_loaded(pf), _no_refs)

    staging = await eng.decide(_cmd(["kubectl", "get", "pods"], environment="staging"))
    assert staging.effect == "allow"
    assert staging.rule_id == "allow-get"

    prod = await eng.decide(_cmd(["kubectl", "get", "pods"], environment="prod"))
    assert prod.effect == "deny"
    assert prod.rule_id == "deny-prod-only"


# --------------------------------------------------------------------------- rewrite


def _rewrite_pack() -> PolicyFile:
    return _pf(
        "pack",
        tool_family="kubectl",
        flags_allowed={"kubectl": ["--dry-run", "--filename"]},
        rules=[
            {
                "id": "rewrite-apply",
                "match": {"argv0": "kubectl", "verb": "apply", "flags_absent": ["--dry-run"]},
                "effect": "rewrite",
                "rewrite": {"inject_flags": ["--dry-run=server"]},
            },
            {
                "id": "allow-apply",
                "match": {"argv0": "kubectl", "verb": "apply"},
                "effect": "allow",
                "channel": "rw",
            },
        ],
    )


async def test_rewrite_happy_path() -> None:
    eng = YamlRuleEngine(_loaded(_rewrite_pack()), _no_refs)
    d = await eng.decide(_cmd(["kubectl", "apply"]))
    assert d.effect == "rewrite"
    assert d.rule_id == "rewrite-apply"
    assert d.rewritten_argv == ["kubectl", "apply", "--dry-run=server"]
    assert d.channel == "rw"


async def test_rewrite_diverged_when_rewritten_hits_deny() -> None:
    pf = _pf(
        "pack",
        tool_family="kubectl",
        flags_allowed={"kubectl": ["--dry-run"]},
        rules=[
            {
                "id": "rewrite-apply",
                "match": {"argv0": "kubectl", "verb": "apply", "flags_absent": ["--dry-run"]},
                "effect": "rewrite",
                "rewrite": {"inject_flags": ["--dry-run=server"]},
            },
            {
                "id": "deny-dry-run",
                "match": {"argv0": "kubectl", "verb": "apply", "flags_any": ["--dry-run"]},
                "effect": "deny",
                "reason": "dry-run explicitly forbidden after rewrite",
            },
        ],
    )
    eng = YamlRuleEngine(_loaded(pf), _no_refs)
    d = await eng.decide(_cmd(["kubectl", "apply"]))
    assert d.effect == "deny"
    assert d.rule_id == "__rewrite_diverged__"


# --------------------------------------------------------------------------- hook fail-closed


async def test_hook_timeout_is_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    # Keep the test fast: shrink the (default 2.0s) timeout so the 5s hook trips it quickly.
    monkeypatch.setattr(engine_mod, "HOOK_TIMEOUT_S", 0.05)
    pf = _pf(
        "pack",
        tool_family="kubectl",
        flags_allowed={"kubectl": ["--namespace"]},
        rules=[
            {
                "id": "hook-get",
                "match": {"argv0": "kubectl", "verb": "get"},
                "effect": "hook",
                "hook": "t4_hook_sleep",
            }
        ],
    )
    eng = YamlRuleEngine(_loaded(pf), _no_refs)
    d = await eng.decide(_cmd(["kubectl", "get", "pods"]))
    assert d.effect == "deny"
    assert d.rule_id == "__fail_closed__"


async def test_hook_exception_is_fail_closed() -> None:
    pf = _pf(
        "pack",
        tool_family="kubectl",
        flags_allowed={"kubectl": ["--namespace"]},
        rules=[
            {
                "id": "hook-get",
                "match": {"argv0": "kubectl", "verb": "get"},
                "effect": "hook",
                "hook": "t4_hook_raise",
            }
        ],
    )
    eng = YamlRuleEngine(_loaded(pf), _no_refs)
    d = await eng.decide(_cmd(["kubectl", "get", "pods"]))
    assert d.effect == "deny"
    assert d.rule_id == "__fail_closed__"


async def test_unknown_hook_name_is_fail_closed() -> None:
    pf = _pf(
        "pack",
        tool_family="kubectl",
        flags_allowed={"kubectl": ["--namespace"]},
        rules=[
            {
                "id": "hook-get",
                "match": {"argv0": "kubectl", "verb": "get"},
                "effect": "hook",
                "hook": "t4_hook_does_not_exist",
            }
        ],
    )
    eng = YamlRuleEngine(_loaded(pf), _no_refs)
    d = await eng.decide(_cmd(["kubectl", "get", "pods"]))
    assert d.effect == "deny"
    assert d.rule_id == "__fail_closed__"


# --------------------------------------------------------------------------- resolver / context


class _ArmedResolver:
    """Resolves fine at construction; raises once armed (simulates a decide-time failure)."""

    def __init__(self) -> None:
        self.armed = False

    def __call__(self, ref: str) -> list[str]:
        if self.armed:
            raise RuntimeError("resolver blew up at decide time")
        return ["ok-context"]


def _context_pack() -> PolicyFile:
    return _pf(
        "base",
        rules=[
            {
                "id": "context-allowlist",
                "match": {
                    "argv0": "kubectl",
                    "flag_value_not_in": {"--context": "${targets.kubernetes.allowed_contexts}"},
                },
                "effect": "deny",
                "reason": "context must be allowlisted",
            }
        ],
    )


async def test_resolver_raising_at_decide_is_fail_closed() -> None:
    resolver = _ArmedResolver()
    eng = YamlRuleEngine(_loaded(_context_pack()), resolver)  # construction resolves fine
    resolver.armed = True
    d = await eng.decide(_cmd(["kubectl", "get", "pods", "--context", "whatever"]))
    assert d.effect == "deny"
    assert d.rule_id == "__fail_closed__"


async def test_empty_resolved_context_list_denies_any_context() -> None:
    def empty_resolver(_ref: str) -> list[str]:
        return []

    eng = YamlRuleEngine(_loaded(_context_pack()), empty_resolver)
    d = await eng.decide(_cmd(["kubectl", "get", "pods", "--context", "anything"]))
    assert d.effect == "deny"
    assert d.rule_id == "context-allowlist"


async def test_construction_raises_on_unresolvable_ref() -> None:
    def bad_resolver(_ref: str) -> list[str]:
        raise KeyError("no such config key")

    with pytest.raises(ValueError, match="cannot be resolved"):
        YamlRuleEngine(_loaded(_context_pack()), bad_resolver)
