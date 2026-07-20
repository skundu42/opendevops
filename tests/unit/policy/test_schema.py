"""Schema validation tests: effect/payload invariants, StrMatcher, Decision, constants."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from opendevops.policy.schema import (
    RESERVED_RULE_IDS,
    RULE_DEFAULT_DENY,
    RULE_FAIL_CLOSED,
    RULE_FLAG_NOT_ALLOWED,
    RULE_REWRITE_DIVERGED,
    RULE_UNKNOWN_TOOL,
    Decision,
    Match,
    PolicyFile,
    Rule,
    StrMatcher,
    ToolCallCtx,
)


def _min_deny_rule(**over: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": "some-deny",
        "match": {"argv0": "kubectl"},
        "effect": "deny",
        "reason": "nope",
    }
    base.update(over)
    return base


# --------------------------------------------------------------------------- StrMatcher


def test_str_matcher_plain_string_is_eq() -> None:
    m = Match.model_validate({"tool_name": "execute"})
    assert isinstance(m.tool_name, StrMatcher)
    assert m.tool_name.eq == "execute"
    assert m.tool_name.matches("execute")
    assert not m.tool_name.matches("other")


def test_str_matcher_in_form() -> None:
    m = Match.model_validate({"verb": {"in": ["get", "describe"]}})
    assert m.verb is not None
    assert m.verb.matches("get")
    assert m.verb.matches("describe")
    assert not m.verb.matches("delete")
    assert m.verb.values() == ["get", "describe"]


def test_str_matcher_eq_object_form() -> None:
    m = Match.model_validate({"argv0": {"eq": "kubectl"}})
    assert m.argv0 is not None
    assert m.argv0.matches("kubectl")
    assert m.argv0.values() == ["kubectl"]


def test_first_positional_matcher_field() -> None:
    # additive Match field for sub-subcommand scoping (gh pr view). Accepts the same
    # StrMatcher sugar (bare string -> eq, {in: [...]}) as the other matchers.
    m = Match.model_validate({"verb": {"eq": "pr"}, "first_positional": {"in": ["view", "list"]}})
    assert m.first_positional is not None
    assert m.first_positional.matches("view")
    assert m.first_positional.matches("list")
    assert not m.first_positional.matches("merge")

    m2 = Match.model_validate({"first_positional": "status"})
    assert m2.first_positional is not None
    assert m2.first_positional.eq == "status"


def test_first_positional_absent_is_none() -> None:
    m = Match.model_validate({"argv0": "gh", "verb": "pr"})
    assert m.first_positional is None


def test_str_matcher_requires_exactly_one() -> None:
    with pytest.raises(ValidationError):
        StrMatcher()
    with pytest.raises(ValidationError):
        StrMatcher.model_validate({"eq": "a", "in": ["b"]})


# --------------------------------------------------------------------------- Rule payloads


def test_allow_without_channel_rejected() -> None:
    with pytest.raises(ValidationError):
        Rule.model_validate({"id": "r", "match": {"argv0": "kubectl"}, "effect": "allow"})


def test_allow_with_channel_ok() -> None:
    r = Rule.model_validate(
        {"id": "r", "match": {"argv0": "kubectl"}, "effect": "allow", "channel": "ro"}
    )
    assert r.channel == "ro"


def test_rewrite_payload_on_non_rewrite_rejected() -> None:
    with pytest.raises(ValidationError):
        Rule.model_validate(_min_deny_rule(rewrite={"inject_flags": ["--dry-run"]}))


def test_rewrite_requires_payload() -> None:
    with pytest.raises(ValidationError):
        Rule.model_validate({"id": "r", "match": {}, "effect": "rewrite"})


def test_rewrite_ok() -> None:
    r = Rule.model_validate(
        {
            "id": "r",
            "match": {"argv0": "kubectl"},
            "effect": "rewrite",
            "rewrite": {"inject_flags": ["--dry-run=server"]},
        }
    )
    assert r.rewrite is not None
    assert r.rewrite.inject_flags == ["--dry-run=server"]


def test_hook_payload_iff_effect() -> None:
    with pytest.raises(ValidationError):
        Rule.model_validate(_min_deny_rule(hook="my_hook"))
    with pytest.raises(ValidationError):
        Rule.model_validate({"id": "r", "match": {}, "effect": "hook"})
    ok = Rule.model_validate({"id": "r", "match": {}, "effect": "hook", "hook": "my_hook"})
    assert ok.hook == "my_hook"


def test_escalation_payload_iff_effect() -> None:
    with pytest.raises(ValidationError):
        Rule.model_validate(_min_deny_rule(escalation={"timeout_s": 30, "on_timeout": "deny"}))
    with pytest.raises(ValidationError):
        # escalate needs an escalation payload...
        Rule.model_validate({"id": "r", "match": {}, "effect": "escalate", "channel": "rw"})
    with pytest.raises(ValidationError):
        # ...AND a channel (an approved escalation executes).
        Rule.model_validate(
            {
                "id": "r",
                "match": {},
                "effect": "escalate",
                "escalation": {"timeout_s": 30, "on_timeout": "deny"},
            }
        )
    ok = Rule.model_validate(
        {
            "id": "r",
            "match": {},
            "effect": "escalate",
            "channel": "rw",
            "escalation": {"timeout_s": 30, "on_timeout": "deny"},
        }
    )
    assert ok.escalation is not None
    assert ok.escalation.timeout_s == 30
    assert ok.channel == "rw"


# --------------------------------------------------------------------------- extra=forbid


def test_extra_key_on_rule_rejected() -> None:
    with pytest.raises(ValidationError):
        Rule.model_validate(_min_deny_rule(bogus=1))


def test_extra_key_on_match_rejected() -> None:
    with pytest.raises(ValidationError):
        Match.model_validate({"argv0": "kubectl", "nope": True})


# ---------------------------------------------------------------- gh_api predicate (gh-write)


def test_gh_api_valid_forms() -> None:
    # each individual constraint is a valid gh_api predicate on its own.
    Match.model_validate({"argv0": "gh", "verb": "api", "gh_api": {"methods": ["POST", "PUT"]}})
    Match.model_validate(
        {
            "argv0": "gh",
            "verb": "api",
            "gh_api": {
                "methods": ["POST"],
                "repo_prefix_from": "${targets.github.write_repos}",
            },
        }
    )
    Match.model_validate({"argv0": "gh", "gh_api": {"path_prefix_any": ["orgs/"]}})
    Match.model_validate({"argv0": "gh", "gh_api": {"path_contains_any": ["actions/secrets"]}})
    Match.model_validate(
        {
            "argv0": "gh",
            "verb": "api",
            "gh_api": {
                "methods": ["POST"],
                "repo_prefix_from": "${targets.github.write_repos}",
                "repo_subpath_prefix_any": ["contents", "pulls"],
            },
        }
    )


def test_gh_api_requires_at_least_one_constraint() -> None:
    with pytest.raises(ValidationError):
        Match.model_validate({"argv0": "gh", "gh_api": {}})


def test_gh_api_empty_list_rejected() -> None:
    with pytest.raises(ValidationError):
        Match.model_validate({"argv0": "gh", "gh_api": {"methods": []}})
    with pytest.raises(ValidationError):
        Match.model_validate({"argv0": "gh", "gh_api": {"path_contains_any": [""]}})
    with pytest.raises(ValidationError):
        Match.model_validate({"argv0": "gh", "gh_api": {"repo_subpath_prefix_any": []}})
    with pytest.raises(ValidationError):
        Match.model_validate({"argv0": "gh", "gh_api": {"repo_subpath_prefix_any": [""]}})


def test_gh_api_extra_key_rejected() -> None:
    with pytest.raises(ValidationError):
        Match.model_validate({"argv0": "gh", "gh_api": {"methods": ["POST"], "nope": 1}})


def test_extra_key_on_policyfile_rejected() -> None:
    with pytest.raises(ValidationError):
        PolicyFile.model_validate(
            {
                "version": 1,
                "metadata": {"name": "n", "owner": "o", "updated": "2026-07-18"},
                "rules": [],
                "surprise": 1,
            }
        )


# --------------------------------------------------------------------------- id validation


def test_kebab_id_required() -> None:
    for bad in ["Bad_Id", "bad id", "UPPER", "trailing-", "-leading", "__default_deny__"]:
        with pytest.raises(ValidationError):
            Rule.model_validate(_min_deny_rule(id=bad))
    ok = Rule.model_validate(_min_deny_rule(id="good-kebab-1"))
    assert ok.id == "good-kebab-1"


# --------------------------------------------------------------------------- PolicyFile


def test_policyfile_minimal_valid() -> None:
    pf = PolicyFile.model_validate(
        {
            "version": 1,
            "metadata": {"name": "n", "owner": "o", "updated": "2026-07-18"},
            "rules": [_min_deny_rule()],
        }
    )
    assert pf.version == 1
    assert len(pf.rules) == 1


def test_policyfile_bad_version_rejected() -> None:
    with pytest.raises(ValidationError):
        PolicyFile.model_validate(
            {
                "version": 2,
                "metadata": {"name": "n", "owner": "o", "updated": "x"},
                "rules": [],
            }
        )


# --------------------------------------------------------------------------- Decision + constants


def test_decision_constructors() -> None:
    d = Decision.deny("some-rule", "because", hint="try this")
    assert d.effect == "deny"
    assert d.rule_id == "some-rule"
    assert d.reason == "because"
    assert d.hint == "try this"

    a = Decision.allow("r", "ok", channel="ro")
    assert a.effect == "allow"
    assert a.channel == "ro"

    rw = Decision.rewrite("r", "ok", rewritten_argv=["kubectl", "get", "pods"])
    assert rw.effect == "rewrite"
    assert rw.rewritten_argv == ["kubectl", "get", "pods"]

    esc = Decision.escalate("r", "ask a human")
    assert esc.effect == "escalate"

    hk = Decision.hook("r", "run hook")
    assert hk.effect == "hook"


def test_reserved_rule_id_constants() -> None:
    assert RULE_DEFAULT_DENY == "__default_deny__"
    assert RULE_UNKNOWN_TOOL == "__unknown_tool__"
    assert RULE_FAIL_CLOSED == "__fail_closed__"
    assert RULE_FLAG_NOT_ALLOWED == "__flag_not_allowed__"
    assert RULE_REWRITE_DIVERGED == "__rewrite_diverged__"
    assert RULE_DEFAULT_DENY in RESERVED_RULE_IDS
    assert len(RESERVED_RULE_IDS) == 5


def test_toolcallctx_shape() -> None:
    ctx = ToolCallCtx(
        tool_name="run_command",
        args={"argv": ["kubectl", "get", "pods"]},
        argv0="kubectl",
        verb="get",
        flags={"--namespace": "web", "--all-namespaces": True},
        positionals=["pods"],
        environment="staging",
        principal="alice",
        run_id="run-1",
    )
    assert ctx.flags["--namespace"] == "web"
    assert ctx.flags["--all-namespaces"] is True
