"""argv parsing tests: short-flag canonicalization, value forms, fail-closed, resources."""

from __future__ import annotations

import pytest

from opendevops.policy.parsing import ParseError, match_resource, parse_argv


def test_basename_argv0() -> None:
    p = parse_argv(["/usr/local/bin/kubectl", "get", "pods"])
    assert p.argv0 == "kubectl"
    assert p.verb == "get"
    assert p.positionals == ["pods"]


def test_short_flag_canonicalization_namespace() -> None:
    p = parse_argv(["kubectl", "-n", "web", "get", "pods"])
    assert p.flags == {"--namespace": "web"}
    assert p.verb == "get"
    assert p.positionals == ["pods"]


def test_short_flag_server_value() -> None:
    p = parse_argv(["kubectl", "-s", "https://x", "get", "pods"])
    assert p.flags["--server"] == "https://x"


def test_short_bool_flag() -> None:
    p = parse_argv(["kubectl", "get", "pods", "-A"])
    assert p.flags["--all-namespaces"] is True


def test_long_flag_eq_form() -> None:
    p = parse_argv(["kubectl", "get", "pods", "--output=wide"])
    assert p.flags["--output"] == "wide"


def test_long_flag_space_form() -> None:
    p = parse_argv(["kubectl", "get", "pods", "--namespace", "web"])
    assert p.flags["--namespace"] == "web"


def test_unknown_long_flag_is_boolean() -> None:
    p = parse_argv(["kubectl", "get", "pods", "--totally-unknown"])
    assert p.flags["--totally-unknown"] is True


def test_double_dash_ends_flag_parsing() -> None:
    p = parse_argv(["kubectl", "get", "pods", "--", "--not-a-flag", "-x"])
    assert "--not-a-flag" in p.positionals
    assert "-x" in p.positionals
    assert "--not-a-flag" not in p.flags


def test_unknown_short_flag_raises() -> None:
    with pytest.raises(ParseError):
        parse_argv(["kubectl", "-Z", "get", "pods"])


def test_combined_short_flags_raise() -> None:
    with pytest.raises(ParseError):
        parse_argv(["kubectl", "-An", "get"])


def test_repeated_flag_raises() -> None:
    with pytest.raises(ParseError):
        parse_argv(["kubectl", "get", "pods", "-n", "a", "-n", "b"])


def test_repeated_long_flag_raises() -> None:
    with pytest.raises(ParseError):
        parse_argv(["kubectl", "get", "pods", "--namespace", "a", "--namespace", "b"])


def test_empty_argv_raises() -> None:
    with pytest.raises(ParseError):
        parse_argv([])


def test_non_string_element_raises() -> None:
    with pytest.raises(ParseError):
        parse_argv([123, "get"])  # type: ignore[list-item]


def test_value_flag_missing_value_raises() -> None:
    with pytest.raises(ParseError):
        parse_argv(["kubectl", "get", "pods", "--namespace"])


def test_helm_short_flags() -> None:
    p = parse_argv(["helm", "-n", "web", "list"])
    assert p.flags["--namespace"] == "web"
    assert p.verb == "list"


def test_gh_short_repo() -> None:
    p = parse_argv(["gh", "pr", "list", "-R", "org/repo"])
    assert p.verb == "pr"
    assert p.flags["--repo"] == "org/repo"
    assert p.positionals == ["list"]


def test_non_subcommand_binary_has_no_verb() -> None:
    p = parse_argv(["bash", "script.sh"])
    assert p.verb is None
    assert p.positionals == ["script.sh"]


# --------------------------------------------------------------------------- match_resource


def test_match_resource_plain() -> None:
    assert match_resource(["secrets"], ["secret", "secrets"])
    assert match_resource(["secret"], ["secret", "secrets"])


def test_match_resource_type_slash_name() -> None:
    assert match_resource(["secret/foo"], ["secret", "secrets"])


def test_match_resource_comma_list() -> None:
    assert match_resource(["po,secrets"], ["secret", "secrets"])


def test_match_resource_case_insensitive() -> None:
    assert match_resource(["Secret"], ["secret", "secrets"])
    assert match_resource(["SECRETS/foo"], ["secret", "secrets"])


def test_match_resource_no_match() -> None:
    assert not match_resource(["pods"], ["secret", "secrets"])
    assert not match_resource([], ["secret", "secrets"])


def test_match_resource_later_positional() -> None:
    # conservative: any positional that looks like TYPE/NAME is checked
    assert match_resource(["foo", "secret/bar"], ["secret"])


def test_match_resource_versioned_group_with_name() -> None:
    # kubectl accepts RESOURCE.VERSION.GROUP/NAME; the bare resource name must still match.
    assert match_resource(["secret.v1.core/foo"], ["secret", "secrets"])


def test_match_resource_trailing_dot() -> None:
    assert match_resource(["secrets."], ["secret", "secrets"])


def test_match_resource_versioned_trailing_dot() -> None:
    assert match_resource(["secrets.v1."], ["secret", "secrets"])


def test_match_resource_comma_list_versioned() -> None:
    assert match_resource(["po,secrets.v1"], ["secret", "secrets"])


def test_match_resource_positional_name_not_bare_resource() -> None:
    # `deployment/secret-config` is a Deployment NAMED "secret-config" — the candidate
    # token is "deployment" (before "/"), not the resource's own name, so this must NOT
    # match a resource_any of ["secret"].
    assert not match_resource(["deployment/secret-config"], ["secret"])


# --------------------------------------------------------------------------- case-fold argv0


def test_argv0_is_lowercased() -> None:
    # argv0 is case-folded so a rule keyed on "kubectl" also matches "KUBECTL"/"Kubectl",
    # and the per-binary alias/value tables + subcommand handling apply to the folded name.
    p = parse_argv(["KUBECTL", "get", "secrets"])
    assert p.argv0 == "kubectl"
    assert p.verb == "get"
    assert p.positionals == ["secrets"]


def test_argv0_lowercased_with_path() -> None:
    p = parse_argv(["/usr/local/bin/Helm", "list"])
    assert p.argv0 == "helm"
    assert p.verb == "list"


def test_argv0_lower_only_no_suffix_strip() -> None:
    # lower() ONLY: "Bash.exe" -> "bash.exe" keeps the suffix, so it lands outside every
    # allow/deny list (default-deny), rather than being normalized to "bash".
    p = parse_argv(["Bash.exe", "script.sh"])
    assert p.argv0 == "bash.exe"


# ------------------------------------------------------------------ value-flag/alias tables


def test_kubectl_mutate_value_flags() -> None:
    p = parse_argv(["kubectl", "scale", "--replicas", "3", "deployment/api"])
    assert p.flags["--replicas"] == "3"
    assert p.positionals == ["deployment/api"]


def test_kubectl_to_revision_value_flag() -> None:
    p = parse_argv(["kubectl", "rollout", "undo", "deployment/api", "--to-revision", "2"])
    assert p.flags["--to-revision"] == "2"


def test_kubectl_dry_run_value_flag_space_form() -> None:
    p = parse_argv(["kubectl", "apply", "--dry-run", "server", "-f", "/x.yaml"])
    assert p.flags["--dry-run"] == "server"
    assert p.flags["--filename"] == "/x.yaml"


def test_kubectl_current_replicas_and_resource_version() -> None:
    p = parse_argv(
        ["kubectl", "scale", "--current-replicas", "2", "--resource-version", "42", "deploy/a"]
    )
    assert p.flags["--current-replicas"] == "2"
    assert p.flags["--resource-version"] == "42"


def test_helm_value_flags_and_all_namespaces_alias() -> None:
    p = parse_argv(["helm", "list", "--max", "5", "--filter", "web", "-A"])
    assert p.flags["--max"] == "5"
    assert p.flags["--filter"] == "web"
    assert p.flags["--all-namespaces"] is True


def test_helm_revision_value_flag() -> None:
    p = parse_argv(["helm", "get", "values", "rel", "--revision", "3"])
    assert p.flags["--revision"] == "3"
    assert p.positionals == ["values", "rel"]


def test_gh_value_flags() -> None:
    p = parse_argv(["gh", "pr", "list", "--json", "number", "--jq", ".[]", "--workflow", "ci"])
    assert p.flags["--json"] == "number"
    assert p.flags["--jq"] == ".[]"
    assert p.flags["--workflow"] == "ci"


def test_gh_branch_is_long_only_value_flag() -> None:
    p = parse_argv(["gh", "run", "list", "--branch", "main"])
    assert p.flags["--branch"] == "main"
    assert p.positionals == ["list"]


def test_gh_bool_flags_take_no_value() -> None:
    p = parse_argv(["gh", "run", "view", "--log-failed", "12345"])
    assert p.flags["--log-failed"] is True
    # value-less bool: the following token stays a positional (the first positional = "view")
    assert p.positionals == ["view", "12345"]
