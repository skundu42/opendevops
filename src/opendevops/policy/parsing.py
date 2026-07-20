"""argv parsing + short-flag canonicalization (T3).

The policy layer is argv-only: there is no shell string and no shell parser anywhere in
the system (see PLAN.md §1). This module turns a raw ``list[str]`` argv into a structured
``ParsedArgv`` whose flags are *canonicalized to their long form* so a single rule can
match ``-n`` and ``--namespace`` alike.

Fail-closed contract: any structural surprise raises :class:`ParseError`. The engine treats
a ParseError as ``deny(fail-closed)`` — so parsing must never guess. Unknown *long* flags
are the one deliberate exception: they parse as boolean and are then rejected downstream by
each pack's ``flags_allowed`` allowlist (this module never allows anything; it only shapes).
This coupling is intentional — an unknown long flag is harmless here precisely because the
loader guarantees every allowed binary has a ``flags_allowed`` entry that will deny it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

# --------------------------------------------------------------------------------------
# alias tables: short flag -> (long flag, takes_value)
# --------------------------------------------------------------------------------------

# Per-binary short-flag alias tables. Keyed by the short flag *as written* (``"-n"``).
ALIAS_TABLES: dict[str, dict[str, tuple[str, bool]]] = {
    "kubectl": {
        "-n": ("--namespace", True),
        "-o": ("--output", True),
        "-l": ("--selector", True),
        "-A": ("--all-namespaces", False),
        "-s": ("--server", True),
        "-f": ("--filename", True),
        "-k": ("--kustomize", True),
        "-c": ("--container", True),
        "-p": ("--previous", False),  # kubectl logs
        "-w": ("--watch", False),
        "-R": ("--recursive", False),
    },
    "helm": {
        "-n": ("--namespace", True),
        "-f": ("--values", True),
        "-o": ("--output", True),
        "-A": ("--all-namespaces", False),
    },
    "gh": {
        "-R": ("--repo", True),
        "-L": ("--limit", True),
        # gh api write flags (P5f). -X sets the HTTP METHOD; -F/-f pass body fields. Registered
        # value-taking so the operand is CONSUMED (never leaked into positionals where it could be
        # misread as the api PATH). The method+path allowlist is enforced by the engine's gh_api
        # predicate off the canonicalized --method flag + the first positional.
        "-X": ("--method", True),
        "-F": ("--field", True),
        "-f": ("--raw-field", True),
    },
    # az uses single-dash short flags heavily; register the value-taking ones the read pack
    # relies on so `-n foo`/`-g rg`/`-o json` canonicalize (and their operand is CONSUMED, never
    # left as a stray positional that could be misread as the action verb).
    "az": {
        "-n": ("--name", True),
        "-g": ("--resource-group", True),
        "-o": ("--output", True),
    },
}

# Per-binary sets of *long* flags that take a value, needed to parse the ``--k v`` form
# (as opposed to ``--k=v``, which is unambiguous). Must include every value-taking flag
# named in the shipped packs plus every value-taking alias target above, plus the
# credential/identity flags the base pack denies (so their operand is consumed as a value
# rather than misparsed as a positional).
VALUE_FLAGS: dict[str, set[str]] = {
    "kubectl": {
        # alias targets that take values
        "--namespace",
        "--output",
        "--selector",
        "--server",
        "--filename",
        "--kustomize",
        "--container",
        # flags_allowed (kubectl-read pack) that take values
        "--context",
        "--tail",
        "--since",
        "--field-selector",
        "--sort-by",
        # flags_allowed (kubectl-mutate pack, P2) that take values
        "--dry-run",
        "--replicas",
        "--to-revision",
        "--current-replicas",
        "--resource-version",
        # credential/identity flags denied by base.yaml (consume their operand)
        "--kubeconfig",
        "--token",
        "--as",
        "--as-group",
    },
    "helm": {
        "--namespace",
        "--values",
        "--output",
        # flags_allowed (helm-read pack, P2) that take values
        "--max",
        "--filter",
        "--revision",
        "--kubeconfig",
        "--kube-context",
        "--kube-token",
        "--kube-apiserver",
    },
    "gh": {
        "--repo",
        "--limit",
        # flags_allowed (gh-read pack, P2) that take values. --branch is long-only:
        # gh's short -b/-B/-H are pr-create flags we never allow, so no alias for it.
        "--json",
        "--jq",
        "--branch",
        "--workflow",
        "--hostname",
        # gh-write pack (P5f). gh api write flags (method + body) and the gh pr create form's
        # value flags — every one MUST consume its operand so a value can never leak into
        # `positionals` and be misread as the gh api PATH (the gh_api predicate keys the METHOD on
        # --method and the PATH on positionals[0]). --draft is boolean (no value) so it is NOT here.
        "--method",
        "--input",
        "--field",
        "--raw-field",
        "--title",
        "--body",
        "--base",
        "--head",
    },
    # Cloud CLIs (P5a). These CLIs use MANY value-taking flags in `--flag value` (space) form;
    # every one MUST be listed here so its operand is consumed as the flag's value and never
    # leaks into `positionals`. A leaked operand is a security hole: with the action pinned by
    # position (aws: first_positional; gcloud/az: last_positional), a value like
    # `--stack-name describe-stacks` on a `delete-stack` must NOT drop `describe-stacks` into
    # positionals where a read-action allow could see it. The lists are intentionally generous
    # (identity/endpoint flags the base pack DENIES are included too, so their operand is
    # consumed rather than misparsed). Fail-closed backstop: even an UNLISTED value-flag cannot
    # smuggle a read token into the ACTION position, because the action is pinned positionally
    # and a leaked operand lands as an extra trailing/leading positional, not as the verb.
    "aws": {
        # global / output / pagination / query
        "--region",
        "--profile",
        "--output",
        "--query",
        "--endpoint-url",
        "--page-size",
        "--max-items",
        "--max-results",
        "--starting-token",
        "--next-token",
        "--cli-input-json",
        "--cli-read-timeout",
        "--cli-connect-timeout",
        "--color",
        "--ca-bundle",
        "--filters",
        "--filter",
        "--filter-pattern",
        "--parameter-filters",
        # resource selectors / identifiers (value-taking)
        "--stack-name",
        "--table-name",
        "--function-name",
        "--db-instance-identifier",
        "--db-cluster-identifier",
        "--db-snapshot-identifier",
        "--instance-ids",
        "--instance-id",
        "--cluster-name",
        "--cluster",
        "--clusters",
        "--services",
        "--service",
        "--task-definition",
        "--bucket",
        "--key",
        "--key-id",
        "--prefix",
        "--name",
        "--names",
        "--path",
        "--secret-id",
        "--ciphertext-blob",
        "--alias-name",
        "--volume-ids",
        "--snapshot-ids",
        "--image-ids",
        "--image-id",
        "--subnet-ids",
        "--vpc-ids",
        "--group-ids",
        "--group-names",
        "--user-name",
        "--role-name",
        "--policy-arn",
        "--load-balancer-arns",
        "--target-group-arn",
        "--queue-url",
        "--topic-arn",
        "--resource-arn",
        "--log-group-name",
        "--log-stream-name",
        "--log-stream-names",
        "--namespace",
        "--metric-name",
        "--alarm-names",
        "--statistics",
        "--period",
        "--start-time",
        "--end-time",
        "--hostname",
    },
    "gcloud": {
        # global flags (identity/scope) — several are DENIED by base.yaml; listed so their
        # operand is consumed rather than left as a positional.
        "--project",
        "--account",
        "--impersonate-service-account",
        "--configuration",
        "--format",
        "--filter",
        "--limit",
        "--page-size",
        "--sort-by",
        "--region",
        "--zone",
        "--location",
        "--verbosity",
        # common command-scoped value flags
        "--secret",
        "--member",
        "--role",
        "--key",
        "--keyring",
        "--iam-account",
        "--instance",
        "--cluster",
    },
    "az": {
        # alias targets that take values
        "--name",
        "--resource-group",
        "--output",
        # global / scope flags (— --subscription is DENIED by base.yaml; consume its operand)
        "--subscription",
        "--query",
        "--ids",
        # common command-scoped value flags
        "--location",
        "--tag",
        "--vault-name",
        "--file",
        "--namespace",
        "--account-name",
        "--server",
        "--id",
        "--sku",
    },
}

# Binaries whose first non-flag token is a subcommand ``verb`` (kubectl get, gh pr, ...).
# For any other binary the first non-flag token is an ordinary positional and ``verb`` is
# left None.
#
# The cloud CLIs (aws/gcloud/az) are included so their first non-flag token becomes ``verb``
# (aws: the SERVICE, e.g. ``ec2``; gcloud/az: the top GROUP, e.g. ``compute``/``vm``). This is
# what lets the packs pin the ACTION at its real position instead of matching a read token at
# ANY positional depth (the P5a fail-open). For aws the action is then ``positionals[0]``
# (``first_positional``); for gcloud/az the action is the LAST positional (``last_positional``),
# because their groups nest to a variable depth. See the pack headers for the full rationale.
SUBCOMMAND_BINARIES: frozenset[str] = frozenset(
    {"kubectl", "helm", "gh", "aws", "gcloud", "az"}
)


class ParseError(Exception):
    """Raised on any structural surprise in an argv. The engine maps this to fail-closed deny."""


@dataclass(frozen=True)
class ParsedArgv:
    """Structured argv: canonicalized long-form flags, subcommand verb, and positionals."""

    argv0: str
    verb: str | None
    flags: dict[str, str | bool] = field(default_factory=dict)
    positionals: list[str] = field(default_factory=list)


def _record(flags: dict[str, str | bool], seen: set[str], name: str, value: str | bool) -> None:
    """Set a flag, raising on repeats (nothing in our packs legitimately repeats a flag)."""
    if name in seen:
        raise ParseError(f"flag {name!r} appears more than once")
    seen.add(name)
    flags[name] = value


def parse_argv(argv: list[str]) -> ParsedArgv:
    """Parse an argv into a :class:`ParsedArgv`, canonicalizing short flags to long form.

    Handles ``--k=v``, ``--k v`` (when ``k`` is a known value-taking flag), short flags via
    the per-binary :data:`ALIAS_TABLES`, and ``--`` as the end-of-flags marker. Raises
    :class:`ParseError` on: empty argv, a non-string element, an unknown short flag, a
    combined/attached short flag (``-An``, ``-nweb``), a repeated flag, or a value-taking
    flag with no operand.
    """
    if not isinstance(argv, list) or not argv:
        raise ParseError("empty argv")
    for tok in argv:
        if not isinstance(tok, str):
            raise ParseError(f"non-string argv element: {tok!r}")

    # basename()+lower() here is a policy-matching normalization ONLY (so a rule keyed on
    # "kubectl" matches "/usr/local/bin/kubectl" and "KUBECTL" alike) — it is not, and must
    # never be treated as, a sanitization step. The executor must never execute a
    # caller-supplied path: T5's tool boundary independently rejects any argv0 containing "/"
    # before this module ever sees it. This module's basename() and T5's path rejection are
    # meant to agree (both resolve to "the same bare binary name is what's allowed to run");
    # if that symmetry ever drifts, this line could start matching policy against a binary
    # name that the executor would refuse to run (or vice versa), so treat any change here as
    # load-bearing for T5 too.
    #
    # Case-fold (.lower()): argv0 is lowercased so "BASH"/"KUBECTL"/"Kubectl" resolve to the
    # same alias/value tables and canonical name the packs are keyed on (all lowercase). We
    # lower() ONLY — no suffix stripping — so "Bash.exe" -> "bash.exe" stays outside every
    # allow/deny list and lands on default-deny, as intended.
    #
    # LOAD-BEARING COUPLING with the engine (engine.py `_decide_argv`): the engine reads
    # argv0 itself (os.path.basename(argv[0])) for its pre-parse argv0-only deny and
    # default-deny short-circuits, BEFORE this parser runs. That path must apply the SAME
    # .lower() normalization or a mixed-case interpreter/binary (e.g. "BASH") short-circuits
    # to __default_deny__ instead of hitting its real rule id (interpreters-hard-deny).
    argv0 = os.path.basename(argv[0]).lower()
    aliases = ALIAS_TABLES.get(argv0, {})
    value_flags = VALUE_FLAGS.get(argv0, set())
    has_verb = argv0 in SUBCOMMAND_BINARIES

    verb: str | None = None
    flags: dict[str, str | bool] = {}
    positionals: list[str] = []
    seen: set[str] = set()

    i = 1
    end_of_flags = False
    while i < len(argv):
        tok = argv[i]

        if end_of_flags:
            positionals.append(tok)
            i += 1
            continue

        if tok == "--":
            end_of_flags = True
            i += 1
            continue

        if tok.startswith("--"):
            name, sep, inline_val = tok.partition("=")
            if sep:  # --k=v
                _record(flags, seen, name, inline_val)
                i += 1
            elif name in value_flags:  # --k v
                if i + 1 >= len(argv):
                    raise ParseError(f"flag {name!r} expects a value")
                _record(flags, seen, name, argv[i + 1])
                i += 2
            else:  # boolean (known bool flag or unknown long flag)
                _record(flags, seen, name, True)
                i += 1
            continue

        if tok.startswith("-") and tok != "-":
            if len(tok) != 2:
                raise ParseError(f"combined/attached short flags are not supported: {tok!r}")
            if tok not in aliases:
                raise ParseError(f"unknown short flag {tok!r} for {argv0!r}")
            long_flag, takes_value = aliases[tok]
            if takes_value:
                if i + 1 >= len(argv):
                    raise ParseError(f"short flag {tok!r} expects a value")
                _record(flags, seen, long_flag, argv[i + 1])
                i += 2
            else:
                _record(flags, seen, long_flag, True)
                i += 1
            continue

        # non-flag token: the subcommand verb (once) or a positional
        if has_verb and verb is None:
            verb = tok
        else:
            positionals.append(tok)
        i += 1

    return ParsedArgv(argv0=argv0, verb=verb, flags=flags, positionals=positionals)


def match_resource(positionals: list[str], resource_any: list[str]) -> bool:
    """True if any positional names a resource type in ``resource_any`` (k8s TYPE[/NAME]).

    Conservative: checks *every* positional, splits comma lists (``po,secrets``), then
    normalizes each candidate to its bare resource name before comparing case-insensitively.

    kubectl accepts fully-qualified resource forms ``RESOURCE[.VERSION[.GROUP]][/NAME]``
    (e.g. ``secret.v1.core/foo``, ``secrets.``) — comparing the raw token-before-``/`` by
    exact equality would let those slip past a deny (or admit them past an allow) because
    ``"secret.v1.core" != "secret"``. So each token is normalized as
    ``token.split("/")[0].split(".")[0].lower()``: take the part before ``/`` (dropping the
    NAME), then the part before the first ``.`` (dropping VERSION/GROUP). This is precise,
    not overbroad — it only strips the trailing qualifiers kubectl itself recognizes, so a
    positional like ``deployment/secret-config`` still normalizes to ``deployment``, not
    ``secret-config``.
    """
    wanted = {r.lower() for r in resource_any}
    for pos in positionals:
        for part in pos.split(","):
            token = part.strip().split("/", 1)[0].split(".", 1)[0].lower()
            if token and token in wanted:
                return True
    return False
