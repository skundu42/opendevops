"""Pydantic policy schema: PolicyFile / Rule / Match / Decision / ToolCallCtx.

This module is the pure *data model* for the policy layer. It carries no decision
logic — the engine consumes these types but needs no change to this file. Every
model is ``extra="forbid"`` so an unexpected YAML key is a hard error, never a silent
no-op (fail-closed configuration).

Reserved ``rule_id`` values (below) name synthetic decisions the engine/middleware
emit at runtime; they never appear as authored ``Rule.id`` values (those are kebab-case
and this module rejects the dunder form).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    ValidationInfo,
    field_validator,
    model_validator,
)

# --------------------------------------------------------------------------------------
# primitive aliases
# --------------------------------------------------------------------------------------

Effect = Literal["allow", "deny", "rewrite", "escalate", "hook"]
Channel = Literal["ro", "rw"]

# Reserved synthetic rule ids (engine/middleware runtime decisions, never authored YAML).
RULE_DEFAULT_DENY = "__default_deny__"
RULE_UNKNOWN_TOOL = "__unknown_tool__"
RULE_FAIL_CLOSED = "__fail_closed__"
RULE_FLAG_NOT_ALLOWED = "__flag_not_allowed__"
RULE_REWRITE_DIVERGED = "__rewrite_diverged__"

RESERVED_RULE_IDS: frozenset[str] = frozenset(
    {
        RULE_DEFAULT_DENY,
        RULE_UNKNOWN_TOOL,
        RULE_FAIL_CLOSED,
        RULE_FLAG_NOT_ALLOWED,
        RULE_REWRITE_DIVERGED,
    }
)

# Authored rule ids must be kebab-case: lowercase alnum groups joined by single hyphens.
_KEBAB = r"^[a-z0-9]+(?:-[a-z0-9]+)*$"


# --------------------------------------------------------------------------------------
# StrMatcher — `eq` (a plain string) | `in` (a list)
# --------------------------------------------------------------------------------------


class StrMatcher(BaseModel):
    """Match a single string by equality (``eq``) or membership (``in``).

    In YAML a bare string is sugar for ``{eq: <string>}``; the ``{in: [...]}`` /
    ``{eq: ...}`` object forms are also accepted. Exactly one of the two must be set.
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    eq: str | None = None
    in_: list[str] | None = Field(default=None, alias="in")

    @model_validator(mode="after")
    def _exactly_one(self) -> StrMatcher:
        if (self.eq is None) == (self.in_ is None):
            raise ValueError("StrMatcher requires exactly one of 'eq' or 'in'")
        return self

    def matches(self, value: str) -> bool:
        """True if ``value`` satisfies this matcher."""
        if self.eq is not None:
            return value == self.eq
        return value in (self.in_ or [])

    def values(self) -> list[str]:
        """The literal string(s) this matcher references (``[eq]`` or the ``in`` list)."""
        if self.eq is not None:
            return [self.eq]
        return list(self.in_ or [])


def _coerce_str_matcher(v: Any) -> Any:
    """Sugar: a bare string becomes ``{eq: <string>}`` before StrMatcher validation."""
    if isinstance(v, str):
        return {"eq": v}
    return v


StrMatcherField = Annotated[StrMatcher, BeforeValidator(_coerce_str_matcher)]


# --------------------------------------------------------------------------------------
# GhApiMatch — the gh-write `gh api` METHOD+PATH allowlist predicate
# --------------------------------------------------------------------------------------


class GhApiMatch(BaseModel):
    """A structured predicate over a parsed ``gh api`` call (gh-write pack).

    Meaningful ONLY on a rule that also pins ``argv0: gh`` and ``verb: {eq: api}``; the engine's
    ``_rule_matches`` re-checks ``parsed.verb == "api"`` defensively before reading anything here.
    The METHOD is the canonicalized ``--method``/``-X`` flag value (default ``GET`` when absent);
    the PATH is the first positional after ``api`` (leading slashes stripped). All *present*
    fields are ANDed together (an absent field is a wildcard); at least one must be set. This is
    an ADDITIVE structured-tool matcher — it never touches gh-read's verb/first_positional
    matching, the run_command argv0 pipeline, or the ssh_run/subagent predicates.

    * ``methods`` — the request METHOD must be in this set (case-insensitive). The ALLOW pins
      ``[POST, PATCH, PUT]``; the narrowed gh-read ``gh-no-api`` deny pins ``[GET, HEAD]`` so
      reads stay denied without shadowing the write allow (deny > allow).
    * ``repo_prefix_from`` — a config-interpolation ref (like a ``flag_value_not_in`` value, e.g.
      ``"${targets.github.write_repos}"``) the engine resolves to an ``owner/repo`` allowlist. The
      PATH must be ``repos/<owner>/<repo>/<sub...>`` for an allowlisted ``owner/repo`` (a trailing
      sub-path is REQUIRED, so a bare ``/repos/{repo}`` never matches, and the ``/`` boundary
      stops ``org/x`` matching ``org/xyz``). Backs the write ALLOW.
    * ``repo_subpath_prefix_any`` — the POSITIVE sub-path allowlist UNDER an allowlisted repo. The
      remainder AFTER the matched ``repos/<owner>/<repo>/`` (what ``repo_prefix_from`` confirmed)
      must be one of these prefixes on a SEGMENT boundary — ``sub == p`` OR ``sub`` starts with
      ``p + "/"`` — so ``["contents", "pulls"]`` matches ``pulls``/``pulls/1``/``contents/app.py``
      but NOT ``pullspam`` or ``keys``. Meaningful ONLY together with ``repo_prefix_from`` (it
      reuses that repo allowlist); the engine fails closed when ``repo_prefix_from`` is unset. This
      turns the write ALLOW from a repo-scoped DENYLIST (any sub-path under an allowlisted repo)
      into a fail-closed POSITIVE allowlist (only the enumerated write endpoints), default-denying
      keys/hooks/collaborators/secrets/branch-protection/merges/git-refs/releases/etc.
    * ``path_prefix_any`` — the normalized PATH must START WITH one of these literal prefixes
      (e.g. ``orgs/``). Anchored, so it cannot false-fire on a repo sub-path that merely contains
      the token. Backs the ``/orgs/*`` audit-clarity DENY.
    * ``path_contains_any`` — the normalized PATH must CONTAIN one of these substrings (e.g.
      ``actions/secrets``). Backs the load-bearing ``actions/secrets`` DENY that overrides the
      repo-prefix ALLOW (deny > allow) so a write to secrets under an allowlisted repo is refused.
    """

    model_config = ConfigDict(extra="forbid")

    methods: list[str] | None = None
    repo_prefix_from: str | None = None
    repo_subpath_prefix_any: list[str] | None = None
    path_prefix_any: list[str] | None = None
    path_contains_any: list[str] | None = None

    @model_validator(mode="after")
    def _at_least_one_non_empty(self) -> GhApiMatch:
        if (
            self.methods is None
            and self.repo_prefix_from is None
            and self.repo_subpath_prefix_any is None
            and self.path_prefix_any is None
            and self.path_contains_any is None
        ):
            raise ValueError(
                "gh_api requires at least one of methods / repo_prefix_from / "
                "repo_subpath_prefix_any / path_prefix_any / path_contains_any"
            )
        for name in ("methods", "repo_subpath_prefix_any", "path_prefix_any", "path_contains_any"):
            val: list[str] | None = getattr(self, name)
            if val is None:
                continue
            if not val:
                raise ValueError(f"gh_api.{name} must not be empty")
            if any(not entry for entry in val):
                raise ValueError(f"gh_api.{name} entries must be non-empty")
        return self


# --------------------------------------------------------------------------------------
# Match
# --------------------------------------------------------------------------------------


class Match(BaseModel):
    """The predicate side of a rule. All fields optional; an absent field is a wildcard.

    ``flag_value_not_in`` values are raw config-interpolation references (e.g.
    ``"${targets.kubernetes.allowed_contexts}"``) stored verbatim — resolution happens
    at engine time, not here.
    """

    model_config = ConfigDict(extra="forbid")

    tool_name: StrMatcherField | None = None
    argv0: StrMatcherField | None = None
    verb: StrMatcherField | None = None
    # first_positional matches the FIRST positional after the subcommand verb — i.e. a tool's
    # sub-subcommand (``gh pr view`` -> verb=pr, first_positional=view). Absent = wildcard.
    # NOTE: the predicate that enforces this lives in the engine's ``_rule_matches`` (engine.py);
    # this field only carries the matcher. A rule using it will not constrain the sub-subcommand
    # until the engine reads it.
    first_positional: StrMatcherField | None = None
    # last_positional matches the LAST positional (``positionals[-1]``). Added for the cloud
    # read packs: gcloud/az nest their command GROUPS to a variable depth, so the action verb
    # (``list``/``show``) cannot be pinned by a fixed FRONT index — but for a bare read it is the
    # final token (``az storage account list`` -> last=list). Pinning the read verb HERE (instead
    # of matching it at ANY positional via ``resource_any``) means an embedded/leaked read token
    # in an argument no longer fires the allow. Enforced in the engine's ``_rule_matches``.
    last_positional: StrMatcherField | None = None
    # second_last_positional matches positionals[-2]. Added for the gcloud `describe <NAME>`
    # read: gcloud puts the resource NAME *after* the verb, so a `describe` read is
    # `... describe <NAME>` where `describe` is the SECOND-TO-LAST positional and <NAME> trails it.
    # Pinning describe HERE (instead of `resource_any:[describe]`, which matched describe at ANY
    # positional — the clone-named-`describe` hole where an attacker names a mutation's target
    # `describe`, e.g. `gcloud sql instances clone prod-db describe`) means a trailing/embedded
    # `describe` on a mutation can no longer fire the read allow. Enforced in the engine's
    # ``_rule_matches`` (unsatisfiable when there are fewer than 2 positionals).
    second_last_positional: StrMatcherField | None = None
    flags_any: list[str] | None = None
    flags_absent: list[str] | None = None
    flag_value_not_in: dict[str, str] | None = None
    resource_any: list[str] | None = None
    # positional_verb_prefix_any DENIES (used only in deny rules) when ANY positional's prefix —
    # the part before the first '-' — is a mutation verb. gcloud/az mutations take BOTH bare
    # (`suspend`, `clone`) and COMPOUND `verb-noun` forms (`set-machine-type`, `add-metadata`,
    # `delete-access-config`, `reset-windows-password`); a bare-verb denylist can never enumerate
    # every noun, so this prefix guard denies the whole `set-*`/`add-*`/`delete-*`/... family
    # without listing each. Matched at the positional level in the engine's ``_rule_matches``;
    # additive (absent = wildcard), so rules that never set it (kubectl/gh/helm) are unaffected.
    positional_verb_prefix_any: list[str] | None = None
    # positional_seq_prefix_any ALLOWS (the fail-closed allowlist inversion for gcloud/az reads)
    # when the parsed positionals START WITH one of the listed EXACT sequences. Each sequence is a
    # curated read command path `[<subgroup...>, <read-verb>]` — e.g. `[instances, list]`,
    # `[instances, describe]`, `[account, list]`. A rule matches iff, for SOME listed sequence,
    # `positionals[:len(seq)] == seq`; positionals shorter than a sequence never match it
    # (fail-closed). Trailing positionals after the matched prefix (a resource NAME/filter for
    # `describe <NAME>` / `logging read <FILTER>` / `storage cat <URI>`) are allowed — the read verb
    # still sits at its DETERMINATE position, so an UNKNOWN verb (`frobnicate`) or an unlisted
    # mutation (`write`, `get-credentials`, `modify-push-config`) at that position cannot match.
    # This REPLACES the fail-open `last_positional`/`second_last_positional` gcloud/az read
    # matchers, which fired for ANY command ending in a read token (a denylist can never be
    # complete). Combined with `verb: <top-group>` in each rule so an unknown GROUP cannot match a
    # subgroup path. Matched in the engine's ``_rule_matches``; additive (absent = wildcard).
    positional_seq_prefix_any: list[list[str]] | None = None
    # ssh_run structured-tool predicates. ``ssh_run(host, argv)`` is NOT argv-only (there is
    # no ParsedArgv), so these read ``ctx.args`` DIRECTLY in the engine's ``_rule_matches`` — a
    # structured-tool matcher distinct from the argv0 pipeline, which they never touch. Additive
    # (absent = wildcard), so no existing run_command rule is affected. Both are meaningful only on
    # a rule that also pins ``tool_name: ssh_run``.
    #
    # ssh_host_in is a config-interpolation ref (like a ``flag_value_not_in`` value, e.g.
    # ``"${targets.ssh.hosts}"``) resolved by the engine to the allowed-host list — the SAME list
    # the tool re-validates against, so config is the single source of truth for the host allowlist.
    # A rule matches only when ``ctx.args["host"]`` is a non-empty string present in the list.
    ssh_host_in: str | None = None
    # ssh_remote_argv0 pins the remote program (``argv[0]``) to a curated read-command allowlist
    # (single-mode pure-read binaries: df / free / uptime / ...). Matched against the LITERAL
    # ``argv[0]``; an absent/empty argv, or an ``argv[0]`` not in the set, does not match
    # (fail-closed for the allow). It stays in active use for the vetted SINGLE-mode binaries — a
    # bare argv0 pin is safe only when the binary has no state-changing subcommand/flag.
    ssh_remote_argv0: StrMatcherField | None = None
    # ssh_remote_argv_seq_prefix_any ALLOWS (the multi-mode read-path allowlist, mirroring the
    # cloud-pack ``positional_seq_prefix_any`` inversion) when ``ctx.args["argv"]`` — the ssh_run
    # remote argv — STARTS WITH one of the listed EXACT sequences. Each sequence is a curated remote
    # read command PATH ``[<argv0>, <read-subcommand>]`` (e.g. ``[systemctl, status]``,
    # ``[systemctl, list-units]``). A pin on argv0 ALONE is fail-OPEN for a multi-mode binary
    # (``systemctl`` shares ``argv[0]`` with ``restart``/``poweroff``/``mask``), so those binaries
    # are pinned to their read PATH here instead. Reads ``ctx.args["argv"]`` DIRECTLY in the
    # engine's ``_rule_matches`` (a structured-tool matcher, distinct from the run_command
    # pipeline). Matching is fail-closed: a sequence longer than the argv never matches, and an
    # unknown/mutating subcommand at the verb position matches no sequence -> default-deny. Additive
    # (absent = wildcard); meaningful only on a rule that also pins ``tool_name: ssh_run``.
    ssh_remote_argv_seq_prefix_any: list[list[str]] | None = None
    # ssh_remote_flag_prefix_any DENIES (used only in deny rules) when ANY remote-argv token — its
    # part before ``=`` — starts with one of the listed flag prefixes. It is the compensating deny
    # for journalctl, whose MUTATING modes are FLAGS (``--vacuum-time=1s``, ``--rotate``,
    # ``--flush`` ...) that share ``argv[0]`` with its reads: the positive allowlist permits bare
    # ``[journalctl]`` and this deny (deny > allow) pins the destructive flags out. Reads
    # ``ctx.args["argv"]`` directly in the engine's ``_rule_matches``. Additive (absent = wildcard);
    # meaningful only on an ssh_run rule.
    ssh_remote_flag_prefix_any: list[str] | None = None
    # gh_api (gh-write) is a STRUCTURED matcher over a parsed ``gh api`` call: the METHOD
    # (``--method``/``-X``, default GET) and the PATH (first positional after ``api``). It reads
    # ``parsed`` in the engine's ``_rule_matches`` and is meaningful only on a rule that also pins
    # ``argv0: gh`` + ``verb: {eq: api}``. Backs BOTH the write ALLOW (methods + repo prefix) and
    # the airtight DENYs (reads, DELETE, /orgs, actions/secrets). Additive (absent = wildcard); no
    # existing kubectl/gh-read/cloud/ssh rule sets it. See :class:`GhApiMatch`.
    gh_api: GhApiMatch | None = None
    # subagent_type_not_in DENIES (used only in deny rules) the deepagents ``task`` tool for any
    # target subagent NOT in the listed allowlist. The ``task`` tool_call carries the target
    # in its ``subagent_type`` arg; this reads ``ctx.args["subagent_type"]`` DIRECTLY in the
    # engine's ``_rule_matches`` (a structured-tool matcher, distinct from the run_command
    # pipeline). Matching is fail-closed: a MISSING or non-string ``subagent_type`` is treated as
    # "not in the allowlist", so the deny fires — an un-named/arbitrary subagent stays denied. The
    # single allowed subagent (the log-summarizer) is permitted at the ENGINE level, not by an allow
    # rule here (base.yaml declares no tool_family). Additive (absent = wildcard); meaningful only
    # on a rule that also pins ``tool_name: task``.
    subagent_type_not_in: list[str] | None = None

    @field_validator("positional_seq_prefix_any", "ssh_remote_argv_seq_prefix_any")
    @classmethod
    def _non_empty_seqs(
        cls, v: list[list[str]] | None, info: ValidationInfo
    ) -> list[list[str]] | None:
        """Fail-loud at load: an empty outer list or an empty inner sequence is author error.

        An empty inner sequence would make ``argv[:0] == []`` true for EVERY argv (a match-all
        allow) — the exact fail-open these predicates exist to prevent — so reject it.
        """
        field = info.field_name
        if v is None:
            return v
        if not v:
            raise ValueError(f"{field} must not be empty")
        for seq in v:
            if not seq:
                raise ValueError(f"{field} sequences must be non-empty")
        return v

    @field_validator("ssh_remote_flag_prefix_any")
    @classmethod
    def _non_empty_flag_prefixes(cls, v: list[str] | None) -> list[str] | None:
        """Fail-loud at load: an empty list or an empty prefix entry is author error.

        An empty prefix entry would make ``head.startswith("")`` true for EVERY token (a match-all
        deny that would break the whole tool), so reject it just as the sequence validator does.
        """
        if v is None:
            return v
        if not v:
            raise ValueError("ssh_remote_flag_prefix_any must not be empty")
        for entry in v:
            if not entry:
                raise ValueError("ssh_remote_flag_prefix_any entries must be non-empty")
        return v


# --------------------------------------------------------------------------------------
# Rule payload sub-models
# --------------------------------------------------------------------------------------


class Rewrite(BaseModel):
    """Payload for an ``effect: rewrite`` rule: flags to inject into the argv."""

    model_config = ConfigDict(extra="forbid")

    inject_flags: list[str]


class Escalation(BaseModel):
    """Payload for an ``effect: escalate`` rule: how long to wait and the timeout action."""

    model_config = ConfigDict(extra="forbid")

    timeout_s: int
    on_timeout: Literal["deny"]


# NOTE: an *approved* escalation EXECUTES the tool, so an ``effect: escalate`` rule must
# carry a ``channel`` (which credential the post-approval execution uses) exactly like an allow.
# The requirement is enforced in ``Rule._check_effect_payloads`` below — an escalate rule
# authored without a channel fails validation loudly (the shipped pack sets it).


# --------------------------------------------------------------------------------------
# Rule
# --------------------------------------------------------------------------------------


class Rule(BaseModel):
    """A single policy rule: a ``Match`` predicate plus the ``Effect`` to apply.

    Invariants (validated): ``channel`` is required when ``effect=allow``; the
    ``rewrite`` / ``hook`` / ``escalation`` payload is present *iff* the matching effect
    is selected.
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=_KEBAB)
    match: Match
    effect: Effect
    channel: Channel | None = None
    environments: list[str] | None = None  # None = all environments
    reason: str | None = None
    hint: str | None = None
    rewrite: Rewrite | None = None
    hook: str | None = None
    escalation: Escalation | None = None

    @model_validator(mode="after")
    def _check_effect_payloads(self) -> Rule:
        if self.effect == "allow" and self.channel is None:
            raise ValueError("effect=allow requires 'channel'")
        if self.effect == "escalate" and self.channel is None:
            # An approved escalation executes the tool, so it needs a credential channel.
            raise ValueError("effect=escalate requires 'channel'")
        if (self.rewrite is not None) != (self.effect == "rewrite"):
            raise ValueError("'rewrite' payload must be present iff effect=rewrite")
        if (self.hook is not None) != (self.effect == "hook"):
            raise ValueError("'hook' must be present iff effect=hook")
        if (self.escalation is not None) != (self.effect == "escalate"):
            raise ValueError("'escalation' payload must be present iff effect=escalate")
        return self


# --------------------------------------------------------------------------------------
# PolicyFile
# --------------------------------------------------------------------------------------


class Metadata(BaseModel):
    """Provenance metadata for a policy file."""

    model_config = ConfigDict(extra="forbid")

    name: str
    owner: str
    updated: str


class PolicyFile(BaseModel):
    """One on-disk policy document (``base.yaml``, a pack, or an env overlay)."""

    model_config = ConfigDict(extra="forbid")

    version: Literal[1]
    metadata: Metadata
    tool_family: str | None = None
    flags_allowed: dict[str, list[str]] | None = None
    rules: list[Rule]
    acknowledged_default_deny: list[str] | None = None


# --------------------------------------------------------------------------------------
# Decision — the engine's output (also constructed by middleware for synthetic denies)
# --------------------------------------------------------------------------------------


class Decision(BaseModel):
    """The result of authorizing a tool call. Constructed by the engine and middleware."""

    model_config = ConfigDict(extra="forbid")

    effect: Effect
    rule_id: str
    reason: str
    channel: Channel | None = None
    rewritten_argv: list[str] | None = None
    hint: str | None = None

    @classmethod
    def deny(cls, rule_id: str, reason: str, hint: str | None = None) -> Decision:
        return cls(effect="deny", rule_id=rule_id, reason=reason, hint=hint)

    @classmethod
    def allow(
        cls, rule_id: str, reason: str, channel: Channel, hint: str | None = None
    ) -> Decision:
        return cls(effect="allow", rule_id=rule_id, reason=reason, channel=channel, hint=hint)

    @classmethod
    def rewrite(
        cls,
        rule_id: str,
        reason: str,
        rewritten_argv: list[str],
        channel: Channel | None = None,
        hint: str | None = None,
    ) -> Decision:
        return cls(
            effect="rewrite",
            rule_id=rule_id,
            reason=reason,
            rewritten_argv=rewritten_argv,
            channel=channel,
            hint=hint,
        )

    @classmethod
    def escalate(cls, rule_id: str, reason: str, hint: str | None = None) -> Decision:
        return cls(effect="escalate", rule_id=rule_id, reason=reason, hint=hint)

    @classmethod
    def hook(cls, rule_id: str, reason: str, hint: str | None = None) -> Decision:
        return cls(effect="hook", rule_id=rule_id, reason=reason, hint=hint)


# --------------------------------------------------------------------------------------
# ToolCallCtx — the parsed request the engine authorizes
# --------------------------------------------------------------------------------------


class ToolCallCtx(BaseModel):
    """Everything the engine needs to decide a single tool call, post-parse."""

    model_config = ConfigDict(extra="forbid")

    tool_name: str
    args: dict[str, Any]
    argv0: str | None = None
    verb: str | None = None
    flags: dict[str, str | bool] = {}
    positionals: list[str] = []
    environment: str
    principal: str
    run_id: str
    # Optional run-time state a hook may consult (additive; ``extra="forbid"`` intact). The
    # middleware populates both for ``run_command`` calls from ``request.state``; every other
    # caller leaves them ``None``. ``files`` is the deepagents virtual-FS ``{path: FileData}``
    # mapping (the ``dry_run_before_apply`` hook resolves manifest shas against it) and
    # ``dry_run_ok`` maps a manifest content-sha256 -> ``True`` once a server dry-run of exactly
    # that manifest has succeeded in this run.
    files: Mapping[str, Any] | None = None
    dry_run_ok: Mapping[str, bool] | None = None
