"""PolicyEngine protocol + :class:`YamlRuleEngine`; OPA slots in behind the protocol.

The engine turns a :class:`~opendevops.policy.schema.ToolCallCtx` into a
:class:`~opendevops.policy.schema.Decision`. It is *default-deny* and *fail-closed*: any
internal error — a parse surprise, a config ref that will not resolve, a hook that raises or
hangs — becomes ``deny``, never an exception to the caller. Precedence over a matched rule
set is fixed: ``deny > escalate > hook > rewrite > allow``.

Ground truth for the data model, argv parser, and shipped YAML is the schema/parsing/loader
trio; this module consumes those interfaces and adds no policy data of its own.

Design note — argv0-only decisions happen *before* full flag parsing. The parser fail-closes
on any structural surprise (an unknown short flag, an attached short cluster like ``-rf`` /
``-exec``). But a hard-denied interpreter (``bash -c ...``) or a wholly-unknown binary
(``rm -rf /``) must be denied by *argv0 alone*, with its real rule id, regardless of whether
the rest of the argv would parse. So the pipeline (a) validates it can read ``argv[0]``,
(b) applies argv0-only deny rules, (c) short-circuits to ``__default_deny__`` when no rule
references the binary at all, and only then (d) fully parses — mapping a parse error on a
binary the policy actually reasons about to ``__fail_closed__``.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Callable
from typing import Protocol, runtime_checkable

from opendevops.policy.hooks import get_hook
from opendevops.policy.loader import LoadedPolicy
from opendevops.policy.parsing import ParsedArgv, ParseError, match_resource, parse_argv
from opendevops.policy.schema import (
    RULE_DEFAULT_DENY,
    RULE_FAIL_CLOSED,
    RULE_FLAG_NOT_ALLOWED,
    RULE_REWRITE_DIVERGED,
    RULE_UNKNOWN_TOOL,
    Decision,
    Rule,
    ToolCallCtx,
)

# Synthetic rule id for a deepagents built-in FS/planning tool allowed at the engine level
# (never authored in YAML; the dunder form is rejected by the schema's kebab-case constraint).
RULE_BUILTIN_FS = "__builtin_fs__"

# Synthetic rule id for the one named subagent the main agent may delegate to via ``task``.
# Allowed at the engine level for the SAME reason as the FS built-ins: base.yaml declares no
# tool_family and carries no allow rules, so this scoped allow cannot live in YAML. Any OTHER
# ``subagent_type`` is denied by base.yaml's ``no-arbitrary-subagents`` rule (deny > allow), and
# this synthetic allow is itself gated on the exact name below so it is fail-closed independent of
# that YAML deny.
RULE_SUBAGENT_ALLOWED = "__subagent_allowed__"

# deepagents built-in filesystem/planning tools, allowed by tool_name (see base.yaml header).
BUILTIN_FS_TOOLS: frozenset[str] = frozenset(
    {"write_todos", "ls", "read_file", "write_file", "edit_file", "glob", "grep"}
)

# The single argv-only execution tool. Only this tool_name enters the argv pipeline.
RUN_COMMAND = "run_command"

# deepagents' subagent-spawner tool (from ``SubAgentMiddleware``). Its ``subagent_type`` arg names
# the target; only :data:`LOG_SUMMARIZER_SUBAGENT` is permitted. The agent registers a
# subagent under EXACTLY this name (see ``agent.py``), so this constant is the single source of
# truth shared by the engine allow, the agent's subagent spec, and base.yaml's allowlist.
TASK_TOOL = "task"
LOG_SUMMARIZER_SUBAGENT = "log-summarizer"

# Hard timeout for a policy hook. Module-level so tests can monkeypatch it without a 2s wait.
HOOK_TIMEOUT_S = 2.0


def _any_verb_prefix(positionals: list[str], prefixes: list[str]) -> bool:
    """True iff any positional's prefix (the part before the first ``-``) is in ``prefixes``.

    Backs the ``positional_verb_prefix_any`` deny predicate: gcloud/az mutations appear as bare
    verbs (``suspend``) and as COMPOUND ``verb-noun`` forms (``set-machine-type``,
    ``delete-access-config``). Splitting each positional on the first ``-`` and comparing the
    prefix denies the whole ``set-*``/``add-*``/... family (and the bare verb, whose prefix is the
    whole word) without enumerating every noun. Comparison is case-insensitive; empty tokens are
    skipped. This is intentionally broad — it may false-deny a READ of a resource whose NAME starts
    with a mutation-verb prefix (e.g. a VM literally named ``set-...``), which is the safe direction
    (fail-closed): a false-deny of a read is acceptable; a false-allow of a mutation is the bug.
    """
    wanted = {p.lower() for p in prefixes}
    for pos in positionals:
        prefix = pos.split("-", 1)[0].lower()
        if prefix and prefix in wanted:
            return True
    return False


def _matches_seq_prefix_any(positionals: list[str], sequences: list[list[str]]) -> bool:
    """True iff ``positionals`` STARTS WITH one of the exact ``sequences``.

    Backs the ``positional_seq_prefix_any`` allow predicate (the fail-closed allowlist inversion
    for gcloud/az reads): a rule fires only when the parsed positionals begin with a CURATED read
    command path ``[<subgroup...>, <read-verb>]`` (e.g. ``[instances, list]``). Matching is
    fail-closed: a sequence longer than ``positionals`` never matches (the slice compares unequal),
    so a missing subgroup/verb cannot satisfy the allow. Trailing positionals after the matched
    prefix — a resource NAME/filter for ``describe <NAME>`` — are permitted; the read verb still
    occupies its DETERMINATE position, so an unknown verb there cannot match. The schema guarantees
    every sequence is non-empty, so an empty sequence can never match-all.
    """
    for seq in sequences:
        n = len(seq)
        if n and positionals[:n] == seq:
            return True
    return False


def _gh_api_method(parsed: ParsedArgv) -> str:
    """The gh api HTTP METHOD from the canonicalized ``--method`` flag, default ``GET`` (upper).

    ``parse_argv`` canonicalizes ``-X``/``--method`` to ``--method`` and CONSUMES its value (both
    are registered value-taking), so the method is a plain string flag value here; a request with
    no method flag defaults to ``GET``. Uppercased so matching is case-insensitive (gh itself
    uppercases the method) — a ``-X post`` cannot dodge the ``[GET, HEAD]`` read deny by casing.
    """
    value = parsed.flags.get("--method")
    return value.upper() if isinstance(value, str) else "GET"


def _gh_api_norm_path(parsed: ParsedArgv) -> str | None:
    """The gh api PATH (first positional after ``api``) with leading slashes stripped, or None.

    gh accepts both ``/repos/...`` and ``repos/...``; stripping the leading slash normalizes the
    two so the prefix/contains/repo checks compare against a stable ``repos/<owner>/<repo>/...``
    shape. Returns None when there is no positional (a path-less ``gh api`` — fail-closed for the
    allow, and the read deny still matches on method).
    """
    if not parsed.positionals:
        return None
    return parsed.positionals[0].lstrip("/")


def _gh_api_repo_subpath(norm_path: str, repos: list[str]) -> str | None:
    """The path remainder AFTER a matched ``repos/<owner>/<repo>/`` for an allowlisted repo.

    Returns the sub-path (what FOLLOWS the trailing ``/`` of the matched ``owner/repo``) or ``None``
    when ``norm_path`` is not ``repos/<owner>/<repo>/<sub...>`` for ANY allowlisted ``owner/repo``.
    A trailing sub-path is REQUIRED (``rest.startswith(slug + "/")``), so a bare ``/repos/{repo}``
    never matches and the ``/`` boundary stops an allowlisted ``org/x`` from matching ``org/xyz``.
    This is the SINGLE SOURCE of the repo-matching boundary — :func:`_gh_api_repo_allowed` is a thin
    ``is not None`` wrapper over it, and the C1 positive sub-path allowlist consumes the remainder.
    """
    prefix = "repos/"
    if not norm_path.startswith(prefix):
        return None
    rest = norm_path[len(prefix) :]
    for repo in repos:
        slug = repo.strip("/")
        if slug and rest.startswith(slug + "/"):
            return rest[len(slug) + 1 :]
    return None


def _gh_api_repo_allowed(norm_path: str, repos: list[str]) -> bool:
    """True iff ``norm_path`` is ``repos/<owner>/<repo>/<sub...>`` for an allowlisted owner/repo.

    Fail-closed: a path not under ``repos/`` (``/orgs/...``, ``/user``) returns False, so the write
    allow simply does not fire and the call falls to a deny / default-deny. Single-sourced with
    :func:`_gh_api_repo_subpath` (same ``repos/`` prefix + trailing-``/`` repo boundary).
    """
    return _gh_api_repo_subpath(norm_path, repos) is not None


def _gh_api_subpath_allowed(sub: str, prefixes: list[str]) -> bool:
    """True iff ``sub`` equals one of ``prefixes`` or is a path UNDER it (SEGMENT boundary).

    ``any(sub == p or sub.startswith(p + "/") for p in prefixes)`` — so ``pulls`` matches ``pulls``
    and ``pulls/1`` but NOT ``pullspam``, and ``contents`` matches ``contents/app.py``. A bare
    ``startswith`` would reintroduce the boundary bug (``pullspam`` slipping through), so it is
    NEVER used here. Backs the C1 fail-closed positive sub-path allowlist (contents + pulls).
    """
    return any(sub == p or sub.startswith(p + "/") for p in prefixes)


def _remote_flag_prefix_hit(argv: list[str], prefixes: list[str]) -> bool:
    """True iff any argv token (its part before '=') starts with one of the flag prefixes.

    Backs the ``ssh_remote_flag_prefix_any`` DENY predicate: journalctl's mutating modes are
    FLAGS (``--vacuum-time=1s``, ``--rotate``, ``--flush`` ...) that share ``argv[0]`` with its
    reads, so the positive allowlist permits ``[journalctl]`` and this deny (deny > allow) pins
    the destructive flags out. Splitting on ``=`` catches the ``--vacuum-time=1s`` value form;
    prefix-match catches the ``--vacuum-size``/``--vacuum-files`` family. All journalctl mutation
    flags are LONG (``--``) flags, so there is no short-flag-bundling evasion. Matching is
    case-INSENSITIVE so the deny does not depend on the remote tool's getopt case behavior (a
    ``--VACUUM-TIME`` variant is denied at the policy layer, not merely by journalctl rejecting it).
    """
    for tok in argv:
        if not isinstance(tok, str):
            continue
        head = tok.split("=", 1)[0].lower()
        if any(head.startswith(p.lower()) for p in prefixes):
            return True
    return False


@runtime_checkable
class PolicyEngine(Protocol):
    """The minimal engine surface. An OpaHttpEngine can implement the same one method later."""

    async def decide(self, ctx: ToolCallCtx) -> Decision: ...


class YamlRuleEngine:
    """Decision engine over the loaded YAML policy.

    ``config_resolver`` resolves an interpolation ref (e.g.
    ``"${targets.kubernetes.allowed_contexts}"``) to a ``list[str]`` at decision time. Every
    ref that appears in the loaded policy is resolved once at construction so a typo'd or
    unbound ref fails loudly at boot rather than silently at first request.
    """

    def __init__(
        self, loaded: LoadedPolicy, config_resolver: Callable[[str], list[str]]
    ) -> None:
        self._loaded = loaded
        self._config_resolver = config_resolver

        # Flatten rules in load/file order (precedence ties break on file order). Derive the
        # per-rule flags_allowed table (the *winning pack's* allowlist, not the global merge)
        # and a per-binary tool_family map for default-deny hints, all from the loaded files.
        self._rules: list[Rule] = []
        self._flags_allowed_by_rule: dict[str, dict[str, list[str]]] = {}
        self._family_by_argv0: dict[str, str] = {}
        for pf in loaded.files.values():
            flags_allowed = pf.flags_allowed or {}
            for rule in pf.rules:
                self._rules.append(rule)
                self._flags_allowed_by_rule[rule.id] = flags_allowed
                if pf.tool_family and rule.match.argv0 is not None:
                    for binary in rule.match.argv0.values():
                        self._family_by_argv0.setdefault(binary, pf.tool_family)

        # Fail at construction if any referenced config ref cannot resolve (fail-loud boot).
        for ref in self._collect_refs():
            try:
                resolved = config_resolver(ref)
            except Exception as exc:  # noqa: BLE001 - re-raised as a construction error
                raise ValueError(
                    f"policy references config {ref!r} which cannot be resolved: {exc}"
                ) from exc
            if not isinstance(resolved, list):
                raise ValueError(
                    f"config resolver for {ref!r} returned {type(resolved).__name__}, "
                    "expected list[str]"
                )

    # -- construction helpers ---------------------------------------------------------------

    def _collect_refs(self) -> set[str]:
        """Every distinct config-interpolation ref used by a predicate (fail-loud at construction).

        Three sources: a ``flag_value_not_in`` value (run_command argv flags, e.g. the kubectl
        ``--context`` allowlist), ``ssh_host_in`` (the ssh_run host allowlist), and the
        gh-write ``gh_api.repo_prefix_from`` write-repo allowlist ref.
        """
        refs: set[str] = set()
        for rule in self._rules:
            if rule.match.flag_value_not_in:
                refs.update(rule.match.flag_value_not_in.values())
            if rule.match.ssh_host_in is not None:
                refs.add(rule.match.ssh_host_in)
            if rule.match.gh_api is not None and rule.match.gh_api.repo_prefix_from is not None:
                refs.add(rule.match.gh_api.repo_prefix_from)
        return refs

    # -- public surface ---------------------------------------------------------------------

    async def decide(self, ctx: ToolCallCtx) -> Decision:
        """Authorize a single tool call. Never raises — every internal error is fail-closed."""
        try:
            return await self._decide(ctx)
        except Exception as exc:  # noqa: BLE001 - the fail-closed invariant: nothing escapes
            return Decision.deny(RULE_FAIL_CLOSED, f"policy engine internal error: {exc}")

    # -- core -------------------------------------------------------------------------------

    async def _decide(self, ctx: ToolCallCtx) -> Decision:
        applicable = self._applicable(ctx.environment)

        if ctx.tool_name == RUN_COMMAND:
            return await self._decide_argv(ctx, applicable)

        # Non-run_command (built-in FS tools + structured tools like ssh_run): match tool_name
        # rules — an authored tool_name deny (task / compact_conversation / execute) wins over a
        # built-in allow and over the fallback, firing with its real rule id; a structured allow
        # (ssh_run) fires when its predicates match.
        matched = [r for r in applicable if self._rule_matches(r, ctx, None)]
        fallback = self._non_run_command_fallback(ctx, applicable)
        if matched:
            return await self._decide_over(
                matched, ctx, [], None, allow_rewrite=True, fallback=fallback
            )
        return fallback

    def _non_run_command_fallback(self, ctx: ToolCallCtx, applicable: list[Rule]) -> Decision:
        tool_name = ctx.tool_name
        if tool_name in BUILTIN_FS_TOOLS:
            return Decision(
                effect="allow",
                rule_id=RULE_BUILTIN_FS,
                reason="deepagents built-in filesystem/planning tool",
                channel=None,
            )
        # The single named subagent the main agent may delegate to via ``task``. Reached only
        # when no deny matched — base.yaml's ``no-arbitrary-subagents`` rule denies every other (and
        # a missing/malformed) ``subagent_type`` before this. Still gated on the EXACT name here so
        # the allow stays fail-closed even if that YAML deny were removed: any other target then
        # falls through to the default-deny below. The task tool uses no credential (it is not
        # decision-gated in the middleware), so channel is None, as for the FS built-ins.
        if tool_name == TASK_TOOL and ctx.args.get("subagent_type") == LOG_SUMMARIZER_SUBAGENT:
            return Decision(
                effect="allow",
                rule_id=RULE_SUBAGENT_ALLOWED,
                reason="delegation to the log-summarizer subagent",
                channel=None,
            )
        # A tool the policy actually REASONS ABOUT — some rule pins its tool_name (e.g. ssh_run's
        # allow) — but no rule matched THIS call's args is a default-deny ("no rule permits this
        # call"), a clearer audit line than __unknown_tool__ for a registered structured tool whose
        # host/argv were simply outside the allowlists. A tool no rule references at all stays
        # __unknown_tool__.
        if any(
            r.match.tool_name is not None and r.match.tool_name.matches(tool_name)
            for r in applicable
        ):
            return Decision.deny(
                RULE_DEFAULT_DENY, f"no policy rule permits this {tool_name!r} call"
            )
        return Decision.deny(RULE_UNKNOWN_TOOL, f"tool {tool_name!r} is not a permitted tool")

    async def _decide_argv(self, ctx: ToolCallCtx, applicable: list[Rule]) -> Decision:
        argv = ctx.args.get("argv")

        # (a) Read argv0 without a full parse; an empty argv or non-string argv0 is fail-closed.
        if not isinstance(argv, list) or not argv or not isinstance(argv[0], str):
            return Decision.deny(RULE_FAIL_CLOSED, "empty argv or non-string argv0")
        # Case-fold to match parsing.py's normalization (both sites must agree — a rule keyed
        # on "kubectl" must also catch "KUBECTL" here in the pre-parse short-circuit path).
        argv0 = os.path.basename(argv[0]).lower()

        # (b) argv0-only deny rules (e.g. interpreters-hard-deny) win before flag parsing, so a
        #     hard-denied binary that also carries flags the parser rejects still denies with
        #     its real rule id (deny is top precedence, so a matching argv0 deny always wins).
        for rule in applicable:
            if (
                rule.effect == "deny"
                and self._is_pure_argv0_rule(rule)
                and rule.match.argv0 is not None
                and rule.match.argv0.matches(argv0)
            ):
                return self._deny_decision(rule)

        # (c) A binary no rule references at all is default-deny — again without parsing, so an
        #     unknown binary with an unparseable argv (e.g. ``rm -rf /``) denies, not fail-closed.
        if not any(
            r.match.argv0 is not None and r.match.argv0.matches(argv0) for r in applicable
        ):
            return Decision.deny(
                RULE_DEFAULT_DENY,
                f"no policy rule permits {argv0!r}",
                hint=self._closest_pack_hint(argv0),
            )

        # (d) Full parse for a binary the policy actually reasons about; a parse surprise here
        #     is a genuine fail-closed (malformed flags on an otherwise-known binary).
        try:
            parsed = parse_argv(argv)
        except ParseError as exc:
            return Decision.deny(RULE_FAIL_CLOSED, str(exc))

        matched = [r for r in applicable if self._rule_matches(r, ctx, parsed)]
        fallback = Decision.deny(
            RULE_DEFAULT_DENY,
            f"no policy rule permits {parsed.argv0!r}",
            hint=self._closest_pack_hint(parsed.argv0),
        )
        return await self._decide_over(
            matched, ctx, argv, parsed, allow_rewrite=True, fallback=fallback
        )

    async def _decide_over(
        self,
        matched: list[Rule],
        ctx: ToolCallCtx,
        argv: list[str],
        parsed: ParsedArgv | None,
        *,
        allow_rewrite: bool,
        fallback: Decision,
    ) -> Decision:
        """Apply fixed precedence (deny > escalate > hook > rewrite > allow) over ``matched``."""
        if not matched:
            return fallback

        denies = [r for r in matched if r.effect == "deny"]
        if denies:
            return self._deny_decision(denies[0])

        escalates = [r for r in matched if r.effect == "escalate"]
        if escalates:
            rule = escalates[0]
            return Decision.escalate(
                rule.id, rule.reason or f"{rule.id} requires approval", hint=rule.hint
            )

        hooks = [r for r in matched if r.effect == "hook"]
        if hooks:
            rule = hooks[0]
            hook_decision = await self._run_hook(rule, ctx)
            if hook_decision is None:
                # No opinion: drop this hook rule and re-apply precedence to the rest.
                remaining = [r for r in matched if r is not rule]
                return await self._decide_over(
                    remaining, ctx, argv, parsed, allow_rewrite=allow_rewrite, fallback=fallback
                )
            return hook_decision

        rewrites = [r for r in matched if r.effect == "rewrite"]
        if rewrites:
            if not allow_rewrite:
                return Decision.deny(
                    RULE_REWRITE_DIVERGED, "rewritten argv would trigger a further rewrite"
                )
            return await self._do_rewrite(rewrites, ctx, argv, parsed)

        allows = [r for r in matched if r.effect == "allow"]
        if allows:
            return self._apply_allow(allows[0], parsed)

        return fallback

    async def _do_rewrite(
        self,
        rewrites: list[Rule],
        ctx: ToolCallCtx,
        argv: list[str],
        parsed: ParsedArgv | None,
    ) -> Decision:
        """Inject each matched rewrite rule's flags (file order, absent-only), re-decide once."""
        present: set[str] = set(parsed.flags.keys()) if parsed is not None else set()
        injected: list[str] = []
        for rule in rewrites:
            if rule.rewrite is None:  # defensive; schema guarantees it for effect=rewrite
                continue
            for token in rule.rewrite.inject_flags:
                name = token.split("=", 1)[0]
                if name not in present:
                    injected.append(token)
                    present.add(name)

        rewritten_argv = list(argv) + injected

        try:
            parsed2 = parse_argv(rewritten_argv)
        except ParseError as exc:
            return Decision.deny(RULE_REWRITE_DIVERGED, f"rewritten argv failed to parse: {exc}")

        applicable = self._applicable(ctx.environment)
        matched2 = [r for r in applicable if self._rule_matches(r, ctx, parsed2)]
        second_fallback = Decision.deny(
            RULE_DEFAULT_DENY,
            f"no policy rule permits {parsed2.argv0!r}",
            hint=self._closest_pack_hint(parsed2.argv0),
        )
        # EXACTLY one re-decide: allow_rewrite=False so a second rewrite cannot recurse.
        second = await self._decide_over(
            matched2, ctx, rewritten_argv, parsed2, allow_rewrite=False, fallback=second_fallback
        )
        if second.effect == "allow":
            winner = rewrites[0]
            return Decision.rewrite(
                rule_id=winner.id,
                reason=winner.reason or "argv rewritten to satisfy policy",
                rewritten_argv=rewritten_argv,
                channel=second.channel,
                hint=winner.hint,
            )
        return Decision.deny(
            RULE_REWRITE_DIVERGED,
            f"rewritten argv did not yield a plain allow (got {second.effect}/{second.rule_id})",
        )

    def _apply_allow(self, rule: Rule, parsed: ParsedArgv | None) -> Decision:
        """Allow post-check: every parsed flag must be in the winning pack's flags_allowed."""
        if parsed is not None:
            allowed = self._flags_allowed_by_rule.get(rule.id, {}).get(parsed.argv0, [])
            for flag in parsed.flags:
                if flag not in allowed:
                    return Decision.deny(
                        RULE_FLAG_NOT_ALLOWED,
                        f"flag {flag!r} is not permitted for {parsed.argv0!r}",
                    )
        return Decision(
            effect="allow",
            rule_id=rule.id,
            reason=rule.reason or "permitted operation",
            channel=rule.channel,
            hint=rule.hint,
        )

    async def _run_hook(self, rule: Rule, ctx: ToolCallCtx) -> Decision | None:
        """Run a hook under a hard timeout. Missing/raising/timeout ⇒ fail-closed Decision."""
        hook_name = rule.hook
        if hook_name is None:  # defensive; schema guarantees it for effect=hook
            return Decision.deny(RULE_FAIL_CLOSED, f"rule {rule.id!r} has effect=hook but no hook")
        fn = get_hook(hook_name)
        if fn is None:
            return Decision.deny(RULE_FAIL_CLOSED, f"unknown policy hook {hook_name!r}")
        try:
            return await asyncio.wait_for(fn(ctx), HOOK_TIMEOUT_S)
        except TimeoutError:
            return Decision.deny(
                RULE_FAIL_CLOSED, f"policy hook {hook_name!r} timed out after {HOOK_TIMEOUT_S}s"
            )
        except Exception as exc:  # noqa: BLE001 - a hook must never crash the engine
            return Decision.deny(RULE_FAIL_CLOSED, f"policy hook {hook_name!r} raised: {exc}")

    # -- matching ---------------------------------------------------------------------------

    def _rule_matches(self, rule: Rule, ctx: ToolCallCtx, parsed: ParsedArgv | None) -> bool:
        """True iff every predicate present in ``rule.match`` is satisfied (absent = wildcard).

        With ``parsed is None`` (a non-run_command tool) any argv-level predicate is
        unsatisfiable, so only pure tool_name rules can match.
        """
        m = rule.match
        flags = parsed.flags if parsed is not None else {}
        positionals = parsed.positionals if parsed is not None else []

        if m.tool_name is not None and not m.tool_name.matches(ctx.tool_name):
            return False
        if m.argv0 is not None and (parsed is None or not m.argv0.matches(parsed.argv0)):
            return False
        if m.verb is not None and (
            parsed is None or parsed.verb is None or not m.verb.matches(parsed.verb)
        ):
            return False
        if m.first_positional is not None and (
            parsed is None
            or not parsed.positionals
            or not m.first_positional.matches(parsed.positionals[0])
        ):
            return False
        if m.last_positional is not None and (
            parsed is None
            or not parsed.positionals
            or not m.last_positional.matches(parsed.positionals[-1])
        ):
            return False
        if m.second_last_positional is not None and (
            parsed is None
            or len(positionals) < 2
            or not m.second_last_positional.matches(positionals[-2])
        ):
            return False
        if m.positional_verb_prefix_any is not None and not _any_verb_prefix(
            positionals, m.positional_verb_prefix_any
        ):
            return False
        if m.positional_seq_prefix_any is not None and not _matches_seq_prefix_any(
            positionals, m.positional_seq_prefix_any
        ):
            return False
        if m.flags_any is not None and not any(f in flags for f in m.flags_any):
            return False
        if m.flags_absent is not None and any(f in flags for f in m.flags_absent):
            return False
        if m.flag_value_not_in is not None:
            fired = any(
                flag in flags and flags[flag] not in self._config_resolver(ref)
                for flag, ref in m.flag_value_not_in.items()
            )
            if not fired:
                return False
        # ssh_run structured-tool predicates: read ctx.args directly (parsed is None here).
        if m.ssh_host_in is not None:
            host = ctx.args.get("host")
            if not isinstance(host, str) or not host:
                return False
            if host not in self._config_resolver(m.ssh_host_in):
                return False
        if m.ssh_remote_argv0 is not None:
            ssh_argv = ctx.args.get("argv")
            # A non-str element anywhere in argv fails CLOSED (symmetric with the seq-prefix guard
            # below): the allow never fires on a malformed argv, so it default-denies rather than
            # matching on argv[0] alone and ignoring the rest.
            if (
                not isinstance(ssh_argv, list)
                or not ssh_argv
                or not all(isinstance(t, str) for t in ssh_argv)
                or not m.ssh_remote_argv0.matches(ssh_argv[0])
            ):
                return False
        if m.ssh_remote_argv_seq_prefix_any is not None:
            ssh_argv = ctx.args.get("argv")
            if (
                not isinstance(ssh_argv, list)
                or not all(isinstance(t, str) for t in ssh_argv)
                or not _matches_seq_prefix_any(ssh_argv, m.ssh_remote_argv_seq_prefix_any)
            ):
                return False
        if m.ssh_remote_flag_prefix_any is not None:
            ssh_argv = ctx.args.get("argv")
            if not isinstance(ssh_argv, list) or not _remote_flag_prefix_hit(
                ssh_argv, m.ssh_remote_flag_prefix_any
            ):
                return False
        # gh_api (gh-write): the `gh api` METHOD+PATH matcher. Meaningful only for a parsed
        # `gh api` call; every present sub-field is ANDed (an absent one is a wildcard). Reads
        # `parsed` directly and re-checks verb=="api" defensively (the rule also pins verb).
        if m.gh_api is not None:
            if parsed is None or parsed.verb != "api":
                return False
            ga = m.gh_api
            norm = _gh_api_norm_path(parsed)
            if ga.methods is not None and _gh_api_method(parsed) not in {
                x.upper() for x in ga.methods
            }:
                return False
            if ga.repo_prefix_from is not None and (
                norm is None
                or not _gh_api_repo_allowed(norm, self._config_resolver(ga.repo_prefix_from))
            ):
                return False
            # C1: fail-closed POSITIVE sub-path allowlist under an allowlisted repo. Meaningful only
            # with repo_prefix_from (it reuses that repo allowlist); fail closed if it is unset or
            # the path is not under an allowlisted repo, so the write allow default-denies every
            # sub-path except the enumerated ones (contents + pulls).
            if ga.repo_subpath_prefix_any is not None:
                if ga.repo_prefix_from is None or norm is None:
                    return False
                sub = _gh_api_repo_subpath(norm, self._config_resolver(ga.repo_prefix_from))
                if sub is None or not _gh_api_subpath_allowed(sub, ga.repo_subpath_prefix_any):
                    return False
            if ga.path_prefix_any is not None and (
                norm is None or not any(norm.startswith(p) for p in ga.path_prefix_any)
            ):
                return False
            if ga.path_contains_any is not None and (
                norm is None or not any(s in norm for s in ga.path_contains_any)
            ):
                return False
        # task-target predicate (deny rules only): fires unless ``subagent_type`` is a known
        # string in the allowlist. A missing/non-string target is "not in" -> the deny matches
        # (fail-closed), so an un-named/arbitrary subagent stays denied.
        if m.subagent_type_not_in is not None:
            sub_type = ctx.args.get("subagent_type")
            if isinstance(sub_type, str) and sub_type in m.subagent_type_not_in:
                return False
        return m.resource_any is None or match_resource(positionals, m.resource_any)

    @staticmethod
    def _is_pure_argv0_rule(rule: Rule) -> bool:
        """True iff the rule matches on ``argv0`` alone (no verb/flag/resource/tool_name)."""
        m = rule.match
        return (
            m.argv0 is not None
            and m.tool_name is None
            and m.verb is None
            and m.first_positional is None
            and m.last_positional is None
            and m.second_last_positional is None
            and m.flags_any is None
            and m.flags_absent is None
            and m.flag_value_not_in is None
            and m.resource_any is None
            and m.positional_verb_prefix_any is None
            and m.positional_seq_prefix_any is None
            and m.ssh_host_in is None
            and m.ssh_remote_argv0 is None
            and m.ssh_remote_argv_seq_prefix_any is None
            and m.ssh_remote_flag_prefix_any is None
            and m.subagent_type_not_in is None
            and m.gh_api is None
        )

    # -- helpers ----------------------------------------------------------------------------

    def _applicable(self, environment: str) -> list[Rule]:
        return [
            r for r in self._rules if r.environments is None or environment in r.environments
        ]

    def _deny_decision(self, rule: Rule) -> Decision:
        return Decision.deny(rule.id, rule.reason or f"denied by {rule.id}", hint=rule.hint)

    def _closest_pack_hint(self, argv0: str) -> str | None:
        family = self._family_by_argv0.get(argv0)
        if family is None:
            return None
        return f"no allow rule permitted {argv0!r}; the closest pack is the {family!r} family"
