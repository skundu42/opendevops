"""Built-in policy hooks that ship with the agent (T12).

Currently the single ``dry_run_before_apply`` gatekeeper: it enforces the P2 deploy contract
that a *real* ``kubectl apply`` (``--dry-run=none``) is permitted only when the identical staged
manifest has already dry-run against the server successfully in this run. A bare ``apply`` (no
``--dry-run``) is left for the ``force-server-dry-run-first`` rewrite rule to rewrite to
``--dry-run=server``; this hook only ever ABSTAINS (returns ``None``) or DENIES.

Convention — hooks are gatekeepers
----------------------------------
A policy hook returns a ``deny`` :class:`~opendevops.policy.schema.Decision` or ``None``
(abstain) — **never** an ``allow``. Returning ``None`` drops the hook rule and re-applies engine
precedence to the remaining matched rules, so every permit still flows through the plain
``kubectl-apply`` allow rule and its ``flags_allowed`` post-check. A hook must never be the thing
that *grants* access; it can only withhold judgement or refuse.

Registration
------------
The ``@policy_hook`` decorator registers the function at import time. The module is imported by
``opendevops.policy.__init__`` so that importing the policy package (which the agent build and
the CLI both do) registers this hook before any decision is made. A ``hook:`` rule whose name is
not registered fails closed at decide time (``__fail_closed__``), so the import is load-bearing.

Cross-layer import note
-----------------------
:func:`resolve_file_refs` is imported from ``opendevops.tools.staging`` — a *pure* function
(scan argv for file flags, hash the referenced virtual-FS content) with no side effects and no
back-dependency on the policy layer. The dry-run precondition keys on exactly the sha256s the
staging bridge records at execution time, so both layers must compute the manifest sha the same
way; importing the one shared pure function is how that identity is guaranteed. This is the only
policy->tools import and is deliberate.
"""

from __future__ import annotations

from opendevops.policy.hooks import policy_hook
from opendevops.policy.parsing import ParseError, parse_argv
from opendevops.policy.schema import RULE_FAIL_CLOSED, Decision, ToolCallCtx

# resolve_file_refs is a pure argv-scanner + content-hasher; see the module docstring for why a
# policy hook is allowed to reach into tools.staging for it.
from opendevops.tools.staging import StagingError, resolve_file_refs

# The rule id every gatekeeper deny is attributed to (the shipped YAML rule that names this hook).
_RULE_ID = "require-dry-run-before-real-apply"

# The one dry-run mode that satisfies the "validated against the server" precondition.
_SERVER = "server"
# The mode that requests a real apply (skip dry-run) — only permitted post-verification.
_NONE = "none"


@policy_hook("dry_run_before_apply")
async def dry_run_before_apply(ctx: ToolCallCtx) -> Decision | None:
    """Gate a ``kubectl apply`` on the dry-run-first-and-enforced contract.

    Decision table (``verb == apply`` is guaranteed by the rule that names this hook):

    * no ``--filename`` at all -> DENY (a real apply must reference a staged manifest; ``-k`` /
      malformed applies have nothing to verify). Denied regardless of the ``--dry-run`` value.
    * ``--dry-run`` absent -> ABSTAIN (``None``): the ``force-server-dry-run-first`` rewrite injects
      ``--dry-run=server`` and the re-pass reaches the plain allow.
    * ``--dry-run=server`` -> ABSTAIN: an explicit server dry-run is exactly what we want to run.
    * ``--dry-run=none`` -> ABSTAIN iff *every* referenced manifest's sha256 is recorded in
      ``ctx.dry_run_ok`` (a prior successful server dry-run this run); otherwise DENY.
    * any other ``--dry-run`` value (``client``, ...) -> DENY: client-side validation is not
      enough; server-side is required before a real apply.

    Fail-closed: an unreadable argv, a parse surprise, a missing files-state, or a manifest that
    cannot be resolved all DENY (``__fail_closed__``) rather than let an apply through unverified.
    """
    argv = ctx.args.get("argv")
    if not isinstance(argv, list) or not argv:
        return Decision.deny(
            RULE_FAIL_CLOSED, "dry_run_before_apply: unreadable argv"
        )

    # argv already parsed cleanly once in the engine before this hook ran; re-parse defensively so
    # a future engine change that skips the parse cannot slip an unparsed argv past the gate.
    try:
        parsed = parse_argv(argv)
    except ParseError as exc:
        return Decision.deny(RULE_FAIL_CLOSED, f"dry_run_before_apply: {exc}")

    # A real apply must reference a manifest via -f/--filename. -k/--kustomize (unsupported in P2)
    # and a bare `apply` have nothing to verify -> deny regardless of the --dry-run value.
    if "--filename" not in parsed.flags:
        return Decision.deny(
            _RULE_ID,
            "apply requires --filename in P2 (a real apply must reference a staged manifest)",
            hint="write the manifest with write_file, then apply it with -f",
        )

    dry_run = parsed.flags.get("--dry-run")

    if dry_run is None or dry_run == _SERVER:
        # Absent -> the rewrite rule injects --dry-run=server (and abstaining lets the re-pass
        # reach allow). Explicit server -> exactly the dry-run we want. Either way: no opinion.
        return None

    if dry_run == _NONE:
        return _gate_real_apply(ctx, argv)

    # client, or any other value: server-side validation is mandatory before a real apply.
    return Decision.deny(
        _RULE_ID,
        f"--dry-run={dry_run!r} is insufficient; server-side validation is required "
        "before a real apply",
        hint="re-run the apply with --dry-run=server",
    )


def _gate_real_apply(ctx: ToolCallCtx, argv: list[str]) -> Decision | None:
    """Permit a ``--dry-run=none`` apply iff every referenced manifest already dry-ran on server."""
    if ctx.files is None:
        # No virtual-FS state to resolve the manifest against -> cannot verify -> fail closed.
        return Decision.deny(
            RULE_FAIL_CLOSED,
            "dry_run_before_apply: no filesystem state available to verify the manifest",
        )
    try:
        refs = resolve_file_refs(list(argv), ctx.files)
    except StagingError as exc:
        return Decision.deny(
            RULE_FAIL_CLOSED,
            f"dry_run_before_apply: cannot resolve manifest for verification: {exc}",
        )
    if not refs:
        # --filename was present (checked by the caller) but nothing resolved -> fail closed.
        return Decision.deny(
            RULE_FAIL_CLOSED,
            "dry_run_before_apply: no manifest resolved to verify",
        )

    # dry_run_ok keys are RUN-SCOPED (``{run_id}:{sha256}``) so a server dry-run recorded on an
    # earlier turn of a checkpointed thread cannot validate a real apply on a later turn (stale
    # cluster validation). Look up the identically-scoped key the middleware records (T12-review).
    recorded = ctx.dry_run_ok or {}
    missing = [
        r.virtual_path for r in refs if not recorded.get(f"{ctx.run_id}:{r.sha256}")
    ]
    if missing:
        return Decision.deny(
            _RULE_ID,
            f"no successful server dry-run is recorded for {missing}",
            hint="run the identical apply with --dry-run=server first",
        )
    # Every manifest sha has a recorded successful server dry-run: abstain -> plain allow.
    return None
