"""Final agent assembly: ``build_agent`` composes the deepagents graph + safety middleware (T8).

``build_agent(cfg, *, audit, counter, checkpointer=None)`` returns a compiled langgraph agent
whose every tool call passes, in order, through the budget stop-loss middleware (per-run USD,
daily USD, model-call / tool-call / shell-call limits) and finally ``PolicyMiddleware`` — the
innermost wrap, so the authorization decision sits closest to execution. ``audit`` and
``counter`` are *injected* (not built here) so the T9 gateway shares the same instances it uses
for ``start_run`` / ``run_completed`` / daily-cap checks.

Boot is fail-closed. Before returning, ``build_agent`` runs two hard assertions and raises
``RuntimeError`` rather than serve a mis-wired graph:

* :func:`_assert_tool_inventory` — the ToolNode must bind exactly the ten expected tools (the
  nine safety tools plus ``task``, now a policy-scoped active tool — see below), plus at most the
  one *tolerated-but-denied* built-in (``execute``). Anything else is a surplus tool the policy
  layer has never vetted → refuse to boot.
* :func:`_assert_reducer_channels` — the compiled graph's ``run_cost_usd`` (and ``run_usage`` /
  ``tool_results_cache`` / ``messages``) channels must be ``BinaryOperatorAggregate`` reducers.
  If T7's state composition ever flattened the budget-mixin annotations into plain ``LastValue``
  fields, the per-run USD cap would silently see only the *last* model call and never fire; we
  turn that latent failure into a loud boot failure.

The log-summarizer subagent + scoped ``task`` (P5c)
---------------------------------------------------
The main agent has ONE named subagent — a haiku-backed **log-summarizer**
(:func:`_build_log_summarizer_subagent`) it delegates log / large-output digesting to via
deepagents' ``task`` tool. It is registered as a :class:`~deepagents.CompiledSubAgent` built from
langchain's ``create_agent`` with **no tools** (it summarizes text it is handed; it must never reach
``run_command`` or any mutation tool — pinned by test). Because it is a *compiled* runnable,
deepagents wires it as-is and does NOT inject its default filesystem/``execute`` toolset (verified
against 0.6.12), so the subagent's tool surface is empty and there is nothing to police inside it.
Its haiku model calls ARE metered: deepagents invokes the subagent inside the parent ``task`` tool
call, which runs inside the gateway's ``get_usage_metadata_callback()`` scope; that callback is an
*inheritable contextvar* hook, so the subagent's usage lands in the run's authoritative aggregate
(verified — see ``test_gateway.py``).

Passing ``subagents=[log-summarizer]`` means ``task`` is now **genuinely bound** (an active tool),
NOT removed: the production harness profile still disables the auto-added general-purpose subagent
(``general_purpose_subagent(enabled=False)``), so ``task`` exposes ONLY the log-summarizer; a
fake-model build (which does not match the profile key) additionally keeps the general-purpose
subagent, but the policy denies every ``subagent_type`` other than the log-summarizer either way. So
``task`` moves into ``EXPECTED_ACTIVE`` and the ``no-arbitrary-subagents`` /
``__subagent_allowed__`` policy pair (base.yaml + engine) scopes it fail-closed.

Neutralizing ``execute`` (Divergence D1)
----------------------------------------
deepagents 0.6.12 binds a shell-string tool that is unwanted:

* ``execute`` (shell-string tool, from the **required** ``FilesystemMiddleware``) — **cannot be
  unbound** without subclassing/monkeypatching private deepagents internals: the middleware is
  in ``_REQUIRED_MIDDLEWARE`` and unconditionally lists ``execute`` in ``.tools``. The only
  supported knob (``HarnessProfile.excluded_tools``) filters it from the *model request* (a real
  defense-in-depth win — the model never sees it) but leaves it in the ToolNode. It is inert on
  ``StateBackend`` and hard-denied by the shipped ``no-builtin-shell-execute`` rule.

Summarizer replacement (T14) — replace-by-name IS possible, via a harness-profile exclusion
--------------------------------------------------------------------------------------------
deepagents' default stack injects a ``create_summarization_middleware(model, backend)`` built on
the **main** model. We replace it with a haiku-backed one (the ``summarizer`` agent alias). The
mechanism (verified empirically against deepagents 0.6.12 / langchain 1.3.14 — probes cited at
:func:`_build_summarizer` / :func:`_register_harness_profiles`):

* ``langchain.agents.factory.create_agent`` still rejects duplicate middleware ``.name`` values
  and ``create_deep_agent`` still only *extends* the stack — so a same-named user summarizer would
  either collide or be dropped. But deepagents ships ``HarnessProfile.excluded_middleware``, whose
  string form ``{"SummarizationMiddleware"}`` drops the default summarizer by its public alias.
* ``_DeepAgentsSummarizationMiddleware.name`` returns that alias **only** for the exact base class
  and its own ``__name__`` for any subclass. So we add a marker-subclass
  (:class:`_HaikuSummarizationMiddleware`, name ``"_HaikuSummarizationMiddleware"``) built on haiku:
  the profile exclusion removes the base default, the subclass survives, and there is no duplicate
  name. Net effect: an in-place, name-matched replacement.

Because the profile is matched against the model **object**, the exclusion is registered under
BOTH the config ``model_key`` (real model) AND the model instance's derived key (so an injected
fake test model also gets the default summarizer excluded — otherwise the fake build would run two
summarizers). See :func:`_register_harness_profiles`.

Per-profile budget caps (T14)
-----------------------------
:class:`CostCapMiddleware` resolves its USD cap **per run** from ``runtime.context.budget_profile``
against a ``profiles`` map (all of ``cfg.budgets``'s profiles resolved once here at build), so the
same compiled graph enforces ``scheduled``'s $2.00 cap on one run and ``incident``'s $10.00 on the
next. The langchain count-limit middlewares (``ModelCallLimitMiddleware`` /
``ToolCallLimitMiddleware``) are third-party and CANNOT read ``runtime.context``, so they are built
from the **max** count across all profiles — a documented ceiling; the tighter per-run USD cap
still stops a run first for the profile that matters, and we deliberately do NOT half-build
per-profile counts. Daily caps (``global_usd`` / ``per_principal_usd``) are not per-profile in the
config schema, so :class:`DailyBudgetMiddleware` keeps the single global daily config.
"""

from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any

from deepagents import (
    CompiledSubAgent,
    GeneralPurposeSubagentProfile,
    HarnessProfile,
    create_deep_agent,
    register_harness_profile,
)
from deepagents.backends import StateBackend
from deepagents.middleware.summarization import (
    _DeepAgentsSummarizationMiddleware,
    create_summarization_middleware,
)
from langchain.agents import create_agent
from langchain.agents.middleware import (
    AgentMiddleware,
    ModelCallLimitMiddleware,
    ToolCallLimitMiddleware,
)

from opendevops.budget.middleware import (
    BudgetStateMixin,
    CostCapMiddleware,
    DailyBudgetMiddleware,
)
from opendevops.context import AgentContext
from opendevops.models import registry
from opendevops.models.pricing import PriceTable
from opendevops.policy.engine import LOG_SUMMARIZER_SUBAGENT, YamlRuleEngine
from opendevops.policy.guard import SingleToolCallMiddleware
from opendevops.policy.loader import check_credential_coverage, load_policy
from opendevops.policy.middleware import PolicyMiddleware
from opendevops.prompts import SYSTEM_PROMPT
from opendevops.state import DevOpsState

if TYPE_CHECKING:
    from langgraph.graph.state import CompiledStateGraph
    from langgraph.runtime import Runtime

    from opendevops.audit.logger import AuditLogger
    from opendevops.budget.daily import DailyCounter
    from opendevops.config import AppConfig, ResolvedProfile

logger = logging.getLogger(__name__)

# The ten tools the agent is *supposed* to expose: our argv-only run_command, the structured
# credential-pinned ssh_run remote-exec tool (P5b), the deepagents built-in filesystem/planning
# tools (allowed by tool_name at the engine level), and `task` — the subagent spawner, now an
# active tool SCOPED by policy to the single named log-summarizer subagent (P5c; base.yaml
# `no-arbitrary-subagents` + engine `__subagent_allowed__`). `task` is bound in BOTH the production
# build (exposing only the log-summarizer) and a fake-model build (also exposing the general-purpose
# subagent, which the policy denies), so it is *required*, not merely tolerated.
EXPECTED_ACTIVE: frozenset[str] = frozenset(
    {
        "run_command",
        "ssh_run",
        "write_todos",
        "ls",
        "read_file",
        "write_file",
        "edit_file",
        "glob",
        "grep",
        "task",
    }
)

# Built-in that may remain *bound* but is hard-denied by shipped policy (see module docstring
# + config/policy/base.yaml):
#   * execute -> base.yaml `no-builtin-shell-execute` (also excluded from the model request)
# The set is TOLERATED, not required. Anything outside EXPECTED_ACTIVE ∪ TOLERATED_DENIED fails
# boot.
TOLERATED_DENIED: frozenset[str] = frozenset({"execute"})

_REDUCER_CHANNELS: tuple[str, ...] = (
    "run_cost_usd",
    "run_usage",
    "tool_results_cache",
    "messages",
)

# The public alias deepagents' default summarization middleware reports as ``.name`` (verified:
# ``create_summarization_middleware(...).name == "SummarizationMiddleware"`` on deepagents 0.6.12).
# The harness profile's string-form ``excluded_middleware`` targets it to drop the default so our
# haiku-backed replacement takes its place. See the module docstring + :func:`_build_summarizer`.
_SUMMARIZER_NAME = "SummarizationMiddleware"

# The one-line description of the log-summarizer shown to the MAIN model in the ``task`` tool's
# generated description (deepagents renders "- <name>: <description>"), telling it when to delegate.
_LOG_SUMMARIZER_DESCRIPTION = (
    "Summarize verbose logs or large command output into a concise, RCA-relevant digest. "
    "Hand it the raw text in the task description; it returns key errors, stack traces, "
    "timestamps, and anomalies. It has NO tools — it only summarizes the text you give it."
)

# The system prompt for the log-summarizer subagent itself. It is a pure text-in/digest-out worker:
# it has no tools, so it must never claim to fetch or run anything — it summarizes only what it is
# handed. Kept local to this module (not in prompts.py) because it is the subagent's contract.
_LOG_SUMMARIZER_PROMPT = """\
You are a log-summarizer subagent for an autonomous DevOps agent. You receive logs or large \
command output in your task instructions and return a tight, root-cause-relevant digest.

You have NO tools. Do not attempt to fetch, run, or read anything — summarize ONLY the text you \
were given. If the text is empty or unusable, say so plainly.

Produce a compact digest that preserves the signal an on-call engineer needs: the key error \
messages and exit statuses, the most relevant stack traces (trimmed), notable timestamps and \
the order of events, repeated/looping failures, and any anomalous-looking values. Drop routine \
noise. Do not speculate beyond what the text supports. Return the digest as your final message."""

# Guard so registering the (process-global) harness profile is idempotent across many builds.
_registered_profiles: set[str] = set()
_registry_lock = threading.Lock()


class _HaikuSummarizationMiddleware(_DeepAgentsSummarizationMiddleware):
    """Marker subclass so deepagents' default summarizer can be replaced *in place* by name.

    ``_DeepAgentsSummarizationMiddleware.name`` reports the public alias
    ``"SummarizationMiddleware"`` only for the exact base class, and its own ``__name__`` for any
    subclass (verified via probe
    against deepagents 0.6.12). Therefore the harness profile's
    ``excluded_middleware={"SummarizationMiddleware"}`` drops the factory's default (main-model)
    summarizer, while this subclass — reporting ``"_HaikuSummarizationMiddleware"`` — is neither
    matched by that exclusion nor a duplicate ``.name`` for langchain's ``create_agent`` dedupe.
    """


def _build_summarizer(cfg: AppConfig, backend: Any) -> _DeepAgentsSummarizationMiddleware:
    """Build the haiku-backed replacement for deepagents' default summarization middleware.

    Reuses the deepagents factory so the model-aware trigger/keep defaults, summary prompt, and
    backend-offload behavior all match the default the factory would have built — only the model
    changes (the ``summarizer`` agent alias -> haiku) and the concrete type is re-tagged to the
    marker subclass so the profile's name-form exclusion of the base class leaves it in place.
    """
    summarizer_model = registry.build_chat_model(cfg, "summarizer")
    middleware = create_summarization_middleware(summarizer_model, backend)
    # Re-tag the concrete type (a no-op-layout subclass) so ``.name`` becomes distinct and the
    # base-class exclusion preserves this instance. See :class:`_HaikuSummarizationMiddleware`.
    middleware.__class__ = _HaikuSummarizationMiddleware
    return middleware


def _build_log_summarizer_subagent(cfg: AppConfig) -> CompiledSubAgent:
    """Build the haiku-backed log-summarizer subagent (P5c) as a tool-less compiled runnable.

    Registered under the exact name :data:`~opendevops.policy.engine.LOG_SUMMARIZER_SUBAGENT`
    (the ``subagent_type`` the policy permits) and delegated to via deepagents' ``task`` tool.

    Built with langchain's ``create_agent(model, tools=[])`` and handed to ``create_deep_agent``
    as a :class:`~deepagents.CompiledSubAgent` (``{name, description, runnable}``). The *compiled*
    form is deliberate: for a raw ``SubAgent`` spec deepagents prepends its default
    filesystem/``execute`` toolset, but a compiled runnable is wired as-is, so this subagent has
    **no tools at all** — it cannot reach ``run_command``/``ssh_run`` or any mutation tool, and
    there is no tool surface to police inside it (pinned by test). Its model is the
    ``log_summarizer`` agent alias (haiku, priced); its usage is metered by the run's gateway-level
    ``get_usage_metadata_callback()`` aggregate because deepagents invokes it inside the parent
    ``task`` tool call, within that inheritable-contextvar scope (verified — see the module
    docstring + ``test_gateway.py``).
    """
    summarizer_model = registry.build_chat_model(cfg, "log_summarizer")
    runnable = create_agent(
        summarizer_model,
        tools=[],
        system_prompt=_LOG_SUMMARIZER_PROMPT,
    )
    return CompiledSubAgent(
        name=LOG_SUMMARIZER_SUBAGENT,
        description=_LOG_SUMMARIZER_DESCRIPTION,
        runnable=runnable,
    )


def _model_profile_key(model: Any) -> str | None:
    """Derive the key deepagents matches a harness profile against for a *pre-built* model.

    Mirrors deepagents' ``_harness_profile_for_model`` (spec-less path): ``provider:identifier``
    when both are known and the identifier is bare, else the identifier (already ``provider:model``
    shaped) or the bare provider. Registering the summarizer-exclusion profile under THIS key
    guarantees the default summarizer is excluded for the actual model instance — including an
    injected fake test model (which derives to e.g. ``"bindablefake"``, not the config model_key).

    Caveat (upgrade gate): imports the beta-private ``deepagents._models`` helpers; re-verify on any
    deepagents bump (see docs/api-notes.md). A None result (unresolvable) simply skips the extra
    registration — the real model still gets the exclusion via the config ``model_key`` profile.
    """
    from deepagents._models import get_model_identifier, get_model_provider

    identifier = get_model_identifier(model)
    provider = get_model_provider(model)
    if provider and identifier and ":" not in identifier:
        return f"{provider}:{identifier}"
    if identifier is not None and ":" in identifier:
        return identifier
    return provider


def _make_config_resolver(cfg: AppConfig) -> Any:
    """Resolve a policy config-interpolation ref (``"${a.b.c}"``) to its value on ``cfg``.

    The engine collects every ref used by a ``flag_value_not_in`` predicate and resolves it once
    at construction (fail-loud on a typo'd/unbound ref), then again per matching decision. P1's
    only ref is ``${targets.kubernetes.allowed_contexts}``.
    """

    def resolve_ref(ref: str) -> Any:
        path = ref.strip()
        if path.startswith("${") and path.endswith("}"):
            path = path[2:-1]
        obj: Any = cfg
        for part in path.split("."):
            obj = getattr(obj, part)
        return obj

    return resolve_ref


def _configured_credential_families(cfg: AppConfig) -> set[str]:
    """The credential families actually configured (the boot coverage gate's ground truth).

    * kubectl — iff a read kubeconfig is set.
    * helm — same condition: helm talks to the cluster with the kubectl-family kubeconfig
      (the executor maps family "helm" to the same KUBECONFIG selection).
    * gh — iff ``targets.github.token_env`` names the env var holding the read-only PAT
      (the executor refuses gh-family calls with CredentialUnavailable when unset, but the
      pack's allow rules are only bootable when the credential is configured).
    * gh-rw — the WRITE pseudo-family (P5f): iff ``targets.github.token_env_rw`` names the env var
      holding the write PAT. The gh-write pack's rw allows require it at boot (the rw coverage
      gate in ``check_credential_coverage`` maps a gh pack's ``channel: rw`` allows to ``"gh-rw"``),
      so a gh-write allow with no write PAT configured refuses to boot — mirroring the ro gh gate.
    * aws / gcloud / az — iff the matching cloud target names ≥1 credential env var (P5a). The
      ``az`` family reads ``targets.azure`` (the Azure CLI binary/family is ``az``, the config
      target is spelled ``azure``). An empty ``credential_env`` list is treated as unconfigured,
      so a shipped cloud pack with allow rules refuses to boot until a credential is named.
    * ssh — iff ``targets.ssh.key_env`` names the env var holding the private-key path (P5b). The
      credential is the config-pinned key + known_hosts; the ssh pack's allow rule is only bootable
      once it is named (the executor refuses any ssh_run call with CredentialUnavailable meanwhile).
    """
    families: set[str] = set()
    if cfg.targets.kubernetes.kubeconfig_ro is not None:
        families.add("kubectl")
        families.add("helm")
    if cfg.targets.github.token_env is not None:
        families.add("gh")
    if cfg.targets.github.token_env_rw is not None:
        families.add("gh-rw")
    if cfg.targets.aws.credential_env:
        families.add("aws")
    if cfg.targets.gcloud.credential_env:
        families.add("gcloud")
    if cfg.targets.azure.credential_env:
        families.add("az")
    if cfg.targets.ssh.key_env is not None:
        families.add("ssh")
    return families


def _register_profile_once(key: str, profile: HarnessProfile) -> None:
    """Register ``profile`` under ``key`` at most once per process (idempotent across builds)."""
    with _registry_lock:
        if key in _registered_profiles:
            return
        register_harness_profile(key, profile)
        _registered_profiles.add(key)


def _register_harness_profiles(model_key: str, model: Any) -> None:
    """Register the harness profile(s) scoping ``task`` and swapping the summarizer.

    Two concerns, two scopes:

    * **Real-model-only** (general-purpose-subagent drop + execute hide + summarizer swap): keyed by
      the config ``model_key``. deepagents matches a profile against the model *object*, so this
      applies to the real configured ``ChatAnthropic`` and NOT to the fake models the graph tests
      inject (they resolve to a different key). ``excluded_tools`` filters ``execute`` from the
      model request (it stays bound but unseen); ``general_purpose_subagent(enabled=False)`` drops
      the auto-added general-purpose subagent so ``task`` (bound because :func:`build_agent` passes
      the named log-summarizer) exposes ONLY that one subagent. A fake build keeps the
      general-purpose
      subagent too, but the policy denies every ``subagent_type`` other than the log-summarizer.
    * **Every-build** (summarizer swap): keyed by the model INSTANCE's derived key when it differs
      from ``model_key`` (i.e. an injected fake). Without this the fake build would keep the
      default (main-model) summarizer AND add ours — two summarizers. The exclusion here is
      summarizer-only.

    Caveat (upgrade gate): ``deepagents.profiles`` / ``deepagents._models`` are beta APIs and this
    mutates process-global profile state. ``task`` is bound on every build (a named subagent is
    always passed), so a future deepagents change to profile matching degrades to "the
    general-purpose subagent re-exposed" — still policy-denied — rather than a crash; re-verify on
    any deepagents bump (see docs/api-notes.md).
    """
    _register_profile_once(
        model_key,
        HarnessProfile(
            excluded_tools=frozenset({"execute"}),
            excluded_middleware=frozenset({_SUMMARIZER_NAME}),
            general_purpose_subagent=GeneralPurposeSubagentProfile(enabled=False),
        ),
    )
    derived = _model_profile_key(model)
    if derived is not None and derived != model_key:
        _register_profile_once(
            derived, HarnessProfile(excluded_middleware=frozenset({_SUMMARIZER_NAME}))
        )


def _resolved_profiles(cfg: AppConfig) -> dict[str, ResolvedProfile]:
    """Resolve every budget profile (``default`` + each named) to a full ``ResolvedProfile``.

    Done once at build so :class:`CostCapMiddleware` can pick the per-run one from
    ``runtime.context.budget_profile`` without re-resolving on every hook call.
    """
    names = ["default", *cfg.budgets.per_run.profiles]
    return {name: cfg.budgets.profile(name) for name in names}


class RunLifecycleMiddleware(AgentMiddleware[BudgetStateMixin, Any, Any]):
    """Write the audit-chain book-ends *in-graph* — for the SERVER build path only (T16).

    Chain-locality problem
    ----------------------
    :class:`LocalGateway` book-ends every run itself: ``audit.start_run`` before ``ainvoke`` and
    ``audit.end_run`` after, in the SAME process the graph runs in, so ``run_started`` /
    ``run_completed`` land in the same per-run chain file (``audit/<run_id>.jsonl``) as the
    in-graph ``decision`` / ``execution`` / ``escalation`` events ``PolicyMiddleware`` writes. In
    **service mode** the graph runs inside the LangGraph Server on a *different* machine from
    :class:`~opendevops.gateway.server.ServerGateway`; if the gateway wrote the book-ends they
    would land on the gateway host while the middleware events land on the server host — a split,
    unverifiable chain. So the book-ends move *into the graph*, co-located with every other event.

    Enabled only on the server build (``build_agent(..., run_lifecycle=True)``), so ``LocalGateway``
    keeps writing its own book-ends and its 400+ tests stay byte-identical — a server-built graph
    with this middleware and a local-built graph without it differ by exactly these two events.

    * ``abefore_model`` seeds the chain with ``start_run`` — **durably idempotent** (T16), so the
      many model calls of a run (and a node re-execution after an ``interrupt()`` resume) collapse
      to a single ``run_started``. Placed first in the stack so the seed precedes any policy append,
      even when a budget middleware jumps-to-end on the very first call.
    * ``aafter_agent`` closes it with ``run_completed``. It fires exactly once at the true end of
      the agent, and — crucially — does NOT fire while a run is SUSPENDED on an escalation
      (``interrupt()`` bubbles out before ``after_agent``), so the chain correctly stays open across
      a suspend and is closed only when the resumed run finally ends. This mirrors ``LocalGateway``
      keep-open-on-suspend / close-on-completion.

    Resume across a process boundary (T16 — the fix that made this shape production-safe): on a
    resume the tools node re-executes BEFORE ``abefore_model``, so if a server RESTART or a
    DIFFERENT worker handles the resume, the fresh :class:`AuditLogger`'s first touch is a policy
    ``append``, not the ``start_run`` seed. :class:`AuditLogger` therefore rehydrates an open chain
    from disk on ANY of append / end_run / start_run — the approved append continues the chain
    (rather than fail-closed denying the human-approved action), the seed durably no-ops (no second
    genesis line), and the replayed decision/escalation still dedupe. (langgraph serializes a
    thread's run to one worker at a time, so an open chain always has a single live writer.)

    Availability-vs-fail-closed decision (deliberate): both hooks SWALLOW an audit failure
    (``logger.exception``, then continue) — an audit-sink hiccup must never crash a live in-flight
    server run, because the ``run_started`` / ``run_completed`` book-ends are *availability* markers
    for the run, not an authorization gate. This is the OPPOSITE posture from a tool-level audit
    write: :class:`PolicyMiddleware` still fails **closed** (denies the tool) if ITS
    ``decision`` / ``execution`` append raises, because that append gates an action. So a lost
    book-end degrades to a chain that merely lacks its open/close marker (still verifiable, a
    crash-shaped hole), while a lost policy append never lets an unaudited action through.

    Accounting divergence (see :class:`ServerGateway`): the gateway-side usage-metadata callback
    cannot see the server-side model calls, so ``cost_authoritative`` is set equal to the in-graph
    ``cost_state`` (``run_cost_usd``) and ``usage`` is flagged ``authoritative_unavailable`` — the
    weekly LangSmith cross-check (PLAN §6) is the compensating control.
    """

    state_schema = BudgetStateMixin

    def __init__(
        self,
        audit: AuditLogger,
        model_key: str,
        policy_version: str,
        git_sha: str | None,
    ) -> None:
        super().__init__()
        self._audit = audit
        self._model_key = model_key
        self._policy_version = policy_version
        self._git_sha = git_sha

    async def abefore_model(
        self, state: BudgetStateMixin, runtime: Runtime[Any]
    ) -> dict[str, Any] | None:
        """Idempotently seed the run chain (``run_started``) before any policy/budget append."""
        run_id = _ctx_attr(runtime, "run_id")
        if not run_id:
            # No safe fallback: without a run_id there is no chain to correlate. PolicyMiddleware
            # fails closed on the same condition; here we simply skip the seed (best-effort audit).
            logger.warning("run-lifecycle: no run_id in context; skipping run_started seed")
            return None
        try:
            self._audit.start_run(str(run_id), **self._header(runtime))
        except Exception:  # noqa: BLE001 - an audit hiccup must never crash a live server run
            logger.exception("run-lifecycle: start_run failed for run %s", run_id)
        return None

    async def aafter_agent(
        self, state: BudgetStateMixin, runtime: Runtime[Any]
    ) -> dict[str, Any] | None:
        """Close the run chain (``run_completed``) with the in-graph cost/usage summary."""
        run_id = _ctx_attr(runtime, "run_id")
        if not run_id:
            return None
        st = cast_state(state)
        cost_state = float(st.get("run_cost_usd") or 0.0)
        usage: dict[str, Any] = dict(st.get("run_usage") or {})
        # The gateway callback cannot see server-side calls; authoritative == state here.
        usage["authoritative_unavailable"] = True
        try:
            self._audit.end_run(
                str(run_id),
                summary={
                    "status": "completed",
                    "cost_state": cost_state,
                    "cost_authoritative": cost_state,
                    "usage": usage,
                    "budget_stop": st.get("budget_stop"),
                },
            )
        except Exception:  # noqa: BLE001 - an audit hiccup must never crash a live server run
            logger.exception("run-lifecycle: end_run failed for run %s", run_id)
        return None

    def _header(self, runtime: Runtime[Any]) -> dict[str, Any]:
        """The run-scoped audit header — identical shape to ``LocalGateway._audit_header``."""
        return {
            "principal": {
                "interface": _ctx_attr(runtime, "interface") or "unknown",
                "user": _ctx_attr(runtime, "principal") or "unknown",
            },
            "environment": _ctx_attr(runtime, "environment") or "staging",
            "model": self._model_key,
            "policy_version": self._policy_version,
            "agent_git_sha": self._git_sha,
        }


def _ctx_attr(runtime: Any, name: str) -> Any:
    """Read ``name`` off ``runtime.context`` (attribute for a dataclass/model, key for a dict)."""
    context = getattr(runtime, "context", None)
    if context is None:
        return None
    value = getattr(context, name, None)
    if value is None and isinstance(context, dict):
        value = context.get(name)
    return value


def cast_state(state: Any) -> dict[str, Any]:
    """Read the agent state as a mapping (it is a ``dict`` at runtime under langgraph)."""
    return state if isinstance(state, dict) else dict(state)


def build_agent(
    cfg: AppConfig,
    *,
    audit: AuditLogger,
    counter: DailyCounter,
    checkpointer: Any = None,
    run_lifecycle: bool = False,
) -> CompiledStateGraph[Any, Any, Any, Any]:
    """Assemble the compiled deepagents graph with the full safety-middleware stack.

    Args:
        cfg: the validated application config.
        audit: the shared :class:`AuditLogger` (the gateway seeds/closes the run chain).
        counter: the shared :class:`DailyCounter` for the daily USD envelopes.
        checkpointer: optional langgraph checkpointer (``None`` in P1; sqlite saver in P2). The
            SERVER build path passes ``None`` — the LangGraph platform injects Postgres
            checkpointing; a saver must never be attached on that path (plan mandate).
        run_lifecycle: enable the in-graph :class:`RunLifecycleMiddleware` audit book-ends. Kept
            ``False`` (the default) for :class:`LocalGateway`, which writes its own book-ends;
            :func:`server_graph` passes ``True`` so the SERVER build writes ``run_started`` /
            ``run_completed`` into the same per-run chain file as the in-graph events.

    Raises:
        RuntimeError: on a credential-coverage gap, a surplus bound tool, or a lost state reducer.
    """
    # Defensive re-assertion of the load-time invariant (every agent model is priced).
    registry.assert_all_agents_priced(cfg)

    model_key = registry.resolve(cfg, "main")
    model = registry.build_chat_model(cfg, "main")

    # --- policy engine ------------------------------------------------------------------
    loaded = load_policy(cfg.policy.dir)
    coverage_gaps = check_credential_coverage(loaded, _configured_credential_families(cfg))
    if coverage_gaps:
        raise RuntimeError(
            "policy has allow rules whose credential family is not configured; refusing to "
            "boot:\n  - " + "\n  - ".join(coverage_gaps)
        )
    engine = YamlRuleEngine(loaded, _make_config_resolver(cfg))

    # --- budget middleware caps (T14: per-run profile, resolved from runtime.context) -----
    # Resolve every profile once here; CostCapMiddleware picks the per-run one from
    # runtime.context.budget_profile in its hook (see module docstring). The langchain count-limit
    # middlewares can't read context, so they take the max count across profiles (documented
    # ceiling); the tighter per-run USD cap still stops the run first for the profile that matters.
    profiles = _resolved_profiles(cfg)
    price_table = PriceTable.from_config(cfg.models)
    max_model_calls = max(p.model_calls for p in profiles.values())
    max_tool_calls = max(p.tool_calls for p in profiles.values())
    max_shell_calls = max(p.shell_calls for p in profiles.values())

    # One backend shared by the compiled graph and our summarizer replacement (so the summarizer
    # offloads evicted history to the same StateBackend the built-in file tools use).
    backend = StateBackend()

    # --- middleware stack (PolicyMiddleware LAST = innermost wrap = closest to execution) ---
    # RunLifecycleMiddleware (server build only) goes FIRST so its ``abefore_model`` seeds the
    # audit chain before any other middleware's append and before any jump-to-end.
    middleware: list[Any] = []
    if run_lifecycle:
        middleware.append(
            RunLifecycleMiddleware(audit, model_key, loaded.policy_version, agent_git_sha())
        )
    middleware += [
        CostCapMiddleware(price_table, model_key, profiles, cfg.budgets.trip_ratio),
        DailyBudgetMiddleware(
            price_table,
            model_key,
            counter,
            cfg.budgets.daily,
            fail_mode=cfg.budgets.fail_mode_on_counter_outage,
        ),
        ModelCallLimitMiddleware(run_limit=max_model_calls, exit_behavior="end"),
        ToolCallLimitMiddleware(run_limit=max_tool_calls, exit_behavior="continue"),
        ToolCallLimitMiddleware(
            tool_name="run_command", run_limit=max_shell_calls, exit_behavior="continue"
        ),
        # Replace deepagents' default (main-model) summarizer with the haiku-backed one. The
        # matching harness-profile exclusion (registered below) drops the default so this is an
        # in-place, name-matched swap — see the module docstring.
        _build_summarizer(cfg, backend),
        # Collapse any parallel tool-call turn to a single call BEFORE PolicyMiddleware sees it, so
        # the escalate interrupt()'s replay window can never contain a sibling to double-execute
        # (the third replay-safety layer; see policy/guard.py). Innermost custom model wrap.
        SingleToolCallMiddleware(),
        PolicyMiddleware(engine, audit, loaded, model_key),
    ]

    # For the production model: hide `execute`, disable the auto-added general-purpose subagent (so
    # `task` exposes ONLY our named log-summarizer, passed to create_deep_agent below), and exclude
    # the default summarizer so our haiku replacement above takes its place (real model + injected
    # fake instance both).
    _register_harness_profiles(model_key, model)

    graph = create_deep_agent(
        model=model,
        tools=[_run_command_tool(cfg), _ssh_run_tool(cfg)],
        system_prompt=SYSTEM_PROMPT,
        middleware=middleware,
        # The main agent's single named subagent (P5c): a tool-less haiku log-summarizer, delegated
        # to via `task`. Passing it exposes `task` (bound as an active tool, scoped by policy to
        # this one subagent_type); the harness profile above keeps the general-purpose subagent
        # disabled for the production model, so production `task` exposes ONLY this subagent.
        subagents=[_build_log_summarizer_subagent(cfg)],
        backend=backend,
        state_schema=DevOpsState,
        context_schema=AgentContext,
        checkpointer=checkpointer,
    )

    _assert_tool_inventory(graph)
    _assert_reducer_channels(graph)
    return graph


def _run_command_tool(cfg: AppConfig) -> Any:
    """Build the single argv-only execution tool (imported lazily to keep import cost low).

    Selects the execution backend from ``cfg.executor.mode`` (P5d): ``local`` (default) keeps the
    in-process ``LocalExecutor`` (``select_executor`` returns ``None`` → unchanged); ``remote``
    wires a ``RemoteExecutor`` that signs each exec and posts it to the executor service.
    """
    from opendevops.tools.executor import select_executor
    from opendevops.tools.run_command import make_run_command

    return make_run_command(cfg, executor=select_executor(cfg))


def _ssh_run_tool(cfg: AppConfig) -> Any:
    """Build the structured ssh_run remote-exec tool (imported lazily; asyncssh stays optional).

    The tool is bound on every build so the inventory is stable (``EXPECTED_ACTIVE`` includes
    ``ssh_run``); ``asyncssh`` is imported only when a call actually executes (see
    :class:`~opendevops.tools.executor.SshExecutor`). When no ssh pack ships / ``targets.ssh`` is
    unconfigured, the engine default-denies every ssh_run call — the tool is bound but inert.
    """
    from opendevops.tools.ssh_run import make_ssh_run

    return make_ssh_run(cfg)


def agent_git_sha() -> str | None:
    """Best-effort short git sha of the working tree, or ``None`` outside a repo / on error.

    Shared by the gateway book-ends (``LocalGateway``) and the in-graph
    :class:`RunLifecycleMiddleware` (server build) so both stamp the same ``agent_git_sha`` on a
    run's audit header.
    """
    import subprocess

    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    sha = out.stdout.strip()
    return sha or None


# --------------------------------------------------------------------------------------
# boot assertions (fail-closed)
# --------------------------------------------------------------------------------------


def _bound_tool_names(graph: CompiledStateGraph[Any, Any, Any, Any]) -> set[str]:
    """The names of every tool bound into the compiled graph's ToolNode.

    Recipe verified in docs/api-notes.md §7: the ``tools`` node is a ``ToolNode`` whose
    ``.bound.tools_by_name`` is the ``{name: tool}`` map. ``.bound`` is typed as a bare
    ``Runnable`` (no ``tools_by_name``), so read it through an ``Any`` local.
    """
    tools_node: Any = graph.nodes["tools"]
    return set(tools_node.bound.tools_by_name.keys())


def _assert_tool_inventory(graph: CompiledStateGraph[Any, Any, Any, Any]) -> None:
    """Fail boot unless the bound tools are exactly EXPECTED_ACTIVE (+ tolerated built-ins).

    Reads the module-level ``EXPECTED_ACTIVE`` / ``TOLERATED_DENIED`` at call time so a test can
    monkeypatch them to prove the assertion actually checks (a smaller EXPECTED_ACTIVE turns the
    previously-expected tools into surplus and raises).
    """
    bound = _bound_tool_names(graph)
    missing = EXPECTED_ACTIVE - bound
    surplus = bound - EXPECTED_ACTIVE - TOLERATED_DENIED
    if missing or surplus:
        raise RuntimeError(
            "tool inventory mismatch — refusing to boot a graph binding tools the policy layer "
            f"has not vetted. missing={sorted(missing)} surplus={sorted(surplus)} "
            f"(bound={sorted(bound)})"
        )


def _assert_reducer_channels(graph: CompiledStateGraph[Any, Any, Any, Any]) -> None:
    """Fail boot if any accumulating state channel lost its commutative reducer.

    Load-bearing for the per-run USD cap: ``run_cost_usd`` must be a ``BinaryOperatorAggregate``
    (summing ``_add_cost`` reducer). If T7's ``DevOpsState`` composition ever flattened the
    ``BudgetStateMixin`` annotations into plain ``LastValue`` fields, the cap would silently see
    only the last model call. We make that a boot failure, not a silent budget hole.
    """
    from langgraph.channels.binop import BinaryOperatorAggregate

    channels = getattr(graph, "channels", {})
    for key in _REDUCER_CHANNELS:
        channel = channels.get(key)
        if not isinstance(channel, BinaryOperatorAggregate):
            raise RuntimeError(
                f"state channel {key!r} is {type(channel).__name__}, not BinaryOperatorAggregate "
                "— the accumulating reducer was lost, so per-run accounting would silently become "
                "last-write-only. Refusing to boot."
            )


# --------------------------------------------------------------------------------------
# module-level lazy singleton for langgraph.json / `langgraph dev`
# --------------------------------------------------------------------------------------

_AGENT_SINGLETON: CompiledStateGraph[Any, Any, Any, Any] | None = None
_SINGLETON_LOCK = threading.Lock()


def get_agent() -> CompiledStateGraph[Any, Any, Any, Any]:
    """Lazily build (once) the module's default agent from the on-disk config.

    Used by ``langgraph.json`` / ``langgraph dev`` where a module-level graph is expected. Builds
    its own durable audit logger + daily counter; the T9 gateway constructs its own graph with
    *shared* instances instead of using this singleton. Kept lazy so importing this module (e.g.
    in unit tests) never requires a valid on-disk config.
    """
    global _AGENT_SINGLETON
    with _SINGLETON_LOCK:
        if _AGENT_SINGLETON is None:
            from opendevops.audit.logger import AuditLogger
            from opendevops.budget.daily import build_daily_counter
            from opendevops.config import load_config

            cfg = load_config()
            audit = AuditLogger(cfg.audit.dir)
            counter = build_daily_counter(cfg)
            _AGENT_SINGLETON = build_agent(cfg, audit=audit, counter=counter)
        return _AGENT_SINGLETON


# --------------------------------------------------------------------------------------
# server graph export for langgraph.json / self-hosted LangGraph Server (P3, T16)
# --------------------------------------------------------------------------------------

# The env var naming the config.yaml the Server loads (default: the shipped ``config/config.yaml``
# relative to the Server's working directory). Its grandparent is the project root ``load_config``
# reads ``config/{config,models,budgets}.yaml`` + ``.env`` from.
_SERVER_CONFIG_ENV = "OPENDEVOPS_CONFIG"


def _load_server_config() -> AppConfig:
    """Load ``AppConfig`` for the server graph from ``$OPENDEVOPS_CONFIG`` (default cwd)."""
    from opendevops.config import load_config

    raw = os.environ.get(_SERVER_CONFIG_ENV)
    if raw:
        # The env var points at ``.../config/config.yaml``; the root is its grandparent so
        # ``load_config`` finds the sibling ``models.yaml`` / ``budgets.yaml`` and ``.env``.
        return load_config(Path(raw).expanduser().resolve().parent.parent)
    return load_config()


def server_graph() -> CompiledStateGraph[Any, Any, Any, Any]:
    """Zero-arg factory the LangGraph Server imports per ``langgraph.json`` (``:server_graph``).

    Builds the compiled agent from the on-disk config with **no checkpointer** — the LangGraph
    platform injects Postgres checkpointing, so attaching a saver here would double-wire persistence
    (plan mandate). Enables :class:`RunLifecycleMiddleware` (``run_lifecycle=True``) so the audit
    book-ends are written server-side, in the same per-run chain file as the in-graph events, which
    :class:`~opendevops.gateway.server.ServerGateway` (a different host) cannot write. Builds a
    fresh durable ``AuditLogger`` + a
    :func:`~opendevops.budget.daily.build_daily_counter`-selected counter — the shared
    ``RedisDailyCounter`` when ``budgets.daily.backend == "redis"`` (so every Server worker
    accumulates one daily envelope), else the durable sqlite ledger.
    """
    from opendevops.audit.logger import AuditLogger
    from opendevops.budget.daily import build_daily_counter

    cfg = _load_server_config()
    audit = AuditLogger(cfg.audit.dir)
    counter = build_daily_counter(cfg)
    return build_agent(cfg, audit=audit, counter=counter, checkpointer=None, run_lifecycle=True)


def __getattr__(name: str) -> Any:
    """PEP 562 lazy export: ``from opendevops.agent import agent`` builds on first access.

    Guarding the build behind attribute access (rather than a module-level call) means importing
    this module — as the unit tests do — never touches the filesystem config or constructs a
    model. Accessing ``agent`` without a valid config raises a clear, contextual error.
    """
    if name == "agent":
        try:
            return get_agent()
        except Exception as exc:  # noqa: BLE001 - re-raise with actionable context
            raise RuntimeError(
                "opendevops.agent.agent could not be constructed from the on-disk config "
                f"(run `opendevops config check`): {exc}"
            ) from exc
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
