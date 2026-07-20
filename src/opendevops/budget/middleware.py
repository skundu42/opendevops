"""Per-run and daily USD budget enforcement as langchain v1 agent middleware.

Two middlewares, both consuming the :class:`~opendevops.models.pricing.PriceTable`:

* :class:`CostCapMiddleware` — the *per-run* USD ceiling. ``aafter_model`` prices each model
  call and accumulates it into ``run_cost_usd``; ``abefore_model`` jumps to end once spend
  crosses ``trip_ratio * profile.usd``.
* :class:`DailyBudgetMiddleware` — the *daily* USD envelopes (a single ``global`` cap plus a
  per-``principal`` cap) backed by a :class:`~opendevops.budget.daily.DailyCounter`.

Ordering-immunity rule
-----------------------
Each budget middleware computes the cost of a model call ITSELF from
``AIMessage.usage_metadata`` via the shared ``PriceTable`` — stateless per-call math; no
middleware reads a ``run_cost_usd`` delta another middleware produced, so ``after_model``'s
reverse-order execution cannot corrupt accounting. Concretely the hooks return per-call
*contributions* and the state channels accumulate them through commutative reducers
(:func:`_add_cost`, :func:`_merge_usage`): reordering or interleaving the writers yields the
same totals. ``run_usage`` in particular has two writers in the same super-step on the
counter-write-failure path (CostCap's token counts + DailyBudget's ``counter_write_failed``
flag), which only stays correct because ``_merge_usage`` merges rather than replaces.

Defense-in-depth (the full stop-loss table; only the first two rows live here)
------------------------------------------------------------------------------
* **per-run USD**   — :class:`CostCapMiddleware`      (this module)
* **daily USD**     — :class:`DailyBudgetMiddleware`  (this module)
* **call counts**   — langchain ``ModelCallLimitMiddleware`` / ``ToolCallLimitMiddleware``
  (constructed and wired directly by ``agent.py`` — deliberately *not* wrapped or re-exported here)
* **recursion / wall-clock** — enforced at the gateway (langgraph ``recursion_limit`` +
  a wall-clock guard), outside the middleware chain.

State contract for the graph assembly
-------------------------------------
The budget state keys live in :class:`BudgetStateMixin` (an ``AgentState`` extension) and are
advertised to the graph via each middleware's ``state_schema`` attribute — the same mechanism
langchain's own ``ModelCallLimitMiddleware`` uses. **``DevOpsState`` must compose
``BudgetStateMixin`` by inheritance so the reducer-annotated fields are preserved.** If it
re-declares ``run_cost_usd`` / ``run_usage`` as plain fields, langgraph will *replace* rather
than accumulate them and per-run accounting silently collapses to the last call only — so
either inherit the mixin or reuse :func:`_add_cost` / :func:`_merge_usage` verbatim.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Annotated, Any, Literal, NotRequired, cast

from langchain.agents.middleware import AgentMiddleware, AgentState, hook_config
from langchain_core.messages import AIMessage
from langgraph.runtime import Runtime

from opendevops.budget.daily import DailyCounter
from opendevops.config import Daily, ResolvedProfile
from opendevops.models.pricing import PriceTable

logger = logging.getLogger(__name__)

_UNKNOWN_PRINCIPAL = "unknown"


# --------------------------------------------------------------------------------------
# state reducers (commutative -> ordering-immune accumulation)
# --------------------------------------------------------------------------------------


def _add_cost(left: float | None, right: float | None) -> float:
    """Reducer for ``run_cost_usd``: sum per-call USD contributions (``None`` == ``0``)."""
    return (left or 0.0) + (right or 0.0)


def _merge_usage(left: dict[str, Any] | None, right: dict[str, Any] | None) -> dict[str, Any]:
    """Reducer for ``run_usage``: sum numeric token counters, OR boolean flags.

    Commutative and non-mutating, so two middlewares writing ``run_usage`` in the same
    super-step (CostCap's token counts + DailyBudget's ``counter_write_failed`` flag) merge
    cleanly regardless of ``after_model`` execution order.
    """
    merged: dict[str, Any] = dict(left or {})
    for key, value in (right or {}).items():
        if isinstance(value, bool):
            merged[key] = bool(merged.get(key, False)) or value
        elif isinstance(value, (int, float)):
            merged[key] = merged.get(key, 0) + value
        else:
            merged[key] = value
    return merged


class BudgetStateMixin(AgentState[Any]):
    """Budget accounting keys, mixed into ``DevOpsState`` (via inheritance).

    * ``run_cost_usd`` — accumulated per-run USD spend (reducer: :func:`_add_cost`).
    * ``run_usage``    — accumulated token counters + blind-spot/failure flags
      (``input_tokens``/``output_tokens``/``cache_read``/``cache_creation``/``usage_missing``
      as ints, ``counter_write_failed`` as a bool; reducer: :func:`_merge_usage`).
    * ``budget_stop``  — set once when a cap trips: ``{"kind": ..., ...}`` describing why the
      run was stopped (``per_run_usd`` / ``daily_usd`` / ``counter_outage``).
    """

    run_cost_usd: NotRequired[Annotated[float, _add_cost]]
    run_usage: NotRequired[Annotated[dict[str, Any], _merge_usage]]
    budget_stop: NotRequired[dict[str, Any] | None]


# --------------------------------------------------------------------------------------
# shared helpers
# --------------------------------------------------------------------------------------


def _new_ai_messages(state: dict[str, Any]) -> list[AIMessage]:
    """The model's just-produced output: the trailing run of ``AIMessage``s in ``messages``.

    A fresh model call appends one (occasionally more) ``AIMessage`` to the end of the
    transcript; the previous call's ``AIMessage`` is always separated from it by the
    intervening human/tool message, so the trailing run isolates exactly this call's output.
    """
    messages = state.get("messages") or []
    trailing: list[AIMessage] = []
    for message in reversed(messages):
        if isinstance(message, AIMessage):
            trailing.append(message)
        else:
            break
    trailing.reverse()
    return trailing


def _per_run_notice(spent: float, cap: float) -> str:
    return (
        f"Budget cap reached: spent ${spent:.2f} of ${cap:.2f} — stopping. "
        "Completed work is summarized above."
    )


def _daily_notice(scope: str, spent: float, cap: float) -> str:
    return (
        f"Budget cap reached: daily {scope} spend ${spent:.2f} of ${cap:.2f} — stopping. "
        "Completed work is summarized above."
    )


def _outage_notice() -> str:
    return (
        "Budget cap reached: the spend counter is unavailable, stopping (fail-closed). "
        "Completed work is summarized above."
    )


def _jump_to_end(notice: str, budget_stop: dict[str, Any]) -> dict[str, Any]:
    """The langchain v1 jump-to-end return shape: route to ``end`` + inject a final notice."""
    return {
        "jump_to": "end",
        "messages": [AIMessage(content=notice)],
        "budget_stop": budget_stop,
    }


# --------------------------------------------------------------------------------------
# per-run USD cap
# --------------------------------------------------------------------------------------


class CostCapMiddleware(AgentMiddleware[BudgetStateMixin, Any, Any]):
    """Enforce a per-run USD ceiling from the *per-run* budget profile.

    The effective cap is resolved **per run** from ``runtime.context.budget_profile`` against the
    ``profiles`` map injected at construction (all of ``cfg.budgets``'s profiles resolved once at
    build time), so the same compiled graph enforces the ``scheduled`` profile's cap on one run and
    the ``incident`` profile's on the next. An absent/unknown profile name falls back to
    ``default_profile`` — fail-safe, never crashing a live hook on a misconfigured context.

    ``model_key`` is the configured main-agent ``provider:model`` (a single model per run;
    multi-model runs would re-key per call). Pricing math is delegated to the ``PriceTable``;
    this middleware never re-derives USD.
    """

    state_schema = BudgetStateMixin

    def __init__(
        self,
        price_table: PriceTable,
        model_key: str,
        profiles: dict[str, ResolvedProfile],
        trip_ratio: float,
        *,
        default_profile: str = "default",
    ) -> None:
        super().__init__()
        self._price_table = price_table
        self._model_key = model_key
        self._profiles = profiles
        self._trip_ratio = trip_ratio
        self._default_profile = default_profile

    def _resolve_profile(self, runtime: Runtime[Any]) -> ResolvedProfile:
        """Resolve the per-run profile from ``runtime.context.budget_profile`` (fail-safe).

        Falls back to ``default_profile`` when the context is missing, carries no
        ``budget_profile``, or names a profile absent from the injected map — enforcing *a* cap is
        always safer than crashing the hook (which would drop the per-run ceiling entirely).
        """
        context = getattr(runtime, "context", None)
        name = getattr(context, "budget_profile", None)
        if name is None and isinstance(context, dict):
            name = context.get("budget_profile")
        if name is not None and name in self._profiles:
            return self._profiles[name]
        logger.warning(
            "budget_profile %r is unknown or absent; falling back to the %r profile's per-run cap",
            name,
            self._default_profile,
        )
        return self._profiles[self._default_profile]

    @hook_config(can_jump_to=["end"])
    async def abefore_model(
        self, state: BudgetStateMixin, runtime: Runtime[Any]
    ) -> dict[str, Any] | None:
        """Stop the run gracefully once spend crosses ``trip_ratio * profile.usd``."""
        spent = cast(dict[str, Any], state).get("run_cost_usd") or 0.0
        cap = self._resolve_profile(runtime).usd
        if spent >= self._trip_ratio * cap:
            budget_stop = {"kind": "per_run_usd", "spent": spent, "cap": cap}
            return _jump_to_end(_per_run_notice(spent, cap), budget_stop)
        return None

    async def aafter_model(
        self, state: BudgetStateMixin, runtime: Runtime[Any]
    ) -> dict[str, Any] | None:
        """Price this call and return its per-call contribution to ``run_cost_usd``/``run_usage``.

        Never raises: a missing ``usage_metadata`` (or, belt-and-braces, an unpriceable key)
        is counted as one ``usage_missing`` blind spot instead of charging or blowing up.
        """
        cost = 0.0
        usage_delta: dict[str, Any] = {
            "input_tokens": 0,
            "output_tokens": 0,
            "cache_read": 0,
            "cache_creation": 0,
            "usage_missing": 0,
        }
        for message in _new_ai_messages(cast(dict[str, Any], state)):
            usage = message.usage_metadata
            if not usage:
                usage_delta["usage_missing"] += 1
                continue
            try:
                cost += self._price_table.cost_usd(self._model_key, usage)
            except Exception:
                logger.exception(
                    "cost_usd failed for model_key=%r; counting as a usage blind spot",
                    self._model_key,
                )
                usage_delta["usage_missing"] += 1
                continue
            details = usage.get("input_token_details") or {}
            usage_delta["input_tokens"] += usage.get("input_tokens", 0)
            usage_delta["output_tokens"] += usage.get("output_tokens", 0)
            usage_delta["cache_read"] += details.get("cache_read", 0)
            usage_delta["cache_creation"] += details.get("cache_creation", 0)
        return {"run_cost_usd": cost, "run_usage": usage_delta}


# --------------------------------------------------------------------------------------
# daily USD caps (global + per-principal)
# --------------------------------------------------------------------------------------


class DailyBudgetMiddleware(AgentMiddleware[BudgetStateMixin, Any, Any]):
    """Enforce the daily ``global`` and per-``principal`` USD envelopes.

    ``before_model`` reads both scopes' running totals and jumps to end if either is at/over
    its cap; ``after_model`` charges this call's cost to both scopes. Fail-closed by default:
    a counter outage in ``before`` stops the run (there is no safe way to prove headroom), an
    outage in ``after`` continues the run but flags the missed write (the gateway's
    authoritative ledger still records the spend, so killing a live run would only waste it).
    """

    state_schema = BudgetStateMixin

    def __init__(
        self,
        price_table: PriceTable,
        model_key: str,
        counter: DailyCounter,
        daily_cfg: Daily,
        *,
        fail_mode: Literal["closed", "open"] = "closed",
        principal_getter: Callable[[Runtime[Any]], str] | None = None,
    ) -> None:
        super().__init__()
        self._price_table = price_table
        self._model_key = model_key
        self._counter = counter
        self._daily_cfg = daily_cfg
        self._fail_mode = fail_mode
        self._principal_getter = principal_getter

    def _principal(self, runtime: Runtime[Any]) -> str:
        """Resolve the caller principal from ``runtime.context`` (or an injected getter).

        Falls back to ``_UNKNOWN_PRINCIPAL`` so accounting stays fail-safe when the context
        (owned by ``AgentContext``) is unavailable in the hook rather than crashing.
        """
        if self._principal_getter is not None:
            return self._principal_getter(runtime)
        context = getattr(runtime, "context", None)
        if context is None:
            return _UNKNOWN_PRINCIPAL
        principal = getattr(context, "principal", None)
        if principal is None and isinstance(context, dict):
            principal = context.get("principal")
        return principal or _UNKNOWN_PRINCIPAL

    def _call_cost(self, state: dict[str, Any]) -> float | None:
        """Priced USD of this call, or ``None`` when there is nothing to charge (no usage)."""
        cost = 0.0
        charged = False
        for message in _new_ai_messages(state):
            usage = message.usage_metadata
            if not usage:
                continue
            try:
                cost += self._price_table.cost_usd(self._model_key, usage)
                charged = True
            except Exception:
                logger.exception(
                    "cost_usd failed for model_key=%r during daily charge", self._model_key
                )
        return cost if charged else None

    @hook_config(can_jump_to=["end"])
    async def abefore_model(
        self, state: BudgetStateMixin, runtime: Runtime[Any]
    ) -> dict[str, Any] | None:
        principal = self._principal(runtime)
        principal_scope = f"principal:{principal}"
        try:
            global_spent = await self._counter.total("global")
            principal_spent = await self._counter.total(principal_scope)
        except Exception:
            logger.exception("daily counter outage in before_model (fail_mode=%s)", self._fail_mode)
            if self._fail_mode == "closed":
                return _jump_to_end(_outage_notice(), {"kind": "counter_outage"})
            return None

        if global_spent >= self._daily_cfg.global_usd:
            budget_stop = {
                "kind": "daily_usd",
                "scope": "global",
                "spent": global_spent,
                "cap": self._daily_cfg.global_usd,
            }
            return _jump_to_end(
                _daily_notice("global", global_spent, self._daily_cfg.global_usd), budget_stop
            )
        if principal_spent >= self._daily_cfg.per_principal_usd:
            budget_stop = {
                "kind": "daily_usd",
                "scope": principal_scope,
                "spent": principal_spent,
                "cap": self._daily_cfg.per_principal_usd,
            }
            return _jump_to_end(
                _daily_notice(principal_scope, principal_spent, self._daily_cfg.per_principal_usd),
                budget_stop,
            )
        return None

    async def aafter_model(
        self, state: BudgetStateMixin, runtime: Runtime[Any]
    ) -> dict[str, Any] | None:
        cost = self._call_cost(cast(dict[str, Any], state))
        if cost is None:
            return None
        principal = self._principal(runtime)
        try:
            await self._counter.add("global", cost)
            await self._counter.add(f"principal:{principal}", cost)
        except Exception:
            logger.warning(
                "daily counter write failed; run continues, gateway ledger remains authoritative",
                exc_info=True,
            )
            return {"run_usage": {"counter_write_failed": True}}
        return None
