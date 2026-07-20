"""``DevOpsState`` — the agent's graph state schema (T7).

Composition (verified against the installed deepagents 0.6.12 / langgraph 1.2.9):

* ``DeepAgentState`` contributes ``messages`` (delta-channel reducer) and the planning/FS
  channels used by the deepagents stack.
* ``BudgetStateMixin`` (T6) contributes ``run_cost_usd`` / ``run_usage`` / ``budget_stop`` and
  is composed **by inheritance** — this is critical. Those fields carry commutative reducer
  annotations (``_add_cost`` sums per-call USD, ``_merge_usage`` merges token counters). If
  they were re-declared here as plain fields, langgraph would wire a ``LastValue`` channel that
  *replaces* rather than accumulates, so the per-run USD cap would only ever see the last
  model call and would silently never fire. T6 flagged this as CRITICAL; a probe confirmed the
  ``DeepAgentState`` + ``BudgetStateMixin`` MRO merge preserves every reducer:
  ``get_type_hints(DevOpsState, include_extras=True)`` keeps ``run_cost_usd`` -> ``_add_cost``,
  ``run_usage`` -> ``_merge_usage``, and ``messages`` -> its delta reducer, and langgraph then
  builds a ``BinaryOperatorAggregate`` channel for each.
* ``tool_results_cache`` (this module) maps ``tool_call_id`` -> cached ``ToolMessage`` content,
  written by ``PolicyMiddleware`` after a tool executes. It uses a dict-merge reducer so the
  one-entry partial update each ``wrap_tool_call`` returns accumulates into the map instead of
  clobbering it — the same ``Annotated[type, reducer]`` idiom the installed deepagents/langchain
  state classes (``FilesystemState.files``, ``BudgetStateMixin.run_cost_usd``) use.
"""

from __future__ import annotations

from typing import Annotated, NotRequired

from deepagents import DeepAgentState

from opendevops.budget.middleware import BudgetStateMixin


def _merge_tool_cache(
    left: dict[str, str] | None, right: dict[str, str] | None
) -> dict[str, str]:
    """Reducer for ``tool_results_cache``: right-biased dict merge (never whole-value replace).

    Commutative for the disjoint ``{tool_call_id: content}`` writes the middleware produces
    (each tool_call_id is written once), so ordering across concurrent tool calls in a
    super-step does not matter. A plain (LastValue) field would drop every prior cache entry on
    each write, defeating the interrupt-resume de-duplication the cache exists to provide.
    """
    merged: dict[str, str] = dict(left or {})
    merged.update(right or {})
    return merged


def _merge_dry_run_ok(
    left: dict[str, bool] | None, right: dict[str, bool] | None
) -> dict[str, bool]:
    """Reducer for ``dry_run_ok``: right-biased dict merge (same idiom as ``tool_results_cache``).

    Maps a staged manifest's content sha256 -> ``True`` once a server-side ``kubectl apply
    --dry-run=server`` of exactly that manifest has succeeded (exit 0) in this run. The
    ``dry_run_before_apply`` policy hook reads this map to permit a later real apply
    (``--dry-run=none``) of the identical manifest. A commutative merge (each sha written once,
    only ever to ``True``) so the one-entry partial update the middleware returns after a
    successful dry-run accumulates across tool calls instead of clobbering earlier entries — a
    plain LastValue field would forget every previously-validated manifest on each new write.
    """
    merged: dict[str, bool] = dict(left or {})
    merged.update(right or {})
    return merged


# ``type: ignore[misc]``: mypy rejects the multi-base TypedDict because ``DeepAgentState`` comes
# from the untyped ``deepagents`` package (``ignore_missing_imports``), so mypy cannot see it is a
# TypedDict and flags "all bases of a new TypedDict must be TypedDict types". At runtime the merge
# is correct and verified — a StateGraph over ``DevOpsState`` wires a ``BinaryOperatorAggregate``
# (reducer) channel for ``run_cost_usd`` / ``run_usage`` / ``tool_results_cache`` / ``messages``
# (see tests/unit/policy/test_middleware.py::test_devops_state_channels_are_accumulating_reducers).
class DevOpsState(DeepAgentState, BudgetStateMixin):  # type: ignore[misc]
    """The graph state schema: deepagents channels + T6 budget keys + the tool-result cache."""

    tool_results_cache: NotRequired[Annotated[dict[str, str], _merge_tool_cache]]
    dry_run_ok: NotRequired[Annotated[dict[str, bool], _merge_dry_run_ok]]
