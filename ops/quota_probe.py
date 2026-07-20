"""ops/quota_probe.py — LangGraph Server node-execution quota probe (P3, T18).

The self-hosted LangGraph Server is licensed against a node-execution quota (PLAN §3.7 / open
question 5). This probe estimates monthly consumption so an operator can make the **license-up vs
FastAPI-embed fallback** decision *before* hitting the ceiling: it counts the super-steps of recent
runs (via the checkpoints/threads API) for the top-5 workflow shapes, extrapolates to a monthly
node-execution figure, and compares it to the verified-tier quota — warning when the projection
exceeds ``> 60%`` of quota (the plan's documented fallback trigger).

Everything here is split so CI exercises only the PURE math (super-step counting, workflow-shape
aggregation, extrapolation) with faked API responses — no live server calls in CI. The typer command
wires the live fetch around those pure functions.

Node-executions vs super-steps: the platform meters node executions. This agent collapses parallel
tool calls to one (``SingleToolCallMiddleware``), so its topology runs ~one node per super-step; the
probe therefore uses super-steps as the node-execution proxy (a documented, slightly conservative
1:1 assumption — a graph with genuine fan-out would undercount, so treat the estimate as a floor).

No silent caps (PLAN P3): the projection is summed over the TOP-5 workflow shapes only (the basis),
but any workload beyond that is reported LOUDLY, never silently dropped: :func:`summarize_shapes`
surfaces the dropped-shape count + their super-steps, and :func:`sample_page_truncated` flags a
thread sample that hit the ``--limit`` page (both are folded into the rendered report). A
heterogeneous workload therefore reads as "the estimate is a floor" rather than biasing the >60%
license-up trigger low without warning.

SDK-firewall exception (deliberate, documented — PLAN §3.1 / task brief)
-----------------------------------------------------------------------
:class:`~opendevops.gateway.server.ServerGateway` is normally the *only* module allowed to import
``langgraph_sdk`` (the compatibility firewall). This probe's live seam (:func:`_build_client`) needs
``threads.search`` / ``threads.get_history``, which are not on the transport-neutral
:class:`AgentGateway` protocol, so — like ``ops/maintenance.py`` — it imports ``langgraph_sdk``
**directly** and is called out here as the sanctioned ops-tool exception: it is not part of the
shipped agent wheel, runs out-of-band by an operator, and the product firewall stays intact.
"""

from __future__ import annotations

import os
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

import typer

app = typer.Typer(
    name="quota-probe",
    help="Estimate LangGraph Server monthly node-execution consumption vs the verified-tier quota.",
    no_args_is_help=True,
    add_completion=False,
)

_DAYS_PER_MONTH = 30.0
# PLAN P3: > 60% of verified quota -> license-up vs the FastAPI-embed fallback decision.
_DEFAULT_WARN_RATIO = 0.60


# --------------------------------------------------------------------------------------
# pure computations (unit-tested; no I/O)
# --------------------------------------------------------------------------------------


def super_steps_from_checkpoints(checkpoints: list[dict[str, Any]]) -> int:
    """Count the executed super-steps of one run from its checkpoint list. Pure.

    Each checkpoint carries ``metadata.step`` (an int); LangGraph uses ``step == -1`` for the input
    seed checkpoint, so the executed super-steps are the DISTINCT non-negative steps. Distinct — not
    the raw count — because a resumed/replayed run can persist more than one checkpoint per step.
    """
    steps: set[int] = set()
    for checkpoint in checkpoints:
        metadata = checkpoint.get("metadata") or {}
        step = metadata.get("step")
        if isinstance(step, int) and step >= 0:
            steps.add(step)
    return len(steps)


@dataclass(frozen=True)
class WorkflowShape:
    """A group of runs sharing a workflow shape, with their aggregate super-step cost."""

    shape: str
    run_count: int
    total_super_steps: int

    @property
    def mean_super_steps(self) -> float:
        return self.total_super_steps / self.run_count if self.run_count else 0.0


def _aggregate_all(runs: list[dict[str, Any]]) -> list[WorkflowShape]:
    """Group runs by ``shape`` and return ALL shapes sorted by total super-steps (desc). Pure.

    Each run is ``{"shape": <str>, "super_steps": <int>}``. Ties break by run_count then shape name,
    so the ordering is deterministic.
    """
    counts: dict[str, int] = defaultdict(int)
    totals: dict[str, int] = defaultdict(int)
    for run in runs:
        shape = str(run.get("shape", "unknown"))
        counts[shape] += 1
        totals[shape] += int(run.get("super_steps", 0))
    shapes = [
        WorkflowShape(shape=shape, run_count=counts[shape], total_super_steps=totals[shape])
        for shape in counts
    ]
    shapes.sort(key=lambda s: (-s.total_super_steps, -s.run_count, s.shape))
    return shapes


@dataclass(frozen=True)
class ShapeSample:
    """The top-``k`` workflow shapes plus the LOUD accounting of what fell OUTSIDE the top-k.

    ``dropped_*`` make the projection's basis explicit (PLAN P3, "no silent caps"): the monthly
    projection sums only the top-``k`` shapes, so a run whose shape ranks below the top-k is
    EXCLUDED from the basis — reported here rather than silently discarded, so a heterogeneous
    workload (>k shapes) reads as "the estimate is a floor" instead of quietly biasing it low.
    (Super-steps are the node-execution proxy, so ``dropped_super_steps`` is the dropped node
    executions.)
    """

    top: list[WorkflowShape]
    total_shapes: int
    dropped_shapes: int
    dropped_super_steps: int


def summarize_shapes(runs: list[dict[str, Any]], *, top_k: int = 5) -> ShapeSample:
    """Aggregate every shape, then split into the top-``k`` projection basis and the reported
    dropped remainder (never silently discarded). Pure."""
    all_shapes = _aggregate_all(runs)
    top = all_shapes[:top_k]
    dropped = all_shapes[top_k:]
    return ShapeSample(
        top=top,
        total_shapes=len(all_shapes),
        dropped_shapes=len(dropped),
        dropped_super_steps=sum(shape.total_super_steps for shape in dropped),
    )


def sample_page_truncated(threads_returned: int, limit: int) -> bool:
    """True if a ``threads.search(limit=...)`` page came back FULL (``>= limit``) — i.e. likely
    TRUNCATED, so more threads may exist beyond the sampled page and the projection can UNDERSTATE
    real consumption. Pure. (``limit <= 0`` means "no limit requested" and never counts as capped.)
    """
    return limit > 0 and threads_returned >= limit


@dataclass(frozen=True)
class QuotaEstimate:
    """The monthly node-execution projection vs the verified-tier quota."""

    sample_node_executions: int
    sample_window_days: float
    projected_monthly: float
    monthly_quota: int
    fraction: float
    warn_ratio: float

    @property
    def over_threshold(self) -> bool:
        return self.fraction > self.warn_ratio


def estimate_monthly_quota(
    sample_node_executions: int,
    sample_window_days: float,
    monthly_quota: int,
    *,
    warn_ratio: float = _DEFAULT_WARN_RATIO,
    days_per_month: float = _DAYS_PER_MONTH,
) -> QuotaEstimate:
    """Extrapolate a sample's node-executions to a monthly figure and compare to quota. Pure.

    ``projected_monthly = sample_node_executions / sample_window_days * days_per_month``. The
    fraction is of the verified-tier ``monthly_quota`` (``inf`` if the quota is non-positive, so the
    warning trips loudly on a mis-set quota rather than silently passing).
    """
    if sample_window_days <= 0:
        raise ValueError("sample_window_days must be > 0 to extrapolate")
    projected = sample_node_executions / sample_window_days * days_per_month
    fraction = projected / monthly_quota if monthly_quota > 0 else float("inf")
    return QuotaEstimate(
        sample_node_executions=sample_node_executions,
        sample_window_days=sample_window_days,
        projected_monthly=projected,
        monthly_quota=monthly_quota,
        fraction=fraction,
        warn_ratio=warn_ratio,
    )


def render_quota_report(
    shapes: list[WorkflowShape],
    estimate: QuotaEstimate,
    *,
    dropped_shapes: int = 0,
    dropped_super_steps: int = 0,
    sample_truncated: bool = False,
    sample_limit: int | None = None,
) -> str:
    """Render the top-shapes table + the projection/verdict as plain text. Pure.

    ``dropped_*`` and ``sample_truncated`` surface the projection's basis LOUDLY (PLAN P3, "no
    silent caps"): shapes ranked below the top-k and a thread sample that hit its page ``--limit``
    are called out so a reader knows the estimate can UNDERSTATE actual consumption. Defaults keep
    the two-arg call a no-op (no extra lines) for callers that don't compute them.
    """
    lines = ["Top workflow shapes (by super-step cost):"]
    if not shapes:
        lines.append("  (no runs sampled)")
    for shape in shapes:
        lines.append(
            f"  {shape.shape:<28} runs={shape.run_count:<5} "
            f"super_steps={shape.total_super_steps:<7} mean={shape.mean_super_steps:.1f}"
        )
    if dropped_shapes > 0:
        lines.append(
            f"  … plus {dropped_shapes} more shape(s) NOT in the projection basis "
            f"({dropped_super_steps} super-steps dropped beyond the top-{len(shapes)}) — "
            "the projection is a floor."
        )
    lines.append("")
    lines.append(
        f"Sampled node-executions: {estimate.sample_node_executions} "
        f"over {estimate.sample_window_days:g} day(s)"
    )
    lines.append(f"Projected monthly:       {estimate.projected_monthly:,.0f} node-executions")
    lines.append(
        f"Verified-tier quota:     {estimate.monthly_quota:,} "
        f"({estimate.fraction * 100:.1f}% projected)"
    )
    if sample_truncated:
        cap = f" ({sample_limit})" if sample_limit is not None else ""
        lines.append(
            f"WARNING: the thread sample hit the page limit{cap} — the sample is CAPPED and the "
            "projection may UNDERSTATE actual consumption (raise --limit to widen the sample)."
        )
    if estimate.over_threshold:
        lines.append(
            f"WARNING: projection exceeds {estimate.warn_ratio * 100:.0f}% of quota — "
            "decide license-up vs the FastAPI-embed fallback (PLAN P3)."
        )
    else:
        lines.append(
            f"OK: projection under {estimate.warn_ratio * 100:.0f}% of quota — no action needed."
        )
    return "\n".join(lines)


# --------------------------------------------------------------------------------------
# live seams (thin; not exercised in CI)
# --------------------------------------------------------------------------------------


def _build_client(url: str, api_key_env: str | None) -> Any:  # pragma: no cover - live seam
    from langgraph_sdk import get_client

    api_key = os.environ.get(api_key_env) if api_key_env else None
    return get_client(url=url, api_key=api_key)


def _run_shape(thread: dict[str, Any]) -> str:  # pragma: no cover - live-shape heuristic
    """Derive a coarse workflow-shape key for a thread (assistant/graph id, else ``unknown``)."""
    metadata = thread.get("metadata") or {}
    return str(metadata.get("graph_id") or metadata.get("assistant_id") or "unknown")


# --------------------------------------------------------------------------------------
# command
# --------------------------------------------------------------------------------------


@app.command("probe")
def probe(  # pragma: no cover - live orchestration over the pure math
    url: str = typer.Option(..., help="LangGraph Server base URL."),
    monthly_quota: int = typer.Option(..., help="Verified-tier monthly node-execution quota."),
    sample_window_days: float = typer.Option(7.0, help="How many days back the sample spans."),
    limit: int = typer.Option(200, help="Max threads to sample."),
    api_key_env: str | None = typer.Option(None, help="Env var holding the server API key."),
    warn_ratio: float = typer.Option(_DEFAULT_WARN_RATIO, help="Warn above this quota fraction."),
) -> None:
    """Sample recent runs, extrapolate monthly node-executions, compare to the verified quota."""
    import asyncio

    async def _run() -> None:
        client = _build_client(url, api_key_env)
        try:
            threads = await client.threads.search(limit=limit)
            # A full page (>= limit) means the sample is capped — surface it, never silently cap.
            truncated = sample_page_truncated(len(threads), limit)
            runs: list[dict[str, Any]] = []
            for thread in threads:
                thread_id = thread.get("thread_id")
                if thread_id is None:
                    continue
                checkpoints = [
                    cp async for cp in client.threads.get_history(str(thread_id), limit=1000)
                ]
                runs.append(
                    {
                        "shape": _run_shape(thread),
                        "super_steps": super_steps_from_checkpoints(checkpoints),
                    }
                )
        finally:
            await client.aclose()

        # Top-5 stays the projection basis, but shapes beyond it are reported, not silently dropped.
        sample = summarize_shapes(runs, top_k=5)
        sampled = sum(s.total_super_steps for s in sample.top)
        estimate = estimate_monthly_quota(
            sampled, sample_window_days, monthly_quota, warn_ratio=warn_ratio
        )
        typer.echo(
            render_quota_report(
                sample.top,
                estimate,
                dropped_shapes=sample.dropped_shapes,
                dropped_super_steps=sample.dropped_super_steps,
                sample_truncated=truncated,
                sample_limit=limit,
            )
        )

    asyncio.run(_run())


if __name__ == "__main__":  # pragma: no cover
    app()
