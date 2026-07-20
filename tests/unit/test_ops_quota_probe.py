"""ops/quota_probe.py pure computations (T18): super-steps, shape aggregation, extrapolation.

The brief's named case is the extrapolation math; the live server sampling is never called in CI
(faked checkpoint/run dicts feed the pure functions).
"""

from __future__ import annotations

import pytest
from ops.quota_probe import (
    estimate_monthly_quota,
    render_quota_report,
    sample_page_truncated,
    summarize_shapes,
    super_steps_from_checkpoints,
)

# --------------------------------------------------------------------------------------
# super_steps_from_checkpoints
# --------------------------------------------------------------------------------------


def _cp(step: int) -> dict[str, object]:
    return {"metadata": {"step": step}}


def test_counts_distinct_non_negative_steps_ignoring_seed() -> None:
    # step -1 is the input seed; distinct executed steps are 0,1,2 -> 3 super-steps.
    checkpoints = [_cp(-1), _cp(0), _cp(1), _cp(2)]
    assert super_steps_from_checkpoints(checkpoints) == 3


def test_dedupes_repeated_step_from_replay() -> None:
    # A resumed run can persist two checkpoints for the same step; count it once.
    assert super_steps_from_checkpoints([_cp(0), _cp(1), _cp(1), _cp(2)]) == 3


def test_tolerates_missing_metadata() -> None:
    assert super_steps_from_checkpoints([{}, {"metadata": {}}, _cp(0)]) == 1


def test_empty_checkpoints_is_zero() -> None:
    assert super_steps_from_checkpoints([]) == 0


# --------------------------------------------------------------------------------------
# shape aggregation (surfaced via summarize_shapes(...).top — the projection basis)
# --------------------------------------------------------------------------------------


def test_groups_by_shape_and_sums_super_steps() -> None:
    runs = [
        {"shape": "crashloop", "super_steps": 5},
        {"shape": "crashloop", "super_steps": 7},
        {"shape": "oom", "super_steps": 3},
    ]
    shapes = summarize_shapes(runs).top
    by_shape = {s.shape: s for s in shapes}
    assert by_shape["crashloop"].run_count == 2
    assert by_shape["crashloop"].total_super_steps == 12
    assert by_shape["crashloop"].mean_super_steps == 6.0
    assert by_shape["oom"].total_super_steps == 3


def test_orders_by_total_super_steps_desc_and_takes_top_k() -> None:
    runs = [
        {"shape": "a", "super_steps": 1},
        {"shape": "b", "super_steps": 10},
        {"shape": "c", "super_steps": 5},
        {"shape": "d", "super_steps": 2},
    ]
    shapes = summarize_shapes(runs, top_k=2).top
    assert [s.shape for s in shapes] == ["b", "c"]


def test_default_shape_and_super_steps() -> None:
    shapes = summarize_shapes([{}, {"shape": "x"}]).top
    by_shape = {s.shape: s for s in shapes}
    assert by_shape["unknown"].total_super_steps == 0
    assert by_shape["x"].run_count == 1


# --------------------------------------------------------------------------------------
# estimate_monthly_quota — THE extrapolation math (named case)
# --------------------------------------------------------------------------------------


def test_extrapolates_sample_to_monthly() -> None:
    # 700 node-executions over 7 days -> 100/day -> 3000/month.
    est = estimate_monthly_quota(700, 7.0, monthly_quota=10_000)
    assert est.projected_monthly == pytest.approx(3000.0)
    assert est.fraction == pytest.approx(0.30)
    assert est.over_threshold is False


def test_over_threshold_when_projection_exceeds_60pct() -> None:
    # 1400 over 7 days -> 200/day -> 6000/month -> 60% of 10k is the boundary; 6001 tips over.
    est = estimate_monthly_quota(1401, 7.0, monthly_quota=10_000)
    assert est.projected_monthly > 6000
    assert est.fraction > 0.60
    assert est.over_threshold is True


def test_exactly_at_threshold_is_not_over() -> None:
    # 6000/month vs 10k quota == exactly 60% -> NOT strictly over (fires only above warn_ratio).
    est = estimate_monthly_quota(1400, 7.0, monthly_quota=10_000)
    assert est.fraction == pytest.approx(0.60)
    assert est.over_threshold is False


def test_custom_warn_ratio() -> None:
    est = estimate_monthly_quota(700, 7.0, monthly_quota=10_000, warn_ratio=0.25)
    assert est.fraction == pytest.approx(0.30)
    assert est.over_threshold is True


def test_zero_window_raises() -> None:
    with pytest.raises(ValueError, match="sample_window_days"):
        estimate_monthly_quota(100, 0.0, monthly_quota=10_000)


def test_non_positive_quota_is_infinite_fraction_and_over() -> None:
    est = estimate_monthly_quota(100, 7.0, monthly_quota=0)
    assert est.fraction == float("inf")
    assert est.over_threshold is True


# --------------------------------------------------------------------------------------
# render_quota_report
# --------------------------------------------------------------------------------------


def test_report_warns_when_over_threshold() -> None:
    shapes = summarize_shapes([{"shape": "crashloop", "super_steps": 1401}]).top
    est = estimate_monthly_quota(1401, 7.0, monthly_quota=10_000)
    report = render_quota_report(shapes, est)
    assert "WARNING" in report
    assert "crashloop" in report
    assert "license-up" in report


def test_report_ok_when_under_threshold() -> None:
    shapes = summarize_shapes([{"shape": "crashloop", "super_steps": 700}]).top
    est = estimate_monthly_quota(700, 7.0, monthly_quota=10_000)
    report = render_quota_report(shapes, est)
    assert "OK:" in report
    assert "WARNING" not in report


# --------------------------------------------------------------------------------------
# summarize_shapes — the dropped-remainder accounting (I2: no silent caps)
# --------------------------------------------------------------------------------------


def test_summarize_reports_dropped_remainder_beyond_top_k() -> None:
    # 6 distinct shapes; top-5 is the basis, the 6th (smallest) is the reported dropped remainder.
    runs = [{"shape": f"s{i}", "super_steps": ss} for i, ss in enumerate([60, 50, 40, 30, 20, 10])]
    sample = summarize_shapes(runs, top_k=5)
    assert sample.total_shapes == 6
    assert [s.shape for s in sample.top] == ["s0", "s1", "s2", "s3", "s4"]
    assert sample.dropped_shapes == 1
    assert sample.dropped_super_steps == 10  # the excluded shape's super-steps, surfaced not hidden


def test_summarize_no_drop_when_within_top_k() -> None:
    runs = [{"shape": "a", "super_steps": 5}, {"shape": "b", "super_steps": 3}]
    sample = summarize_shapes(runs, top_k=5)
    assert sample.total_shapes == 2
    assert sample.dropped_shapes == 0
    assert sample.dropped_super_steps == 0


def test_report_calls_out_dropped_shapes() -> None:
    runs = [{"shape": f"s{i}", "super_steps": ss} for i, ss in enumerate([60, 50, 40, 30, 20, 10])]
    sample = summarize_shapes(runs, top_k=5)
    est = estimate_monthly_quota(200, 7.0, monthly_quota=10_000)
    report = render_quota_report(
        sample.top,
        est,
        dropped_shapes=sample.dropped_shapes,
        dropped_super_steps=sample.dropped_super_steps,
    )
    assert "1 more shape" in report
    assert "10 super-steps dropped" in report
    assert "floor" in report


# --------------------------------------------------------------------------------------
# sample_page_truncated + report truncation warning (I2)
# --------------------------------------------------------------------------------------


def test_page_truncated_detects_full_page() -> None:
    assert sample_page_truncated(200, 200) is True   # full page -> likely more beyond it
    assert sample_page_truncated(201, 200) is True   # defensive: at/over the limit
    assert sample_page_truncated(199, 200) is False  # partial page -> the whole workload was seen
    assert sample_page_truncated(0, 0) is False      # no limit requested is never "capped"


def test_report_warns_when_sample_truncated() -> None:
    shapes = summarize_shapes([{"shape": "crashloop", "super_steps": 700}]).top
    est = estimate_monthly_quota(700, 7.0, monthly_quota=10_000)  # under threshold on its own
    report = render_quota_report(shapes, est, sample_truncated=True, sample_limit=200)
    assert "CAPPED" in report
    assert "UNDERSTATE" in report
    assert "200" in report
