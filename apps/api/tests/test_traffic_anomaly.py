"""The deterministic baseline comparison (docs/12-implementation/TRAFFIC-BASELINES.md).

Same-hour-of-week median and MAD over the prior weeks, with a minimum number of comparable weeks.
Below the minimum nothing is flagged: "insufficient baseline" is a result, not an anomaly.
"""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta

import pytest

from netsight_api.traffic import anomaly as alg
from netsight_api.traffic.anomaly import SeriesData, evaluate_series

HOUR = 3600
WEEK = 7 * 24 * HOUR
GIB = 1024**3
MIB = 1024**2
OBSERVED = int(datetime(2026, 10, 6, 2, tzinfo=UTC).timestamp())  # a Tuesday, 02:00 UTC


def hours(*offsets: int) -> list[int]:
    return [OBSERVED + n * HOUR for n in offsets]


def history(
    value: int | list[int], *, weeks: int = 4, observed: int | None = None
) -> tuple[dict[int, int], frozenset[int]]:
    """Prior same-hour values (week 1 first) plus the observed hour; coverage = every hour given."""
    values = [value] * weeks if isinstance(value, int) else list(value)
    data = {OBSERVED - (k + 1) * WEEK: v for k, v in enumerate(values)}
    covered = set(data)
    if observed is not None:
        data[OBSERVED] = observed
        covered.add(OBSERVED)
    return data, frozenset(covered)


def run(values: dict[int, int], coverage: frozenset[int], label: str | None = None):
    series = SeriesData("total" if label is None else "application", label, values)
    return evaluate_series([series], coverage, OBSERVED, OBSERVED + HOUR)


def test_the_documented_constants() -> None:
    assert (alg.WEEKS, alg.MIN_WEEKS) == (4, 3)
    assert alg.THRESHOLD == 3.5
    assert alg.MIN_DIFFERENCE_BYTES == 10 * MIB


def test_a_steady_hour_is_not_an_anomaly() -> None:
    values, covered = history(GIB, observed=GIB)
    result = run(values, covered)
    assert (result.buckets, result.evaluated, result.insufficient, result.no_data) == (1, 1, 0, 0)
    assert result.anomalies == ()


def test_a_spike_is_flagged_with_its_baseline_and_difference() -> None:
    values, covered = history([GIB, GIB + 50 * MIB, GIB - 50 * MIB, GIB], observed=9 * GIB)
    (found,) = run(values, covered).anomalies
    assert found.direction == "above"
    assert found.observed == 9 * GIB
    assert found.baseline == GIB
    assert found.difference == 8 * GIB
    assert found.ratio == pytest.approx(9.0)
    assert found.samples == 4
    assert found.score > 3.5
    assert found.confidence == "high"
    assert found.bucket_start == datetime(2026, 10, 6, 2, tzinfo=UTC)
    assert found.kind == "total" and found.label is None


def test_a_drop_is_flagged_below() -> None:
    values, covered = history(GIB, observed=GIB // 20)
    (found,) = run(values, covered).anomalies
    assert found.direction == "below"
    assert found.difference == found.observed - found.baseline < 0
    assert found.score < -3.5


def test_below_the_minimum_weeks_nothing_is_flagged() -> None:
    values, covered = history(GIB, weeks=2, observed=50 * GIB)
    result = run(values, covered)
    assert result.anomalies == ()
    assert (result.evaluated, result.insufficient, result.no_data) == (0, 1, 0)


def test_the_minimum_weeks_is_enough() -> None:
    values, covered = history(GIB, weeks=3, observed=9 * GIB)
    (found,) = run(values, covered).anomalies
    assert found.samples == 3
    assert found.confidence == "medium"  # three weeks never earn "high"


def test_a_week_the_source_had_no_data_for_is_not_a_sample() -> None:
    values, covered = history(GIB, observed=9 * GIB)
    covered = covered - {OBSERVED - 2 * WEEK}  # a flow outage: not a zero, simply absent
    values.pop(OBSERVED - 2 * WEEK)
    (found,) = run(values, covered).anomalies
    assert found.samples == 3


def test_two_missing_weeks_leave_too_little_history() -> None:
    values, covered = history(GIB, observed=9 * GIB)
    covered = covered - {OBSERVED - WEEK, OBSERVED - 2 * WEEK}
    result = run(values, covered)
    assert result.anomalies == () and result.insufficient == 1


def test_an_observed_hour_without_source_data_is_no_data_not_a_drop() -> None:
    values, covered = history(GIB)
    result = run(values, covered)
    assert (result.buckets, result.no_data, result.evaluated) == (1, 1, 0)
    assert result.anomalies == ()


def test_an_application_absent_from_a_covered_hour_counts_as_zero() -> None:
    covered = frozenset([OBSERVED, *(OBSERVED - k * WEEK for k in range(1, 5))])
    values = {OBSERVED: 5 * GIB}  # the application never appeared in the prior weeks
    (found,) = run(values, covered, label="Zoom").anomalies
    assert found.baseline == 0 and found.ratio is None
    assert found.kind == "application" and found.label == "Zoom"
    assert found.difference == 5 * GIB


def test_constant_history_does_not_flag_ordinary_noise() -> None:
    # MAD is zero here; the 10 percent noise floor keeps a 4 percent wobble from scoring high.
    values, covered = history(GIB, observed=GIB + GIB // 25)
    assert run(values, covered).anomalies == ()


def test_constant_history_still_flags_a_large_change() -> None:
    values, covered = history(GIB, observed=3 * GIB)
    assert len(run(values, covered).anomalies) == 1


def test_a_small_absolute_change_is_never_flagged_whatever_its_ratio() -> None:
    values, covered = history(100 * 1024, observed=4 * MIB)
    assert run(values, covered).anomalies == ()


def test_one_poisoned_week_does_not_become_normal() -> None:
    # Median/MAD: an exfiltration week in the history does not move the baseline.
    values, covered = history([GIB, GIB, GIB, 50 * GIB], observed=GIB + GIB // 20)
    assert run(values, covered).anomalies == ()
    values, covered = history([GIB, GIB, GIB, 50 * GIB], observed=50 * GIB)
    (found,) = run(values, covered).anomalies
    assert found.baseline == GIB


def test_confidence_follows_the_score_and_the_sample_count() -> None:
    def judged(observed: int, weeks: int = 4):
        values, covered = history([GIB + i * 100 * MIB for i in range(weeks)], observed=observed)
        return run(values, covered).anomalies

    assert judged(GIB + 5 * 1024 * MIB)[0].confidence == "high"
    low = judged(GIB + 700 * MIB)
    assert low and low[0].confidence == "low"


def test_the_baseline_is_rounded_half_up_and_the_difference_uses_it() -> None:
    values, covered = history(
        [100 * MIB, 100 * MIB + 1, 100 * MIB, 100 * MIB + 1], observed=9 * GIB
    )
    (found,) = run(values, covered).anomalies
    assert found.baseline == 100 * MIB + 1  # the median is 100 MiB + 0.5 bytes
    assert found.difference == found.observed - found.baseline


def test_results_are_deterministic_and_independent_of_input_order() -> None:
    rng = random.Random(7)
    values, covered = history([GIB, 2 * GIB, GIB, 2 * GIB], observed=40 * GIB)
    items = list(values.items())
    rng.shuffle(items)
    shuffled = dict(items)
    assert run(values, covered) == run(shuffled, covered)
    assert run(values, covered) == run(values, covered)


def test_anomalies_are_ordered_by_strength_then_time_then_subject() -> None:
    covered = frozenset({OBSERVED + n * HOUR - k * WEEK for n in (0, 1, 2) for k in range(5)})
    quiet = {OBSERVED + n * HOUR - k * WEEK: GIB for n in (0, 1, 2) for k in range(1, 5)}
    values = {**quiet, OBSERVED: 5 * GIB, OBSERVED + HOUR: 20 * GIB, OBSERVED + 2 * HOUR: 5 * GIB}
    result = evaluate_series(
        [SeriesData("total", None, values)], covered, OBSERVED, OBSERVED + 3 * HOUR
    )
    scores = [abs(a.score) for a in result.anomalies]
    assert scores == sorted(scores, reverse=True)
    assert result.anomalies[0].bucket_start == datetime(2026, 10, 6, 3, tzinfo=UTC)
    tied = [a.bucket_start for a in result.anomalies[1:]]
    assert tied == sorted(tied)


def test_counts_cover_every_series_and_hour() -> None:
    covered = frozenset({OBSERVED, OBSERVED + HOUR, *(OBSERVED - k * WEEK for k in range(1, 5))})
    total = {OBSERVED - k * WEEK: GIB for k in range(1, 5)} | {OBSERVED: GIB}
    other = {OBSERVED - k * WEEK: GIB for k in range(1, 5)}
    result = evaluate_series(
        [SeriesData("total", None, total), SeriesData("application", "Zoom", other)],
        covered,
        OBSERVED,
        OBSERVED + 2 * HOUR,
    )
    assert result.series == 2
    assert result.buckets == 4
    # hour 1 has source data but no comparable weeks; hour 0 is judged for both series
    assert (result.evaluated, result.insufficient, result.no_data) == (2, 2, 0)
    assert result.evaluated + result.insufficient + result.no_data == result.buckets


def test_an_empty_range_has_nothing_to_judge() -> None:
    result = evaluate_series([SeriesData("total", None, {})], frozenset(), OBSERVED, OBSERVED)
    assert (result.buckets, result.evaluated) == (0, 0)
    assert result.anomalies == ()


def test_the_work_is_bounded() -> None:
    too_many = OBSERVED + (alg.MAX_BUCKETS + 1) * HOUR
    with pytest.raises(ValueError):
        evaluate_series([SeriesData("total", None, {})], frozenset(), OBSERVED, too_many)
    series = [SeriesData("application", f"a{n}", {}) for n in range(alg.MAX_SERIES + 1)]
    with pytest.raises(ValueError):
        evaluate_series(series, frozenset(), OBSERVED, OBSERVED + HOUR)


def test_a_range_that_is_not_on_the_hour_is_refused() -> None:
    with pytest.raises(ValueError):
        evaluate_series([SeriesData("total", None, {})], frozenset(), OBSERVED + 1, OBSERVED + HOUR)


def test_the_maximum_window_is_a_week_of_hours() -> None:
    assert alg.MAX_BUCKETS == 168


def test_the_baseline_helper_is_exact_for_odd_and_even_counts() -> None:
    assert alg.median([3, 1, 2]) == 2
    assert alg.median([1, 2, 3, 4]) == 2.5
    assert alg.mad([1, 1, 1, 50]) == 0
    assert alg.mad([1, 2, 3, 4, 100]) == 1
    with pytest.raises(ValueError):
        alg.median([])


def test_the_week_alignment_is_fixed_168_hours_in_utc() -> None:
    day = datetime(2026, 10, 6, 2, tzinfo=UTC)
    assert alg.prior_hours(int(day.timestamp()))[0] == int((day - timedelta(days=7)).timestamp())
    assert len(alg.prior_hours(int(day.timestamp()))) == alg.WEEKS
