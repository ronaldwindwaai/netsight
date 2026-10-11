"""Exact-boundary behaviour of the hourly baseline comparison (Step 7 code review).

The two flag conditions are inclusive and independent: ``|score| >= 3.5`` and
``|observed - baseline| >= 10 MiB``. Each test builds one steady history, moves a single input across
a boundary by the smallest possible step, and checks that the flag flips exactly there.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from netsight_api.traffic import anomaly as alg

MIB = 1024 * 1024
HOUR = int(datetime(2026, 10, 11, 10, tzinfo=UTC).timestamp())
COVERAGE = {HOUR - k * alg.WEEK_SECONDS for k in range(alg.WEEKS + 1)}


def judge(history: list[int], observed: int) -> alg.RawAnomaly | None:
    """The anomaly for ``observed`` against ``history`` (one value per prior week), or None."""
    values = {HOUR - k * alg.WEEK_SECONDS: value for k, value in enumerate(history, start=1)}
    values[HOUR] = observed
    outcome = alg.evaluate_series(
        [alg.SeriesData("total", None, values)], COVERAGE, HOUR, HOUR + alg.HOUR_SECONDS
    )
    assert outcome.evaluated == 1 and outcome.insufficient == 0
    return outcome.anomalies[0] if outcome.anomalies else None


# --- the score threshold: median 100 MiB, scale 10 MiB (10 percent of the median) ---------------------


STEADY_100 = [100 * MIB] * alg.WEEKS


def test_a_score_of_exactly_the_threshold_is_flagged() -> None:
    found = judge(STEADY_100, 135 * MIB)  # (135 - 100) / 10 = 3.5
    assert found is not None
    assert found.score == pytest.approx(3.5, abs=0)
    assert found.score == alg.THRESHOLD
    assert found.difference == 35 * MIB and found.direction == "above"


def test_a_score_just_under_the_threshold_is_not_flagged() -> None:
    observed = 100 * MIB + int(3.49 * 10 * MIB)  # score 3.49
    assert 3.48 < (observed - 100 * MIB) / (10 * MIB) < alg.THRESHOLD
    assert judge(STEADY_100, observed) is None


def test_one_byte_under_the_threshold_score_is_not_flagged() -> None:
    assert judge(STEADY_100, 135 * MIB - 1) is None


def test_one_byte_over_the_threshold_score_is_flagged() -> None:
    assert judge(STEADY_100, 135 * MIB + 1) is not None


def test_the_threshold_applies_to_a_drop_as_well() -> None:
    found = judge(STEADY_100, 65 * MIB)  # (65 - 100) / 10 = -3.5
    assert found is not None and found.direction == "below" and found.score == -alg.THRESHOLD
    assert judge(STEADY_100, 65 * MIB + 1) is None


# --- the minimum difference: median 2 MiB, scale 1 MiB (the floor) -----------------------------------------

STEADY_2 = [2 * MIB] * alg.WEEKS


def test_a_difference_of_exactly_ten_mib_is_flagged() -> None:
    found = judge(STEADY_2, 12 * MIB)  # score 10, difference exactly 10 MiB
    assert found is not None
    assert found.difference == alg.MIN_DIFFERENCE_BYTES
    assert found.score == pytest.approx(10.0)


def test_a_difference_one_byte_below_ten_mib_is_not_flagged() -> None:
    # The score (about 10) is far above the threshold: only the minimum difference holds it back.
    assert judge(STEADY_2, 12 * MIB - 1) is None


def test_a_difference_one_byte_above_ten_mib_is_flagged() -> None:
    assert judge(STEADY_2, 12 * MIB + 1) is not None


def test_the_minimum_difference_applies_to_a_drop_as_well() -> None:
    history = [20 * MIB] * alg.WEEKS  # scale max(0, 2 MiB, 1 MiB) = 2 MiB
    found = judge(history, 10 * MIB)  # -10 MiB, score -5
    assert found is not None and found.direction == "below"
    assert judge(history, 10 * MIB + 1) is None


# --- both conditions are required ---------------------------------------------------------------------------


def test_a_large_difference_with_a_small_score_is_not_flagged() -> None:
    # 200 MiB median: scale 20 MiB; +60 MiB is score 3.0 although the difference is far above 10 MiB.
    assert judge([200 * MIB] * alg.WEEKS, 260 * MIB) is None


def test_the_scale_floors_are_the_documented_ones() -> None:
    assert alg.NOISE_FLOOR_RATIO == 0.10
    assert alg.MIN_SCALE_BYTES == MIB
    assert alg.THRESHOLD == 3.5 and alg.MIN_DIFFERENCE_BYTES == 10 * MIB


def test_the_median_not_the_mean_sets_the_baseline() -> None:
    # One poisoned week (a 10x spike) does not move the median, so today's normal hour stays normal.
    history = [100 * MIB, 100 * MIB, 100 * MIB, 1000 * MIB]
    assert judge(history, 100 * MIB) is None
