"""Deterministic hourly baseline comparison: same hour of the week, median and MAD, no model.

The question asked of every (series, hour) pair is: *is this hour's byte count unlike the same hour
in the previous weeks?* The answer is arithmetic over source-reported counters, reproducible from the
same input, and explainable in one sentence. There is no training, no hidden state and no score the
operator cannot recompute.

For an observed hour ``h`` and series ``s``:

1. **Samples.** The values of ``s`` at ``h - k * 168 h`` for ``k = 1..WEEKS``. A prior hour counts
   only if the flow source has *any* data for it (``coverage``); an hour the source never saw, such as
   a collector outage, is *absent*, not zero. A covered hour where the series is missing is a real
   zero (the application simply was not used).
2. **Minimum history.** Fewer than ``MIN_WEEKS`` samples is ``insufficient``: no baseline, no
   anomaly, and the result says so. An observed hour with no source data is ``no_data`` (a gap is not
   a drop).
3. **Baseline.** ``median`` of the samples (robust to a poisoned week: one exfiltration week in four
   does not move it). The reported baseline is that median rounded half up to whole bytes.
4. **Scale.** ``max(1.4826 * MAD, 10% of the median, 1 MiB)``. The 1.4826 factor makes MAD comparable
   to a standard deviation; the floors stop a perfectly steady history from turning ordinary noise into
   a large score.
5. **Flag.** ``score = (observed - median) / scale``. Flagged when ``|score| >= THRESHOLD`` **and**
   ``|observed - baseline| >= MIN_DIFFERENCE_BYTES`` (a tiny link is not an incident).
6. **Confidence.** ``high``: ``|score| >= 8`` with a full ``WEEKS`` of samples; ``medium``: ``|score|
   >= 5``; otherwise ``low``. It describes the statistical separation, not the likelihood of malice.

The week is a fixed 168 hours in UTC, so across a daylight-saving change the local hour shifts by
one for the weeks before it. Working hours and "after hours" are *context* attached by the caller
from operator policy; they never change the score.
"""

from __future__ import annotations

import math
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final, Literal

WEEKS: Final = 4
MIN_WEEKS: Final = 3
THRESHOLD: Final = 3.5
MIN_DIFFERENCE_BYTES: Final = 10 * 1024 * 1024
MAD_SCALE: Final = 1.4826
NOISE_FLOOR_RATIO: Final = 0.10
MIN_SCALE_BYTES: Final = 1024 * 1024
HIGH_SCORE: Final = 8.0
MEDIUM_SCORE: Final = 5.0
HOUR_SECONDS: Final = 3600
WEEK_SECONDS: Final = 7 * 24 * HOUR_SECONDS
MAX_BUCKETS: Final = 168  # one week of hours
MAX_SERIES: Final = 11  # the total plus the ten largest applications

Confidence = Literal["low", "medium", "high"]


@dataclass(frozen=True)
class SeriesData:
    """One byte series by hour: ``values`` maps an hour start (epoch seconds) to bytes."""

    kind: Literal["total", "application"]
    label: str | None
    values: Mapping[int, int]


@dataclass(frozen=True)
class RawAnomaly:
    kind: Literal["total", "application"]
    label: str | None
    bucket_start: datetime
    direction: Literal["above", "below"]
    observed: int
    baseline: int
    samples: int
    difference: int
    ratio: float | None
    score: float
    confidence: Confidence


@dataclass(frozen=True)
class EvaluationOutcome:
    """Counts add up: ``evaluated + insufficient + no_data == buckets``."""

    series: int
    buckets: int
    evaluated: int
    insufficient: int
    no_data: int
    anomalies: tuple[RawAnomaly, ...]


def median(values: Sequence[float]) -> float:
    if not values:
        raise ValueError("median of nothing")
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return float(ordered[middle])
    return (ordered[middle - 1] + ordered[middle]) / 2


def mad(values: Sequence[float]) -> float:
    """Median absolute deviation from the median."""
    centre = median(values)
    return median([abs(value - centre) for value in values])


def prior_hours(hour: int) -> tuple[int, ...]:
    """The same hour of the week in each of the previous ``WEEKS`` weeks, nearest first."""
    return tuple(hour - k * WEEK_SECONDS for k in range(1, WEEKS + 1))


def _round_half_up(value: float) -> int:
    return math.floor(value + 0.5)


def _confidence(score: float, samples: int) -> Confidence:
    strength = abs(score)
    if strength >= HIGH_SCORE and samples >= WEEKS:
        return "high"
    return "medium" if strength >= MEDIUM_SCORE else "low"


def _judge(
    series: SeriesData, hour: int, coverage: Collection[int]
) -> RawAnomaly | Literal["insufficient", "evaluated"]:
    samples = [series.values.get(prior, 0) for prior in prior_hours(hour) if prior in coverage]
    if len(samples) < MIN_WEEKS:
        return "insufficient"
    centre = median(samples)
    scale = max(MAD_SCALE * mad(samples), NOISE_FLOOR_RATIO * centre, MIN_SCALE_BYTES)
    observed = series.values.get(hour, 0)
    score = (observed - centre) / scale
    baseline = _round_half_up(centre)
    difference = observed - baseline
    if abs(score) < THRESHOLD or abs(difference) < MIN_DIFFERENCE_BYTES:
        return "evaluated"
    return RawAnomaly(
        kind=series.kind,
        label=series.label,
        bucket_start=datetime.fromtimestamp(hour, tz=UTC),
        direction="above" if difference > 0 else "below",
        observed=observed,
        baseline=baseline,
        samples=len(samples),
        difference=difference,
        ratio=(observed / baseline) if baseline > 0 else None,
        score=score,
        confidence=_confidence(score, len(samples)),
    )


def evaluate_series(
    series: Sequence[SeriesData],
    coverage: Collection[int],
    first_hour: int,
    last_hour: int,
) -> EvaluationOutcome:
    """Judge every hour in ``[first_hour, last_hour)`` of every series; pure and bounded."""
    if first_hour % HOUR_SECONDS or last_hour % HOUR_SECONDS or last_hour < first_hour:
        raise ValueError("the range runs on whole hours")
    hours = range(first_hour, last_hour, HOUR_SECONDS)
    if len(hours) > MAX_BUCKETS or len(series) > MAX_SERIES:
        raise ValueError("the evaluation is bounded to a week of hours and eleven series")
    evaluated = insufficient = no_data = 0
    found: list[RawAnomaly] = []
    for item in series:
        for hour in hours:
            if hour not in coverage:
                no_data += 1
                continue
            verdict = _judge(item, hour, coverage)
            if verdict == "insufficient":
                insufficient += 1
                continue
            evaluated += 1
            if isinstance(verdict, RawAnomaly):
                found.append(verdict)
    found.sort(key=lambda a: (-abs(a.score), a.bucket_start, a.kind, a.label or ""))
    return EvaluationOutcome(
        series=len(series),
        buckets=len(hours) * len(series),
        evaluated=evaluated,
        insufficient=insufficient,
        no_data=no_data,
        anomalies=tuple(found),
    )
