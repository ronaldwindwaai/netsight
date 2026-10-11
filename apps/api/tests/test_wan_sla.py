"""Deterministic SLA maths over stored probe cycles (PRD 21, Step 5b).

Everything here is a pure function of stored cycles/samples and a window: no clock, no I/O.
Time not covered by a sample is *unknown*, never up and never down.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from itertools import pairwise

import pytest

from netsight_api.wan import sla
from netsight_api.wan.sla import Cycle, Sample

T0 = datetime(2026, 10, 1, 0, 0, tzinfo=UTC)
INTERVAL = 60


def s(
    outcome: str, *, probe: str = "icmp", target: str = "a", latency: float | None = None
) -> Sample:
    return Sample(probe=probe, target=target, outcome=outcome, latency_ms=latency)  # type: ignore[arg-type]


def cyc(minute: float, state: str, *, interval: int = INTERVAL) -> Cycle:
    passes = {"up": 2, "degraded": 1}.get(state, 0)
    fails = {"down": 2, "degraded": 1}.get(state, 0)
    unknowns = 2 if state == "unknown" else 0
    return Cycle(
        link_id="wan-a",
        sampled_at=T0 + timedelta(seconds=round(minute * 60)),
        interval_seconds=interval,
        passes=passes,
        fails=fails,
        unknowns=unknowns,
        state=state,  # type: ignore[arg-type]
    )


# --- one cycle's state ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("samples", "state"),
    [
        ([s("pass"), s("pass", target="b")], "up"),
        ([s("pass"), s("unknown", target="b")], "up"),
        ([s("fail"), s("fail", target="b")], "down"),
        ([s("pass"), s("fail", target="b")], "degraded"),
        ([s("fail"), s("unknown", target="b")], "unknown"),
        ([s("unknown")], "unknown"),
        ([], "unknown"),
    ],
)
def test_cycle_state_follows_reachability_samples(samples: list[Sample], state: str) -> None:
    assert sla.build_cycle("wan-a", T0, INTERVAL, samples).state == state


def test_dns_and_other_probes_never_decide_reachability() -> None:
    cycle = sla.build_cycle("wan-a", T0, INTERVAL, [s("fail", probe="dns"), s("pass", probe="tcp")])
    assert (cycle.passes, cycle.fails, cycle.unknowns, cycle.state) == (1, 0, 0, "up")


def test_a_cycle_time_must_be_whole_seconds_and_aware() -> None:
    with pytest.raises(ValueError, match="whole seconds"):
        sla.build_cycle("wan-a", T0.replace(microsecond=5), INTERVAL, [])
    with pytest.raises(ValueError, match="timezone"):
        sla.build_cycle("wan-a", T0.replace(tzinfo=None), INTERVAL, [])


# --- coverage ---------------------------------------------------------------------------------


def test_each_cycle_covers_its_interval_plus_half_and_never_past_the_next_cycle() -> None:
    segments = sla.segments([cyc(0, "up"), cyc(5, "down")], T0, T0 + timedelta(minutes=10))
    kinds = [(seg.state, seg.seconds) for seg in segments]
    # up covers 90 s (1.5 x 60), then the gap to the next cycle is unknown, then down for 90 s,
    # then unknown to the end of the window.
    assert kinds == [("up", 90), ("unknown", 210), ("down", 90), ("unknown", 210)]


def test_consecutive_cycles_leave_no_gap() -> None:
    cycles = [cyc(m, "up") for m in range(10)]
    segments = sla.segments(cycles, T0, T0 + timedelta(minutes=10))
    assert [(seg.state, seg.seconds) for seg in segments] == [("up", 600)]


def test_a_gap_in_sampling_is_unknown_not_up_and_not_down() -> None:
    cycles = [cyc(0, "up"), cyc(1, "up"), cyc(30, "up")]
    summary = sla.summarise(cycles, T0, T0 + timedelta(minutes=31))
    assert summary.up_seconds == 60 + 90 + 60
    assert summary.unknown_seconds == 31 * 60 - summary.up_seconds
    assert summary.down_seconds == 0


def test_a_cycle_just_before_the_window_covers_into_it_and_one_after_is_ignored() -> None:
    before = cyc(-0.5, "down")  # 30 s before the window; covers 90 s, so 60 s into it
    after = cyc(10, "up")
    segments = sla.segments([before, after], T0, T0 + timedelta(minutes=10))
    assert (segments[0].state, segments[0].seconds) == ("down", 60)
    assert sum(seg.seconds for seg in segments) == 600


def test_segments_tile_the_window_exactly() -> None:
    cycles = [cyc(0, "up"), cyc(2, "down"), cyc(3, "degraded"), cyc(9, "up")]
    window_end = T0 + timedelta(minutes=12)
    segments = sla.segments(cycles, T0, window_end)
    assert sum(seg.seconds for seg in segments) == 12 * 60
    assert segments[0].start == T0 and segments[-1].end == window_end
    for first, second in pairwise(segments):
        assert first.end == second.start


def test_a_zero_length_window_is_an_honest_empty_summary() -> None:
    summary = sla.summarise([cyc(0, "up")], T0, T0)
    assert (summary.total_seconds, summary.unknown_seconds, summary.cycle_count) == (0, 0, 0)
    assert summary.uptime_pct is None and summary.coverage_pct == 0.0
    assert summary.windows == () and summary.outage_count == 0
    with pytest.raises(ValueError, match="before"):
        sla.summarise([], T0 + timedelta(seconds=1), T0)


def test_seconds_always_add_up_to_the_total_even_for_a_window_with_fractions() -> None:
    start = T0 + timedelta(milliseconds=500)
    end = T0 + timedelta(seconds=100, milliseconds=500)
    summary = sla.summarise([cyc(0, "up")], start, end)
    parts = (
        summary.up_seconds
        + summary.degraded_seconds
        + summary.down_seconds
        + summary.unknown_seconds
    )
    assert summary.total_seconds == 100 and parts == 100
    assert summary.up_seconds == 89 and summary.unknown_seconds == 11  # the remainder is unknown


def test_an_empty_window_or_no_cycles_is_all_unknown() -> None:
    assert sla.summarise([], T0, T0 + timedelta(hours=1)).unknown_seconds == 3600
    with pytest.raises(ValueError, match="before"):
        sla.segments([], T0, T0)


def test_input_order_does_not_change_the_result() -> None:
    cycles = [cyc(0, "up"), cyc(1, "down"), cyc(2, "up")]
    forward = sla.summarise(cycles, T0, T0 + timedelta(minutes=5))
    assert sla.summarise(list(reversed(cycles)), T0, T0 + timedelta(minutes=5)) == forward


def test_the_same_cycle_twice_counts_once() -> None:
    window = (T0, T0 + timedelta(minutes=5))
    once = sla.summarise([cyc(0, "down"), cyc(1, "up")], *window)
    assert sla.summarise([cyc(0, "down"), cyc(0, "down"), cyc(1, "up")], *window) == once


def test_two_writers_that_disagree_about_one_instant_make_that_time_unknown() -> None:
    window = (T0, T0 + timedelta(minutes=5))
    forward = sla.summarise([cyc(0, "up"), cyc(0, "down")], *window)
    assert sla.summarise([cyc(0, "down"), cyc(0, "up")], *window) == forward
    assert forward.up_seconds == 0 and forward.down_seconds == 0
    assert forward.unknown_seconds == 300 and forward.outage_count == 0
    assert forward.uptime_pct is None


def test_interleaved_writers_tile_deterministically_and_add_up() -> None:
    first = [cyc(m, "up") for m in range(10)]
    second = [cyc(m + 0.5, "down") for m in range(10)]
    window = (T0, T0 + timedelta(minutes=10))
    result = sla.summarise(first + second, *window)
    assert sla.summarise(second + first, *window) == result
    assert result.up_seconds + result.down_seconds + result.unknown_seconds == 600
    assert result.up_seconds == 300 and result.down_seconds == 300


# --- summary ----------------------------------------------------------------------------------


def test_uptime_counts_degraded_as_reachable_and_is_over_known_time_only() -> None:
    cycles = [cyc(0, "up"), cyc(1, "degraded"), cyc(2, "down"), cyc(3, "up")]
    summary = sla.summarise(cycles, T0, T0 + timedelta(minutes=4))
    assert (summary.up_seconds, summary.degraded_seconds, summary.down_seconds) == (120, 60, 60)
    assert summary.unknown_seconds == 0
    assert summary.uptime_pct == 75.0
    assert summary.coverage_pct == 100.0


def test_no_known_time_means_no_percentage_not_zero_or_hundred() -> None:
    summary = sla.summarise([cyc(0, "unknown")], T0, T0 + timedelta(minutes=2))
    assert summary.uptime_pct is None
    assert summary.coverage_pct == 0.0
    empty = sla.summarise([], T0, T0 + timedelta(minutes=2))
    assert empty.uptime_pct is None and empty.coverage_pct == 0.0


def test_outages_are_runs_of_down_time_broken_by_gaps() -> None:
    cycles = [cyc(0, "down"), cyc(1, "down"), cyc(2, "up"), cyc(3, "down"), cyc(20, "down")]
    summary = sla.summarise(cycles, T0, T0 + timedelta(minutes=30))
    outages = [w for w in summary.windows if w.kind == "down"]
    assert [(w.started_at, w.duration_seconds, w.sample_count) for w in outages] == [
        (T0, 120, 2),
        (T0 + timedelta(minutes=3), 90, 1),
        (T0 + timedelta(minutes=20), 90, 1),
    ]
    assert summary.outage_count == 3
    assert summary.longest_outage_seconds == 120


def test_windows_list_down_degraded_and_unknown_never_up() -> None:
    cycles = [cyc(0, "up"), cyc(1, "degraded"), cyc(2, "down"), cyc(3, "unknown")]
    summary = sla.summarise(cycles, T0, T0 + timedelta(minutes=5))
    assert [w.kind for w in summary.windows] == ["degraded", "down", "unknown"]
    gap = summary.windows[-1]
    assert gap.sample_count == 1  # the unknown cycle itself
    assert gap.duration_seconds == 120


def test_unsampled_gaps_have_zero_samples() -> None:
    summary = sla.summarise([cyc(0, "up")], T0, T0 + timedelta(minutes=5))
    gap = summary.windows[-1]
    assert (gap.kind, gap.sample_count, gap.duration_seconds) == ("unknown", 0, 210)


def test_the_window_list_is_bounded_and_says_when_it_was_cut() -> None:
    cycles = [cyc(m * 2, "down") for m in range(40)]
    summary = sla.summarise(cycles, T0, T0 + timedelta(minutes=80), max_windows=10)
    assert len(summary.windows) == 10
    assert summary.windows_truncated is True
    assert summary.outage_count == 40  # counts are never truncated


def test_violations_need_a_configured_target_and_known_time() -> None:
    cycles = [cyc(0, "up"), cyc(1, "down"), cyc(2, "up"), cyc(3, "up")]
    window_end = T0 + timedelta(minutes=4)
    assert sla.summarise(cycles, T0, window_end).violations == ()
    below = sla.summarise(cycles, T0, window_end, uptime_target_pct=99.9)
    assert [(v.kind, v.target_pct, v.actual_pct) for v in below.violations] == [
        ("uptime-below-target", 99.9, 75.0)
    ]
    assert sla.summarise(cycles, T0, window_end, uptime_target_pct=70.0).violations == ()
    assert sla.summarise([], T0, window_end, uptime_target_pct=99.9).violations == ()


def test_the_current_outage_is_reported_only_while_the_newest_cycle_is_current() -> None:
    cycles = [cyc(0, "up"), cyc(1, "down"), cyc(2, "down")]
    now = T0 + timedelta(minutes=2, seconds=30)
    current = sla.current_outage(cycles, now)
    assert current is not None
    assert current.started_at == T0 + timedelta(minutes=1)
    assert current.duration_seconds == 90
    assert sla.current_outage(cycles, T0 + timedelta(minutes=10)) is None  # collector went quiet
    assert sla.current_outage([cyc(0, "down"), cyc(1, "up")], T0 + timedelta(minutes=1)) is None
    assert sla.current_outage([], T0) is None


# --- quality ----------------------------------------------------------------------------------


def stamped(minute: int, sample: Sample) -> tuple[datetime, Sample]:
    return (T0 + timedelta(minutes=minute), sample)


def test_latency_jitter_and_loss_come_from_reachability_samples() -> None:
    rows = [
        stamped(0, s("pass", latency=10.0)),
        stamped(1, s("pass", latency=14.0)),
        stamped(2, s("pass", latency=12.0)),
        stamped(3, s("fail")),
    ]
    quality = sla.quality(rows)
    assert quality.sample_count == 4
    assert quality.latency_ms == 12.0
    assert quality.jitter_ms == 3.0  # |14-10| = 4, |12-14| = 2 -> mean 3
    assert quality.loss_pct == 25.0


def test_jitter_is_per_target_and_needs_two_latencies() -> None:
    rows = [
        stamped(0, s("pass", target="a", latency=10.0)),
        stamped(0, s("pass", target="b", latency=50.0)),
    ]
    quality = sla.quality(rows)
    assert quality.latency_ms == 30.0
    assert quality.jitter_ms is None  # one latency per target: no pair, never 0


def test_unknown_samples_are_not_loss_and_nothing_is_not_zero() -> None:
    only_unknown = sla.quality([stamped(0, s("unknown"))])
    assert only_unknown.loss_pct is None and only_unknown.latency_ms is None
    nothing = sla.quality([])
    assert nothing.sample_count == 0 and nothing.loss_pct is None and nothing.latency_ms is None


def test_a_pass_without_a_latency_counts_as_a_pass_but_adds_no_latency() -> None:
    quality = sla.quality([stamped(0, s("pass")), stamped(1, s("fail"))])
    assert quality.loss_pct == 50.0 and quality.latency_ms is None


def test_dns_is_reported_separately_from_loss() -> None:
    rows = [
        stamped(0, s("pass", latency=10.0)),
        stamped(1, s("fail", probe="dns")),
        stamped(2, s("pass", probe="dns", latency=30.0)),
    ]
    quality = sla.quality(rows)
    assert quality.loss_pct == 0.0
    assert (quality.dns_status, quality.dns_latency_ms) == ("pass", 30.0)
    assert sla.quality([stamped(0, s("pass", latency=1.0))]).dns_status is None


# --- month bounds -------------------------------------------------------------------------------

NOW = datetime(2026, 10, 11, 12, 0, tzinfo=UTC)


def test_a_month_is_utc_calendar_bounded_and_clipped_to_now() -> None:
    start, end = sla.month_window("2026-09", NOW)
    assert (start, end) == (datetime(2026, 9, 1, tzinfo=UTC), datetime(2026, 10, 1, tzinfo=UTC))
    start, end = sla.month_window("2026-10", NOW)
    assert (start, end) == (datetime(2026, 10, 1, tzinfo=UTC), NOW)
    assert sla.month_window("2025-12", NOW)[1] == datetime(2026, 1, 1, tzinfo=UTC)


@pytest.mark.parametrize(
    "month",
    [
        "2026-11",
        "2027-01",
        "2024-09",
        "2026-13",
        "2026-00",
        "2026-9",
        "26-09",
        "",
        "2026-09-01",
        "2026-10 ",
        "٢٠٢٦-٠٩",
        "2026-09\n",
    ],
)
def test_months_outside_the_server_bounds_are_refused(month: str) -> None:
    with pytest.raises(ValueError, match="month"):
        sla.month_window(month, NOW)


def test_the_oldest_allowed_month_is_twenty_four_months_back() -> None:
    assert sla.month_window("2024-10", NOW)[0] == datetime(2024, 10, 1, tzinfo=UTC)
    with pytest.raises(ValueError, match="month"):
        sla.month_window("2024-09", NOW)
