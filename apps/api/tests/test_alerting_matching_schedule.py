"""Pure helpers of the alert engine: linear-time text matching, schedules, maintenance windows."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest

from netsight_api.alerting.maintenance import effect_of_windows, window_phase
from netsight_api.alerting.matching import MAX_MATCH_TEXT_LENGTH, glob_matches
from netsight_api.alerting.schedule import ScheduleError, load_zone, schedule_active
from netsight_api.schemas import AlertSchedule, AlertScope, MaintenanceWindowDefinition

# --- glob matching (the 'matches' operator must never use a backtracking regex engine) ----


@pytest.mark.parametrize(
    ("pattern", "text", "expected"),
    [
        ("abc", "abc", True),
        ("abc", "abd", False),
        ("abc", "ABC", False),
        ("a*c", "abbbc", True),
        ("a*c", "ac", True),
        ("a*c", "acd", False),
        ("*", "", True),
        ("*", "anything at all", True),
        ("?", "", False),
        ("a?c", "abc", True),
        ("a?c", "ac", False),
        ("*ssh*", "Failed ssh login from 10.0.0.1", True),
        ("**a**", "bab", True),
        # Regex metacharacters are literals: this is not a regular expression.
        (".*", "abc", False),
        (".*", ".*", True),
        ("(a+)+$", "aaaa", False),
        ("[ab]", "a", False),
        ("a|b", "a", False),
        ("\\d", "5", False),
        ("é?", "éa", True),
        ("", "", True),
        ("", "x", False),
    ],
)
def test_glob_matching_semantics(pattern: str, text: str, expected: bool) -> None:
    assert glob_matches(pattern, text) is expected


def _reference_glob(pattern: str, text: str) -> bool:
    """Obvious O(n*m) dynamic programme, used only to cross-check the bit-parallel matcher."""
    previous = [False] * (len(text) + 1)
    previous[0] = True
    for token in pattern:
        current = [False] * (len(text) + 1)
        if token == "*":
            current[0] = previous[0]
            for j in range(1, len(text) + 1):
                current[j] = previous[j] or current[j - 1]
        else:
            for j in range(1, len(text) + 1):
                current[j] = previous[j - 1] and (token == "?" or token == text[j - 1])
        previous = current
    return previous[len(text)]


def test_matcher_agrees_with_a_reference_on_random_small_alphabet_inputs() -> None:
    import random

    rng = random.Random(20261008)  # fixed seed: deterministic
    for _ in range(4000):
        pattern = "".join(rng.choice("ab*?") for _ in range(rng.randint(0, 9)))
        text = "".join(rng.choice("abc") for _ in range(rng.randint(0, 9)))
        assert glob_matches(pattern, text) is _reference_glob(pattern, text), (pattern, text)


def test_adversarial_pattern_runs_in_bounded_time() -> None:
    pattern = "a*" * 120 + "b"  # catastrophic for a backtracking matcher
    text = "a" * 4000
    started = time.perf_counter()
    assert glob_matches(pattern, text) is False
    assert glob_matches("a*" * 120, text) is True
    assert glob_matches("?" * 250 + "*", text) is True
    assert time.perf_counter() - started < 0.5


def test_over_long_text_does_not_match_instead_of_burning_cpu() -> None:
    assert glob_matches("*", "x" * (MAX_MATCH_TEXT_LENGTH + 1)) is False
    assert glob_matches("*", "x" * MAX_MATCH_TEXT_LENGTH) is True


# --- schedules ---------------------------------------------------------------------------------


def utc(*parts: int) -> datetime:
    return datetime(*parts, tzinfo=UTC)  # type: ignore[arg-type, misc]


def schedule(tz: str, *entries: tuple[list[str], str, str]) -> AlertSchedule:
    return AlertSchedule.model_validate(
        {
            "timezone": tz,
            "active": [
                {"weekdays": days, "from": start, "to": end} for days, start, end in entries
            ],
        }
    )


WEEKDAYS = ["mon", "tue", "wed", "thu", "fri"]


def test_no_schedule_is_always_active() -> None:
    assert schedule_active(None, utc(2026, 10, 8, 3, 0)) is True


def test_naive_instants_are_refused() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        schedule_active(
            schedule("UTC", (WEEKDAYS, "08:00", "17:00")),
            datetime(2026, 10, 8, 9),  # noqa: DTZ001 (deliberately naive)
        )


def test_same_day_window_is_half_open() -> None:
    s = schedule("UTC", (WEEKDAYS, "08:00", "17:00"))
    thursday = (2026, 10, 8)
    assert schedule_active(s, utc(*thursday, 7, 59)) is False
    assert schedule_active(s, utc(*thursday, 8, 0)) is True
    assert schedule_active(s, utc(*thursday, 16, 59)) is True
    assert schedule_active(s, utc(*thursday, 17, 0)) is False


def test_weekday_filter_applies() -> None:
    s = schedule("UTC", (WEEKDAYS, "08:00", "17:00"))
    assert schedule_active(s, utc(2026, 10, 10, 9, 0)) is False  # Saturday
    assert schedule_active(s, utc(2026, 10, 9, 9, 0)) is True  # Friday


def test_overnight_window_belongs_to_the_day_it_starts() -> None:
    s = schedule("UTC", (WEEKDAYS, "20:00", "06:00"))  # the ALERT-ENGINE.md example
    assert schedule_active(s, utc(2026, 10, 8, 21, 0)) is True  # Thu evening
    assert schedule_active(s, utc(2026, 10, 9, 5, 59)) is True  # Fri early: Thu's window
    assert schedule_active(s, utc(2026, 10, 9, 6, 0)) is False
    assert schedule_active(s, utc(2026, 10, 9, 21, 0)) is True  # Fri evening
    # Friday night runs into Saturday morning; Saturday evening does not start a window.
    assert schedule_active(s, utc(2026, 10, 10, 5, 0)) is True
    assert schedule_active(s, utc(2026, 10, 10, 21, 0)) is False
    # Monday early morning: Sunday does not start a window, so it is not active.
    assert schedule_active(s, utc(2026, 10, 12, 5, 0)) is False


def test_equal_from_and_to_means_the_whole_day() -> None:
    s = schedule("UTC", (["sat"], "00:00", "00:00"))
    assert schedule_active(s, utc(2026, 10, 10, 0, 0)) is True
    assert schedule_active(s, utc(2026, 10, 10, 23, 59)) is True
    assert schedule_active(s, utc(2026, 10, 11, 0, 0)) is False


def test_multiple_entries_union() -> None:
    s = schedule("UTC", (["mon"], "09:00", "10:00"), (["tue"], "09:00", "10:00"))
    assert schedule_active(s, utc(2026, 10, 12, 9, 30)) is True  # Monday
    assert schedule_active(s, utc(2026, 10, 13, 9, 30)) is True  # Tuesday
    assert schedule_active(s, utc(2026, 10, 14, 9, 30)) is False


def test_windhoek_local_time_is_used_not_utc() -> None:
    s = schedule("Africa/Windhoek", (WEEKDAYS, "20:00", "06:00"))  # UTC+2, no DST
    assert schedule_active(s, utc(2026, 10, 8, 18, 30)) is True  # 20:30 local
    assert schedule_active(s, utc(2026, 10, 8, 17, 59)) is False  # 19:59 local
    assert schedule_active(s, utc(2026, 10, 9, 4, 0)) is False  # 06:00 local


def test_fixed_offset_instants_are_converted_not_compared_raw() -> None:
    s = schedule("UTC", (WEEKDAYS, "08:00", "17:00"))
    plus_five = timezone(timedelta(hours=5))
    # 12:00+05:00 is 07:00 UTC: outside.
    assert schedule_active(s, datetime(2026, 10, 8, 12, 0, tzinfo=plus_five)) is False


def test_spring_forward_gap_has_no_phantom_hour() -> None:
    # America/New_York 2026-03-08: 02:00 EST jumps to 03:00 EDT; 02:xx never exists.
    s = schedule("America/New_York", (["sun"], "02:00", "04:00"))
    assert schedule_active(s, utc(2026, 3, 8, 6, 59)) is False  # 01:59 EST
    assert schedule_active(s, utc(2026, 3, 8, 7, 0)) is True  # 03:00 EDT, first real instant
    assert schedule_active(s, utc(2026, 3, 8, 7, 59)) is True
    assert schedule_active(s, utc(2026, 3, 8, 8, 0)) is False  # 04:00 EDT, end exclusive


def test_fall_back_repeats_the_ambiguous_hour_in_both_passes() -> None:
    # America/New_York 2026-11-01: 02:00 EDT falls back to 01:00 EST, so 01:30 happens twice.
    s = schedule("America/New_York", (["sun"], "01:15", "01:45"))
    assert schedule_active(s, utc(2026, 11, 1, 5, 30)) is True  # 01:30 EDT, first pass
    assert schedule_active(s, utc(2026, 11, 1, 6, 30)) is True  # 01:30 EST, second pass
    assert schedule_active(s, utc(2026, 11, 1, 6, 50)) is False  # 01:50 EST


def test_overnight_window_on_the_fall_back_night_is_wall_clock_eleven_hours() -> None:
    s = schedule("America/New_York", (["sat"], "20:00", "06:00"))
    assert schedule_active(s, utc(2026, 11, 1, 0, 0)) is True  # Sat 20:00 EDT
    assert schedule_active(s, utc(2026, 11, 1, 10, 59)) is True  # Sun 05:59 EST
    assert schedule_active(s, utc(2026, 11, 1, 11, 0)) is False  # Sun 06:00 EST


def test_half_hour_and_forty_five_minute_offsets() -> None:
    kolkata = schedule("Asia/Kolkata", (["thu"], "09:00", "10:00"))  # UTC+5:30
    assert schedule_active(kolkata, utc(2026, 10, 8, 3, 30)) is True
    assert schedule_active(kolkata, utc(2026, 10, 8, 4, 30)) is False
    kathmandu = schedule("Asia/Kathmandu", (["thu"], "09:00", "10:00"))  # UTC+5:45
    assert schedule_active(kathmandu, utc(2026, 10, 8, 3, 15)) is True


def test_weekday_is_judged_in_the_schedule_timezone_not_utc() -> None:
    # 2026-10-08 23:30 UTC is already Friday 01:30 in Windhoek.
    s = schedule("Africa/Windhoek", (["fri"], "01:00", "02:00"))
    assert schedule_active(s, utc(2026, 10, 8, 23, 30)) is True


def test_unknown_timezone_fails_closed() -> None:
    s = schedule("Mars/Olympus", (WEEKDAYS, "08:00", "17:00"))
    with pytest.raises(ScheduleError):
        schedule_active(s, utc(2026, 10, 8, 9, 0))
    with pytest.raises(ScheduleError):
        load_zone("Mars/Olympus")


@pytest.mark.parametrize("name", ["../etc/passwd", "", "UTC\x00", "a" * 200, "Europe//London"])
def test_hostile_timezone_names_are_refused_not_loaded(name: str) -> None:
    with pytest.raises(ScheduleError):
        load_zone(name)


# --- maintenance windows --------------------------------------------------------------------------


class _Window:
    """Duck-typed stand-in carrying the five fields the engine reads."""

    def __init__(
        self,
        start: datetime,
        end: datetime,
        *,
        scope: tuple[str, str],
        evaluation: str,
        status: str,
    ) -> None:
        definition = MaintenanceWindowDefinition(
            name="m",
            scope=AlertScope(kind=scope[0], ref=scope[1]),  # type: ignore[arg-type]
            starts_at=start,
            ends_at=end,
            evaluation=evaluation,  # type: ignore[arg-type]
            reason="planned",
        )
        self.scope = definition.scope
        self.starts_at = definition.starts_at
        self.ends_at = definition.ends_at
        self.evaluation = definition.evaluation
        self.status = status


def window(
    start: datetime,
    end: datetime,
    *,
    scope: tuple[str, str] = ("site", "hq"),
    evaluation: str = "retain",
    status: str = "scheduled",
) -> Any:
    return _Window(start, end, scope=scope, evaluation=evaluation, status=status)


T0 = utc(2026, 10, 8, 10, 0)
SCOPES = frozenset({("site", "hq"), ("device", "d1")})


def test_window_phase_is_derived_from_the_clock() -> None:
    w = window(T0, T0 + timedelta(hours=1))
    assert window_phase(w, T0 - timedelta(seconds=1)) == "upcoming"
    assert window_phase(w, T0) == "active"  # start inclusive
    assert window_phase(w, T0 + timedelta(minutes=59, seconds=59)) == "active"
    assert window_phase(w, T0 + timedelta(hours=1)) == "expired"  # end exclusive
    cancelled = window(T0, T0 + timedelta(hours=1), status="cancelled")
    assert window_phase(cancelled, T0 + timedelta(minutes=5)) == "cancelled"


def test_window_phase_requires_an_aware_clock() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        window_phase(
            window(T0, T0 + timedelta(hours=1)),
            datetime(2026, 10, 8, 10, 30),  # noqa: DTZ001 (deliberately naive)
        )


def test_no_matching_window_means_no_effect() -> None:
    other_scope = window(T0, T0 + timedelta(hours=1), scope=("site", "branch"))
    expired = window(T0 - timedelta(hours=3), T0 - timedelta(hours=2))
    cancelled = window(T0, T0 + timedelta(hours=1), status="cancelled")
    effect = effect_of_windows([other_scope, expired, cancelled], SCOPES, T0 + timedelta(minutes=1))
    assert effect.kind == "none"
    assert effect.indexes == ()


def test_active_retain_window_suppresses_notifications_only() -> None:
    effect = effect_of_windows([window(T0, T0 + timedelta(hours=1))], SCOPES, T0)
    assert effect.kind == "suppress"
    assert effect.indexes == (0,)


def test_overlapping_windows_disable_beats_retain_and_union_is_reported() -> None:
    windows = [
        window(T0, T0 + timedelta(hours=2)),
        window(T0 + timedelta(hours=1), T0 + timedelta(hours=3), evaluation="disable"),
        window(T0, T0 + timedelta(hours=5), scope=("device", "d1")),
    ]
    at_1 = effect_of_windows(windows, SCOPES, T0 + timedelta(minutes=30))
    assert (at_1.kind, at_1.indexes) == ("suppress", (0, 2))
    at_2 = effect_of_windows(windows, SCOPES, T0 + timedelta(hours=1, minutes=30))
    assert (at_2.kind, at_2.indexes) == ("disable", (0, 1, 2))
    at_3 = effect_of_windows(windows, SCOPES, T0 + timedelta(hours=2, minutes=30))
    assert (at_3.kind, at_3.indexes) == ("disable", (1, 2))
    at_4 = effect_of_windows(windows, SCOPES, T0 + timedelta(hours=4))
    assert (at_4.kind, at_4.indexes) == ("suppress", (2,))


def test_back_to_back_windows_have_no_gap_and_no_double_count() -> None:
    first = window(T0, T0 + timedelta(hours=1))
    second = window(T0 + timedelta(hours=1), T0 + timedelta(hours=2))
    boundary = T0 + timedelta(hours=1)
    effect = effect_of_windows([first, second], SCOPES, boundary)
    assert (effect.kind, effect.indexes) == ("suppress", (1,))


def test_window_instants_compare_across_offsets() -> None:
    plus_two = timezone(timedelta(hours=2))
    w = window(
        datetime(2026, 10, 8, 12, 0, tzinfo=plus_two),
        datetime(2026, 10, 8, 13, 0, tzinfo=plus_two),
    )
    assert window_phase(w, utc(2026, 10, 8, 10, 30)) == "active"
