"""Rule schedules: when, in the schedule's timezone, a rule is allowed to fire.

The instant being judged is converted to the schedule's local wall-clock time and compared
with the configured times of day, so daylight-saving transitions behave as a person reading
the clock would expect:

* a time of day that does not exist (spring-forward gap) simply never occurs, so a window
  that covers it is one real hour shorter that night;
* a time of day that happens twice (fall-back) is matched in both passes.

Weekdays name the day a window *starts*. A window whose ``to`` is earlier than ``from``
crosses midnight and also covers the early hours of the following day; equal ``from`` and
``to`` mean the whole day (``alert-rule.schema.json``). A ``to`` is exclusive.
An unknown timezone raises :class:`ScheduleError`: the caller must treat that as "do not
fire" (fail closed), never as "always active".
"""

from __future__ import annotations

import re
from datetime import datetime
from functools import lru_cache
from typing import Final
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from netsight_api.schemas import AlertSchedule, AlertScheduleEntry

_WEEKDAYS: Final = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
_ZONE_NAME: Final = re.compile(r"^(UTC|[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z][A-Za-z0-9_+-]*){1,2})$")
_MAX_ZONE_NAME: Final = 64


class ScheduleError(ValueError):
    """The schedule cannot be evaluated (unknown timezone). Fail closed."""


@lru_cache(maxsize=256)
def _load(name: str) -> ZoneInfo:
    return ZoneInfo(name)


def load_zone(name: str) -> ZoneInfo:
    """The IANA zone ``name`` or :class:`ScheduleError`; hostile names never reach the loader."""
    if len(name) > _MAX_ZONE_NAME or _ZONE_NAME.fullmatch(name) is None:
        raise ScheduleError("timezone name is not a valid IANA key")
    try:
        return _load(name)
    except (ZoneInfoNotFoundError, ValueError, OSError):
        raise ScheduleError("timezone is not available on this host") from None


def _minutes(time_of_day: str) -> int:
    return int(time_of_day[:2]) * 60 + int(time_of_day[3:])


def _entry_active(
    entry: AlertScheduleEntry, weekday: str, previous_weekday: str, minute: int
) -> bool:
    start, end = _minutes(entry.from_), _minutes(entry.to)
    today = weekday in entry.weekdays
    if start == end:
        return today
    if start < end:
        return today and start <= minute < end
    # Crosses midnight: the evening part belongs to today, the morning part to yesterday.
    return (today and minute >= start) or (previous_weekday in entry.weekdays and minute < end)


def schedule_active(schedule: AlertSchedule | None, at: datetime) -> bool:
    """True when ``at`` falls inside the schedule; no schedule means always active."""
    if at.tzinfo is None or at.utcoffset() is None:
        raise ValueError("the instant must be timezone-aware")
    if schedule is None:
        return True
    local = at.astimezone(load_zone(schedule.timezone))
    weekday = _WEEKDAYS[local.weekday()]
    previous_weekday = _WEEKDAYS[(local.weekday() - 1) % 7]
    minute = local.hour * 60 + local.minute
    return any(_entry_active(entry, weekday, previous_weekday, minute) for entry in schedule.active)
