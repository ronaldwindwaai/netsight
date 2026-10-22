"""The sliding-window limiter must not grow without bound: a key whose hits have all expired is
deleted (swept periodically), so a stream of one-off keys does not accumulate memory."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from netsight_api.auth import rate_limit
from netsight_api.auth.rate_limit import RateLimiter


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def monotonic(self) -> float:
        return self.now


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    fake = Clock()
    monkeypatch.setattr(rate_limit, "time", SimpleNamespace(monotonic=fake.monotonic))
    return fake


def test_expired_keys_are_removed_by_the_periodic_sweep(clock: Clock) -> None:
    limiter = RateLimiter()
    for number in range(500):
        assert limiter.allow(f"ip-{number}", 5, 60)
    assert len(limiter) == 500
    clock.now += 61 + 60  # past every window and past the sweep interval
    limiter.allow("someone-new", 5, 60)
    assert len(limiter) == 1  # only the live key remains


def test_a_key_with_live_hits_survives_the_sweep(clock: Clock) -> None:
    limiter = RateLimiter()
    limiter.allow("busy", 2, 600)
    limiter.allow("quiet", 2, 10)
    clock.now += 120
    limiter.allow("trigger", 2, 10)
    assert len(limiter) == 2  # busy (window 600 s still open) and trigger; quiet is gone
    assert limiter.allow("busy", 2, 600) is True
    assert limiter.allow("busy", 2, 600) is False  # its earlier hits still count


def test_limits_still_apply_and_reset_removes_the_key(clock: Clock) -> None:
    limiter = RateLimiter()
    assert [limiter.allow("k", 2, 60) for _ in range(3)] == [True, True, False]
    limiter.reset("k")
    assert len(limiter) == 0 and limiter.allow("k", 2, 60) is True


def test_a_disabled_limit_stores_nothing(clock: Clock) -> None:
    limiter = RateLimiter()
    assert limiter.allow("k", 0, 60) is True
    assert len(limiter) == 0


def test_the_window_slides_so_old_hits_stop_counting(clock: Clock) -> None:
    limiter = RateLimiter()
    assert limiter.allow("k", 1, 30) and not limiter.allow("k", 1, 30)
    clock.now += 31
    assert limiter.allow("k", 1, 30) is True
