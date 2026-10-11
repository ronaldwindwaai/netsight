"""Daylight saving and the fixed 168-hour baseline weeks (Step 7 code review).

The comparison looks back whole weeks in UTC. When the policy time zone changes its clock between the
oldest baseline week and the end of the evaluated range, the *local* hour of the earlier weeks is
shifted by one, so a working-hours reading of an earlier week can differ. The score is unaffected
(it never uses local time); the response flags the crossing so the UI can say so.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from alerting_support import Caller
from traffic_support import FakeSource, inputs

from netsight_api import read_limit, traffic_routes
from netsight_api.auth.rate_limit import RateLimiter
from netsight_api.auth.settings import session_policy
from netsight_api.contracts import validate
from netsight_api.main import app
from netsight_api.traffic import anomaly, guards
from netsight_api.traffic.cache import TtlCache
from netsight_api.traffic.policy import POLICY_FILE_ENV

ANOMS = "/api/v1/traffic/anomalies"
DAY = timedelta(days=1)


def hours(zone: str | None) -> dict[str, Any]:
    document: dict[str, Any] = {"version": 1}
    if zone is not None:
        document["working_hours"] = {
            "timezone": zone,
            "days": ["mon", "tue", "wed", "thu", "fri"],
            "start": "09:00",
            "end": "17:00",
        }
    return document


@pytest.fixture(autouse=True)
def _wiring(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in ("NETSIGHT_ENV", "DATABASE_URL", "CLICKHOUSE_DSN", POLICY_FILE_ENV):
        monkeypatch.delenv(name, raising=False)
    app.dependency_overrides.clear()
    session_policy.cache_clear()
    monkeypatch.setattr(read_limit, "_read_limiter", RateLimiter())
    guards.reset_for_tests()
    app.dependency_overrides[traffic_routes.get_anomaly_cache] = lambda: TtlCache()
    app.dependency_overrides[traffic_routes.get_explorer_source] = lambda: FakeSource(
        inputs=inputs()
    )
    yield
    app.dependency_overrides.clear()
    session_policy.cache_clear()


def evaluation_for(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, zone: str | None, end: datetime
) -> dict[str, Any]:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(hours(zone)), "utf-8")
    monkeypatch.setenv(POLICY_FILE_ENV, str(path))
    response = Caller("administrator").get(
        ANOMS, **{"from": (end - timedelta(hours=2)).isoformat(), "to": end.isoformat()}
    )
    assert response.status_code == 200, response.text
    body = response.json()
    validate("traffic_anomalies", body)
    return body["evaluation"]  # type: ignore[no-any-return]


CLOCKS_FORWARD = datetime(2026, 3, 29, 1, tzinfo=UTC)  # UK summer time begins
CLOCKS_BACK = datetime(2026, 10, 25, 1, tzinfo=UTC)  # UK summer time ends


def test_the_weeks_are_fixed_168_hour_utc_weeks() -> None:
    assert anomaly.WEEK_SECONDS == 7 * 24 * 3600
    hour = int(datetime(2026, 3, 30, 10, tzinfo=UTC).timestamp())
    assert anomaly.prior_hours(hour)[0] == hour - 168 * 3600


def test_a_range_whose_baseline_weeks_cross_the_clock_change_is_flagged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The evaluated range is the day after clocks go forward; its first baseline week is before it.
    end = CLOCKS_FORWARD + DAY + timedelta(hours=11)
    assert (
        evaluation_for(tmp_path, monkeypatch, "Europe/London", end)["daylight_saving"] == "crossed"
    )


def test_a_range_whose_baseline_weeks_all_follow_the_change_is_not_flagged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Five weeks after the spring change even the oldest baseline week (four weeks back) follows it.
    end = CLOCKS_FORWARD + timedelta(weeks=5, hours=11)
    assert evaluation_for(tmp_path, monkeypatch, "Europe/London", end)["daylight_saving"] == "none"


def test_the_autumn_change_is_flagged_too(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    end = CLOCKS_BACK + timedelta(days=2, hours=11)
    assert (
        evaluation_for(tmp_path, monkeypatch, "Europe/London", end)["daylight_saving"] == "crossed"
    )


def test_a_change_up_to_four_weeks_back_still_counts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The change falls in the oldest baseline week (three weeks and six days before the range).
    end = CLOCKS_FORWARD + timedelta(weeks=3, days=6, hours=11)
    assert (
        evaluation_for(tmp_path, monkeypatch, "Europe/London", end)["daylight_saving"] == "crossed"
    )


def test_a_zone_without_daylight_saving_never_crosses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    end = CLOCKS_FORWARD + DAY + timedelta(hours=11)
    result = evaluation_for(tmp_path, monkeypatch, "Africa/Johannesburg", end)
    assert result["daylight_saving"] == "none"


def test_without_a_time_zone_it_is_not_applicable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    end = CLOCKS_FORWARD + DAY + timedelta(hours=11)
    assert evaluation_for(tmp_path, monkeypatch, None, end)["daylight_saving"] == "not-applicable"


def test_without_a_policy_file_it_is_not_applicable() -> None:
    response = Caller("administrator").get(
        ANOMS, **{"from": "2026-03-30T10:00:00Z", "to": "2026-03-30T12:00:00Z"}
    )
    assert response.json()["evaluation"]["daylight_saving"] == "not-applicable"


def test_the_flag_does_not_change_what_is_flagged_as_an_anomaly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The score is UTC arithmetic: the same inputs give the same anomalies in any zone."""
    hour = datetime(2026, 3, 30, 11, tzinfo=UTC)
    week = 7 * 24 * 3600
    base = int(hour.timestamp())
    totals = {base - k * week: 1024**3 for k in range(1, 5)} | {base: 9 * 1024**3}
    app.dependency_overrides[traffic_routes.get_explorer_source] = lambda: FakeSource(
        inputs=inputs(hourly_total=totals)
    )
    found = {}
    for zone in ("Europe/London", "Africa/Johannesburg", None):
        path = tmp_path / f"{zone or 'none'}.json".replace("/", "-")
        path.write_text(json.dumps(hours(zone)), "utf-8")
        monkeypatch.setenv(POLICY_FILE_ENV, str(path))
        body = (
            Caller("administrator")
            .get(ANOMS, **{"from": "2026-03-30T11:00:00Z", "to": "2026-03-30T12:00:00Z"})
            .json()
        )
        found[zone] = [
            (a["bucket_start"], a["observed"], a["baseline"], a["score"]) for a in body["anomalies"]
        ]
    assert found["Europe/London"] == found["Africa/Johannesburg"] == found[None]
    assert len(found[None]) == 1
