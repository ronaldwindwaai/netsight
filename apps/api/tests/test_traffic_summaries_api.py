"""Applications, Destinations and Anomalies over HTTP: RBAC, policy, baselines, bounds and states."""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from alerting_support import Caller
from fastapi.testclient import TestClient
from traffic_support import (
    GIB,
    HOSTILE,
    NOW,
    WEEK,
    WINDOW,
    FakeSource,
    applications_read,
    destinations_read,
    first_seen,
    hour_of,
    inputs,
    make_application,
    make_destination,
    spike_inputs,
)

from netsight_api import read_limit, traffic_routes
from netsight_api.auth.rate_limit import RateLimiter
from netsight_api.auth.settings import session_policy
from netsight_api.contracts import validate
from netsight_api.main import app
from netsight_api.traffic import guards
from netsight_api.traffic.cache import TtlCache
from netsight_api.traffic.policy import POLICY_FILE_ENV, load_policy

APPS = "/api/v1/traffic/applications"
DESTS = "/api/v1/traffic/destinations"
ANOMS = "/api/v1/traffic/anomalies"
ROLES_WITH_ACCESS = [
    "administrator",
    "network_engineer",
    "security_analyst",
    "auditor",
    "management",
]
HOUR_WINDOW = {"from": "2026-10-11T11:00:00Z", "to": "2026-10-11T12:00:00Z"}
SCHEMA = {APPS: "traffic_applications", DESTS: "traffic_destinations", ANOMS: "traffic_anomalies"}


@pytest.fixture(autouse=True)
def _wiring(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in (
        "NETSIGHT_ENV",
        "NETSIGHT_ENABLE_DEV_IDENTITY",
        "DATABASE_URL",
        "CLICKHOUSE_DSN",
        POLICY_FILE_ENV,
    ):
        monkeypatch.delenv(name, raising=False)
    app.dependency_overrides.clear()
    session_policy.cache_clear()
    monkeypatch.setattr(read_limit, "_read_limiter", RateLimiter())
    guards.reset_for_tests()
    app.dependency_overrides[traffic_routes.get_now] = lambda: NOW
    app.dependency_overrides[traffic_routes.get_anomaly_cache] = lambda: TtlCache()
    yield
    app.dependency_overrides.clear()
    session_policy.cache_clear()


def use(source: FakeSource | None) -> None:
    app.dependency_overrides[traffic_routes.get_explorer_source] = lambda: source


def get(path: str, role: str = "administrator", **params: Any) -> Any:
    return Caller(role).get(path, **{**WINDOW, **params})


def ok(path: str, role: str = "administrator", **params: Any) -> dict[str, Any]:
    response = get(path, role, **params)
    assert response.status_code == 200, response.text
    body = response.json()
    validate(SCHEMA[path], body)
    return body  # type: ignore[no-any-return]


def policy_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, document: Any) -> None:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(document) if not isinstance(document, str) else document, "utf-8")
    monkeypatch.setenv(POLICY_FILE_ENV, str(path))


# --- access --------------------------------------------------------------------------------------------


@pytest.mark.parametrize("path", [APPS, DESTS, ANOMS])
def test_anonymous_callers_are_refused(path: str) -> None:
    assert TestClient(app).get(path).status_code == 401


@pytest.mark.parametrize("path", [APPS, DESTS, ANOMS])
def test_technician_and_unknown_roles_are_refused(path: str) -> None:
    use(FakeSource())
    assert get(path, "technician").status_code == 403
    assert get(path, "not-a-role").status_code == 403


@pytest.mark.parametrize("path", [APPS, DESTS, ANOMS])
@pytest.mark.parametrize("role", ROLES_WITH_ACCESS)
def test_the_aggregate_rung_reaches_every_summary(path: str, role: str) -> None:
    use(None)
    assert get(path, role).status_code == 200


@pytest.mark.parametrize("path", [APPS, DESTS, ANOMS])
def test_summaries_are_read_only_and_never_cached(path: str) -> None:
    use(None)
    caller = Caller("administrator")
    for verb in ("post", "put", "delete", "patch"):
        assert getattr(caller.http, verb)(path).status_code in {404, 405}
    assert caller.get(path, **WINDOW).headers["cache-control"] == "no-store"


@pytest.mark.parametrize("path", [APPS, DESTS, ANOMS])
def test_summaries_name_no_endpoint_and_take_no_filters(path: str) -> None:
    use(None)
    for name in ("source_ip", "destination_ip", "user", "device", "sort"):
        assert get(path, **{name: "10.0.0.10"}).status_code == 422, name


@pytest.mark.parametrize("path", [APPS, DESTS, ANOMS])
def test_bounds_are_a_422(path: str) -> None:
    use(None)
    assert get(path, preset="12h").status_code == 422
    assert Caller("administrator").get(path, **{"from": WINDOW["from"]}).status_code == 422
    assert (
        get(path, **{"from": "2026-10-11T12:00:00Z", "to": "2026-10-11T00:00:00Z"}).status_code
        == 422
    )
    assert (
        get(path, **{"from": "2026-01-01T00:00:00Z", "to": "2026-10-11T00:00:00Z"}).status_code
        == 422
    )
    repeated = Caller("administrator").http.get(path + "?preset=1h&preset=6h")
    assert repeated.status_code == 422


@pytest.mark.parametrize("path", [APPS, DESTS])
def test_list_limits_are_bounded(path: str) -> None:
    use(FakeSource(applications=applications_read(), destinations=destinations_read()))
    assert get(path, limit="0").status_code == 422
    assert get(path, limit="101").status_code == 422
    assert get(path, limit="100").status_code == 200


@pytest.mark.parametrize("path", [APPS, DESTS, ANOMS])
def test_authorisation_precedes_the_rate_limit(path: str) -> None:
    caller = Caller("technician")
    assert {caller.get(path, **WINDOW).status_code for _ in range(40)} == {403}


def test_the_anomaly_budget_is_the_smallest() -> None:
    use(FakeSource(inputs=inputs()))
    caller = Caller("administrator")
    codes = [
        caller.get(ANOMS, **WINDOW).status_code
        for _ in range(traffic_routes.ANOMALY_LIMIT_PER_MINUTE + 1)
    ]
    assert codes[-1] == 429 and set(codes[:-1]) == {200}


def test_a_busy_flow_source_is_a_503_not_a_queue(monkeypatch: pytest.MonkeyPatch) -> None:
    use(
        FakeSource(
            applications=applications_read(), destinations=destinations_read(), inputs=inputs()
        )
    )
    monkeypatch.setattr(guards, "MAX_CONCURRENT_HEAVY", 0)
    for path in (APPS, DESTS, ANOMS):
        response = get(path)
        assert response.status_code == 503 and response.headers["retry-after"] == "5", path


# --- states ---------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("path", [APPS, DESTS, ANOMS])
def test_no_source_is_not_connected(path: str) -> None:
    use(None)
    body = ok(path)
    assert body["state"] == "not-connected"
    assert body["freshness"] == {"state": "unknown", "observed_at": None, "source": None}
    assert not body.get("items") and not body.get("anomalies")


@pytest.mark.parametrize("path", [APPS, DESTS, ANOMS])
def test_a_failing_source_is_unknown_and_leaks_nothing(
    path: str, caplog: pytest.LogCaptureFixture
) -> None:
    use(FakeSource(error=RuntimeError("clickhouse exploded: password=hunter2")))
    with caplog.at_level(logging.WARNING):
        body = ok(path)
    assert body["state"] == "unknown" and body["freshness"]["source"] == "clickhouse"
    assert "hunter2" not in json.dumps(body) and "hunter2" not in caplog.text


# --- applications -----------------------------------------------------------------------------------------------


def test_applications_without_a_policy_are_unknown_not_guessed() -> None:
    use(FakeSource(applications=applications_read()))
    body = ok(APPS)
    assert body["state"] == "ok" and body["policy"] == {"state": "not-configured"}
    (row,) = body["items"]
    assert row["risk"] == "unknown" and row["approval"] == "unknown"
    assert row["users"] is None and row["endpoints"] == 25
    assert row["trend"]["state"] == "up"
    assert body["previous_range"] is not None and body["previous_range"]["preset"] is None


def test_approval_and_risk_come_only_from_the_operator_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy_file(
        tmp_path,
        monkeypatch,
        {
            "version": 1,
            "applications": {
                "approved": ["Microsoft 365"],
                "unapproved": ["BitTorrent"],
                "risk": {"BitTorrent": "high", "Microsoft 365": "low"},
            },
        },
    )
    rows = [
        make_application(rank=1, application="Microsoft 365"),
        make_application(
            rank=2,
            application="BitTorrent",
            bytes=100,
            share=None,
            trend={"state": "unknown", "previous_bytes": None, "change_ratio": None},
        ),
        make_application(
            rank=3,
            application="Unlisted",
            bytes=50,
            share=None,
            trend={"state": "unknown", "previous_bytes": None, "change_ratio": None},
        ),
    ]
    use(FakeSource(applications=applications_read(rows)))
    body = ok(APPS)
    assert body["policy"] == {"state": "configured"}
    by_name = {r["application"]: r for r in body["items"]}
    assert (by_name["Microsoft 365"]["approval"], by_name["Microsoft 365"]["risk"]) == (
        "approved",
        "low",
    )
    assert (by_name["BitTorrent"]["approval"], by_name["BitTorrent"]["risk"]) == (
        "unapproved",
        "high",
    )
    assert (by_name["Unlisted"]["approval"], by_name["Unlisted"]["risk"]) == ("unknown", "unknown")


def test_an_invalid_policy_file_classifies_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy_file(tmp_path, monkeypatch, "{not json")
    use(FakeSource(applications=applications_read([make_application(application="Zoom")])))
    body = ok(APPS)
    assert body["policy"] == {"state": "invalid"}
    assert (body["items"][0]["approval"], body["items"][0]["risk"]) == ("unknown", "unknown")


def test_a_hostile_application_name_is_data_and_earns_no_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy_file(tmp_path, monkeypatch, {"version": 1, "applications": {"approved": ["Zoom"]}})
    use(FakeSource(applications=applications_read([make_application(application=HOSTILE)])))
    row = ok(APPS)["items"][0]
    assert row["application"] == HOSTILE and row["approval"] == "unknown"


def test_a_source_without_applications_is_unknown_and_says_what_is_missing() -> None:
    use(
        FakeSource(
            applications=applications_read([], unsupported=("application",), total_bytes=None)
        )
    )
    body = ok(APPS)
    assert (
        body["state"] == "unknown"
        and body["unsupported"] == ["application"]
        and body["items"] == []
    )


def test_a_long_window_has_no_previous_range() -> None:
    use(FakeSource(applications=applications_read(previous_range=None)))
    assert ok(APPS)["previous_range"] is None


def test_applications_contract_violations_degrade_to_unknown() -> None:
    rows = [make_application(rank=2)]  # ranks must run 1..n
    use(FakeSource(applications=applications_read(rows)))
    assert ok(APPS)["state"] == "unknown"


def test_the_window_and_limit_reach_the_source() -> None:
    source = FakeSource(applications=applications_read())
    use(source)
    ok(APPS, limit="7")
    assert source.calls[0]["limit"] == 7 and source.calls[0]["end"] - source.calls[0][
        "start"
    ] == timedelta(hours=12)


# --- destinations -------------------------------------------------------------------------------------------------


def test_destinations_without_lists_have_unknown_reputation() -> None:
    use(FakeSource(destinations=destinations_read()))
    body = ok(DESTS)
    assert body["state"] == "ok" and body["policy"] == {"state": "not-configured"}
    row = body["items"][0]
    assert row["reputation"] == "unknown" and row["users"] is None and row["endpoints"] == 12
    assert body["first_seen_since"] is not None


def test_reputation_comes_only_from_the_operator_lists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy_file(
        tmp_path,
        monkeypatch,
        {
            "version": 1,
            "destinations": {
                "allow": ["203.0.113.0/24", "AS64501"],
                "deny": ["bad.example", "AS64666"],
            },
        },
    )
    rows = [
        make_destination(rank=1, address="203.0.113.9", domain="cdn.example.net", asn=64500),
        make_destination(
            rank=2, address="198.51.100.7", domain="files.bad.example", asn=64500, bytes=9
        ),
        make_destination(rank=3, address="192.0.2.5", domain=None, asn=64501, bytes=8),
        make_destination(rank=4, address="192.0.2.6", domain=None, asn=None, bytes=7),
        make_destination(rank=5, address="192.0.2.7", domain=None, asn=64666, bytes=6),
    ]
    use(FakeSource(destinations=destinations_read(rows)))
    got = {r["address"]: r["reputation"] for r in ok(DESTS)["items"]}
    assert got == {
        "203.0.113.9": "allow-listed",
        "198.51.100.7": "deny-listed",
        "192.0.2.5": "allow-listed",
        "192.0.2.6": "unknown",
        "192.0.2.7": "deny-listed",
    }


def test_a_spoofable_hostname_never_earns_allow_listing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy_file(tmp_path, monkeypatch, {"version": 1, "destinations": {"allow": ["AS64501"]}})
    row = make_destination(address="198.51.100.7", domain="as64501.trusted.example", asn=64500)
    use(FakeSource(destinations=destinations_read([row])))
    assert ok(DESTS)["items"][0]["reputation"] == "unknown"


def test_destination_text_is_data() -> None:
    use(FakeSource(destinations=destinations_read([make_destination(domain=HOSTILE)])))
    assert ok(DESTS)["items"][0]["domain"] == HOSTILE


def test_destinations_contract_violations_degrade_to_unknown() -> None:
    use(FakeSource(destinations=destinations_read([make_destination(rank=3)])))
    assert ok(DESTS)["state"] == "unknown"


# --- anomalies ---------------------------------------------------------------------------------------------------------


def observed_hour():
    return NOW.replace(hour=11, minute=0)  # the last complete hour before 12:00


def test_a_spike_against_four_comparable_weeks_is_reported_with_its_evidence() -> None:
    use(FakeSource(inputs=spike_inputs(observed_hour())))
    body = ok(ANOMS, **HOUR_WINDOW)
    assert body["state"] == "ok"
    assert (
        body["evaluation"]["status"] == "evaluated" and body["evaluation"]["anomalies_total"] == 1
    )
    (found,) = body["anomalies"]
    assert found["subject"] == {"kind": "total", "label": None}
    assert (found["direction"], found["observed"], found["baseline"]) == ("above", 9 * GIB, GIB)
    assert found["difference"] == 8 * GIB and found["baseline_samples"] == 4
    assert found["confidence"] == "high" and found["ratio"] == pytest.approx(9.0)
    assert found["bucket_start"].startswith("2026-10-11T11:00:00")
    assert body["method"]["algorithm"] == "same-hour-of-week-median-mad"
    assert (body["method"]["weeks"], body["method"]["min_weeks"]) == (4, 3)


def test_the_judged_hours_are_whole_and_complete() -> None:
    source = FakeSource(inputs=spike_inputs(observed_hour()))
    use(source)
    body = ok(ANOMS, **{"from": "2026-10-11T08:30:00Z", "to": "2026-10-11T12:20:00Z"})
    (call,) = source.calls
    assert call["last"].isoformat().startswith("2026-10-11T12:00:00")
    assert (call["last"] - call["first"]) == timedelta(hours=4)  # ceil(3h50m) hours back from 12:00
    assert body["evaluated_range"]["from"].startswith("2026-10-11T08:00:00")
    assert body["time_range"]["from"].startswith(
        "2026-10-11T08:30:00"
    )  # the request, echoed as asked


def test_below_the_minimum_weeks_nothing_is_flagged_and_the_response_says_so() -> None:
    use(FakeSource(inputs=spike_inputs(observed_hour(), weeks=2)))
    body = ok(ANOMS, **HOUR_WINDOW)
    assert body["anomalies"] == []
    assert body["evaluation"]["status"] == "insufficient-baseline"
    assert (body["evaluation"]["evaluated"], body["evaluation"]["insufficient_baseline"]) == (0, 1)


def test_an_hour_the_source_has_no_data_for_is_no_data_not_a_drop() -> None:
    use(FakeSource(inputs=inputs(hourly_total={hour_of(observed_hour()) - WEEK: GIB})))
    body = ok(ANOMS, **HOUR_WINDOW)
    assert body["evaluation"]["status"] == "no-data" and body["anomalies"] == []
    assert body["evaluation"]["no_data"] == 1


def test_applications_are_judged_as_their_own_series() -> None:
    hour = hour_of(observed_hour())
    totals = {hour - k * WEEK: 2 * GIB for k in range(5)}
    zoom = {hour - k * WEEK: GIB for k in range(1, 5)} | {hour: 8 * GIB}
    use(FakeSource(inputs=inputs(hourly_total=totals, hourly_apps={"Zoom": zoom})))
    body = ok(ANOMS, **HOUR_WINDOW)
    assert (
        body["evaluation"]["series"] == 2
        and body["evaluation"]["application_series"] == "evaluated"
    )
    assert [a["subject"] for a in body["anomalies"]] == [{"kind": "application", "label": "Zoom"}]


def test_applications_not_reported_by_the_source_are_said_not_to_be() -> None:
    use(
        FakeSource(
            inputs=spike_inputs(observed_hour()).__class__(
                **{**spike_inputs(observed_hour()).__dict__, "applications_reported": False}
            )
        )
    )
    assert ok(ANOMS, **HOUR_WINDOW)["evaluation"]["application_series"] == "not-reported"


def test_outside_working_hours_is_context_with_common_legitimate_causes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy_file(
        tmp_path,
        monkeypatch,
        {
            "version": 1,
            "working_hours": {
                "timezone": "UTC",
                "days": ["mon", "tue", "wed", "thu", "fri", "sat", "sun"],
                "start": "13:00",
                "end": "17:00",
            },
        },
    )
    use(FakeSource(inputs=spike_inputs(observed_hour())))
    body = ok(ANOMS, **HOUR_WINDOW)
    assert body["working_hours"] == {"state": "configured", "timezone": "UTC"}
    context = body["anomalies"][0]["context"]
    assert context["outside_working_hours"] is True
    assert "backup" in context["common_legitimate_patterns"]
    assert "patching-or-updates" in context["common_legitimate_patterns"]
    assert "malicious" not in json.dumps(body).lower()


def test_inside_working_hours_lists_no_legitimate_causes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy_file(
        tmp_path,
        monkeypatch,
        {
            "version": 1,
            "working_hours": {
                "timezone": "UTC",
                "days": ["mon", "tue", "wed", "thu", "fri", "sat", "sun"],
                "start": "08:00",
                "end": "17:00",
            },
        },
    )
    use(FakeSource(inputs=spike_inputs(observed_hour())))
    context = ok(ANOMS, **HOUR_WINDOW)["anomalies"][0]["context"]
    assert context == {"outside_working_hours": False, "common_legitimate_patterns": []}


def test_without_working_hours_the_flag_is_unknown_never_assumed() -> None:
    use(FakeSource(inputs=spike_inputs(observed_hour())))
    body = ok(ANOMS, **HOUR_WINDOW)
    assert body["working_hours"] == {"state": "not-configured", "timezone": None}
    assert body["anomalies"][0]["context"] == {
        "outside_working_hours": None,
        "common_legitimate_patterns": [],
    }


def test_a_drop_is_not_given_causes_for_high_volume(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy_file(
        tmp_path,
        monkeypatch,
        {
            "version": 1,
            "working_hours": {"timezone": "UTC", "days": ["mon"], "start": "08:00", "end": "09:00"},
        },
    )
    use(FakeSource(inputs=spike_inputs(observed_hour(), spike=GIB // 20)))
    found = ok(ANOMS, **HOUR_WINDOW)["anomalies"][0]
    assert found["direction"] == "below"
    assert found["context"]["outside_working_hours"] is True
    assert found["context"]["common_legitimate_patterns"] == []


def test_first_seen_flags_need_history_before_the_window() -> None:
    rows = (first_seen(), first_seen(kind="first-seen-asn", asn=64501, address=None, bytes=7))
    use(FakeSource(inputs=inputs(first_seen=rows, oldest=NOW - timedelta(days=2))))
    body = ok(ANOMS, **HOUR_WINDOW)
    assert body["first_seen_status"]["state"] == "insufficient" and body["first_seen"] == []


def test_first_seen_destinations_and_asns_are_listed_with_context() -> None:
    rows = (
        first_seen(address="198.51.100.7", bytes=300),
        first_seen(address="10.9.9.9", bytes=900),  # internal space is not a new destination
        first_seen(kind="first-seen-asn", asn=64501, address=None, bytes=500),
    )
    use(FakeSource(inputs=inputs(first_seen=rows)))
    body = ok(ANOMS, **HOUR_WINDOW)
    assert body["first_seen_status"]["state"] == "sufficient"
    assert [(r["kind"], r["asn"], r["address"]) for r in body["first_seen"]] == [
        ("first-seen-asn", 64501, None),
        ("first-seen-destination", None, "198.51.100.7"),
    ]
    assert body["first_seen"][0]["context"]["outside_working_hours"] is None


def test_first_seen_is_capped_at_twenty() -> None:
    rows = tuple(first_seen(address=f"198.51.100.{n}", bytes=1000 - n) for n in range(1, 31))
    use(FakeSource(inputs=inputs(first_seen=rows)))
    assert len(ok(ANOMS, **HOUR_WINDOW)["first_seen"]) == 20


def test_anomalies_are_capped_at_fifty_but_all_are_counted() -> None:
    hour = hour_of(observed_hour())
    hours = [hour - n * 3600 for n in range(60)]
    totals = {h - k * WEEK: GIB for h in hours for k in range(1, 5)} | {h: 9 * GIB for h in hours}
    use(FakeSource(inputs=inputs(hourly_total=totals)))
    body = ok(ANOMS, **{"from": "2026-10-08T12:00:00Z", "to": "2026-10-11T12:00:00Z"})
    assert len(body["anomalies"]) == 50 and body["evaluation"]["anomalies_total"] == 60


def test_the_window_is_capped_at_a_week() -> None:
    use(FakeSource(inputs=inputs()))
    assert (
        get(ANOMS, **{"from": "2026-10-03T11:00:00Z", "to": "2026-10-11T12:00:00Z"}).status_code
        == 422
    )
    assert (
        get(ANOMS, **{"from": "2026-10-04T12:00:00Z", "to": "2026-10-11T12:00:00Z"}).status_code
        == 200
    )


def test_the_baseline_load_is_cached_and_shared_by_identity() -> None:
    source = FakeSource(inputs=spike_inputs(observed_hour()))
    use(source)
    shared = TtlCache()
    app.dependency_overrides[traffic_routes.get_anomaly_cache] = lambda: shared
    ok(ANOMS, "administrator", **HOUR_WINDOW)
    ok(ANOMS, "management", **HOUR_WINDOW)
    assert source.methods() == ["anomaly_inputs"]  # one load, two readers
    ok(ANOMS, "administrator", **{"from": "2026-10-11T00:00:00Z", "to": "2026-10-11T12:00:00Z"})
    assert source.methods() == [
        "anomaly_inputs",
        "anomaly_inputs",
    ]  # a different window loads again


def test_a_failed_baseline_load_is_not_cached() -> None:
    source = FakeSource(error=RuntimeError("down"))
    use(source)
    shared = TtlCache()
    app.dependency_overrides[traffic_routes.get_anomaly_cache] = lambda: shared
    assert ok(ANOMS, **HOUR_WINDOW)["state"] == "unknown"
    source.error = None
    source._inputs = spike_inputs(observed_hour())
    assert ok(ANOMS, **HOUR_WINDOW)["state"] == "ok"
    assert len(shared) == 1


# --- the cache itself ----------------------------------------------------------------------------------------------------


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


@pytest.mark.asyncio
async def test_cache_entries_expire() -> None:
    clock = Clock()
    cache = TtlCache(ttl_seconds=10, clock=clock)
    loads: list[int] = []

    async def load() -> int:
        loads.append(1)
        return len(loads)

    assert await cache.get_or_load("k", load) == 1
    clock.now = 9
    assert await cache.get_or_load("k", load) == 1
    clock.now = 10
    assert await cache.get_or_load("k", load) == 2


@pytest.mark.asyncio
async def test_cache_is_bounded() -> None:
    cache = TtlCache(max_entries=3)

    async def load() -> int:
        return 1

    for key in range(10):
        await cache.get_or_load(key, load)
    assert len(cache) == 3


@pytest.mark.asyncio
async def test_concurrent_requests_for_one_key_share_one_load() -> None:
    cache = TtlCache()
    started = 0

    async def slow() -> int:
        nonlocal started
        started += 1
        await asyncio.sleep(0.05)
        return 7

    results = await asyncio.gather(*(cache.get_or_load("k", slow) for _ in range(8)))
    assert results == [7] * 8 and started == 1


@pytest.mark.asyncio
async def test_a_failing_load_propagates_and_is_not_stored() -> None:
    cache = TtlCache()

    async def boom() -> int:
        raise RuntimeError("x")

    with pytest.raises(RuntimeError):
        await cache.get_or_load("k", boom)
    assert len(cache) == 0

    async def fine() -> int:
        return 5

    assert await cache.get_or_load("k", fine) == 5


def test_the_policy_loader_is_the_only_classifier() -> None:
    assert load_policy(None).state == "not-configured"
