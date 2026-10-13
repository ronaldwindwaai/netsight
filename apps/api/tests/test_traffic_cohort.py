"""Small cohorts and internal destinations on the aggregate tier (Step 7 security review, HIGH-2).

``traffic:read`` without ``traffic:read-detail`` (Management) is the aggregate tier. A filter such as
"application = X" can narrow an answer to one machine without naming it, so when fewer than the
configured minimum of source addresses stand behind an answer it is withheld, and the response says
so (``cohort.state == "too-few-sources"``) instead of being quietly emptier. The detail tier is not
subject to the rule. A destination inside the organisation is never listed to the aggregate tier.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from typing import Any

import pytest
from alerting_support import Caller, audit_records
from traffic_support import (
    NOW,
    WINDOW,
    FakeSource,
    applications_read,
    destinations_read,
    exploration,
    first_seen,
    inputs,
    make_aggregations,
    make_application,
    make_destination,
    spike_inputs,
    volume_of,
)

from netsight_api import read_limit, traffic_routes
from netsight_api.auth.rate_limit import RateLimiter
from netsight_api.auth.settings import session_policy
from netsight_api.contracts import validate
from netsight_api.main import app
from netsight_api.schemas_traffic import TrafficFlowsResponse
from netsight_api.traffic import cohort, guards
from netsight_api.traffic.cache import TtlCache
from netsight_api.traffic.filters import FlowFilterSet
from netsight_api.traffic.policy import POLICY_FILE_ENV

FLOWS = "/api/v1/traffic/flows"
APPS = "/api/v1/traffic/applications"
DESTS = "/api/v1/traffic/destinations"
ANOMS = "/api/v1/traffic/anomalies"
SCHEMA = {
    FLOWS: "traffic_flows",
    APPS: "traffic_applications",
    DESTS: "traffic_destinations",
    ANOMS: "traffic_anomalies",
}
DETAIL_ROLES = ["administrator", "network_engineer", "security_analyst", "auditor"]


@pytest.fixture(autouse=True)
def _wiring(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in (
        "NETSIGHT_ENV",
        "NETSIGHT_ENABLE_DEV_IDENTITY",
        "DATABASE_URL",
        "CLICKHOUSE_DSN",
        POLICY_FILE_ENV,
        cohort.MIN_COHORT_ENV,
    ):
        monkeypatch.delenv(name, raising=False)
    app.dependency_overrides.clear()
    session_policy.cache_clear()
    monkeypatch.setattr(read_limit, "_read_limiter", RateLimiter())
    guards.reset_for_tests()
    app.dependency_overrides[traffic_routes.get_now] = lambda: NOW
    app.dependency_overrides[traffic_routes.get_anomaly_cache] = lambda: TtlCache()
    app.dependency_overrides[traffic_routes.get_identity_service] = lambda: None
    yield
    app.dependency_overrides.clear()
    session_policy.cache_clear()


def use(source: FakeSource | None) -> None:
    app.dependency_overrides[traffic_routes.get_explorer_source] = lambda: source


def ok(path: str, role: str = "management", **params: Any) -> dict[str, Any]:
    response = Caller(role).get(path, **{**WINDOW, **params})
    assert response.status_code == 200, response.text
    body = response.json()
    validate(SCHEMA[path], body)
    return body  # type: ignore[no-any-return]


def aggregations_with(sources: int, **overrides: Any) -> Any:
    return make_aggregations(volume=volume_of(sources), **overrides)


# --- the configured minimum ----------------------------------------------------------------------------------


def test_the_default_minimum_is_five() -> None:
    assert cohort.DEFAULT_MIN_COHORT == 5
    assert cohort.min_cohort() == 5


@pytest.mark.parametrize(("raw", "expected"), [("2", 2), ("3", 3), (" 8 ", 8), ("1000", 1000)])
def test_a_valid_minimum_is_used(monkeypatch: pytest.MonkeyPatch, raw: str, expected: int) -> None:
    monkeypatch.setenv(cohort.MIN_COHORT_ENV, raw)
    assert cohort.min_cohort() == expected


@pytest.mark.parametrize("raw", ["1", "0", "-3", "abc", "2.5", "1001", "5 5", "٣"])
def test_an_invalid_minimum_falls_back_to_the_default_and_says_so(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, raw: str
) -> None:
    # Never weaker than the default: a value that would switch the rule off is refused, not honoured.
    monkeypatch.setenv(cohort.MIN_COHORT_ENV, raw)
    with caplog.at_level(logging.WARNING, logger="netsight_api"):
        assert cohort.min_cohort() == 5
    assert cohort.MIN_COHORT_ENV in caplog.text


def test_an_empty_minimum_is_the_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(cohort.MIN_COHORT_ENV, "  ")
    assert cohort.min_cohort() == 5


# --- the Explorer: isolating one endpoint -------------------------------------------------------------------------


def test_an_answer_about_one_source_is_withheld_from_the_aggregate_tier() -> None:
    isolating = exploration(aggregations=aggregations_with(1))
    source = FakeSource(explorer=lambda _: isolating)
    use(source)
    body = ok(FLOWS, application="BitTorrent")
    assert body["state"] == "ok" and body["flows_restricted"] is True
    assert body["cohort"] == {"state": "too-few-sources", "minimum": 5}
    assert body["aggregations"] is None and body["flows"] == []
    # Nothing the answer was made of survives: not the bytes, the timeline or the destinations.
    text = json.dumps(body)
    assert "1200000000" not in text and "cdn.example.net" not in text and "203.0.113.9" not in text
    assert source.calls[0]["include_rows"] is False


@pytest.mark.parametrize(("sources", "state"), [(4, "too-few-sources"), (5, "sufficient")])
def test_the_minimum_itself_is_enough(sources: int, state: str) -> None:
    use(FakeSource(explored=exploration(aggregations=aggregations_with(sources))))
    body = ok(FLOWS)
    assert body["cohort"]["state"] == state
    assert (body["aggregations"] is None) == (state == "too-few-sources")


def test_the_minimum_is_configurable(monkeypatch: pytest.MonkeyPatch) -> None:
    use(FakeSource(explored=exploration(aggregations=aggregations_with(4))))
    monkeypatch.setenv(cohort.MIN_COHORT_ENV, "4")
    body = ok(FLOWS)
    assert body["cohort"] == {"state": "sufficient", "minimum": 4}
    assert body["aggregations"] is not None


def test_enough_sources_leave_the_aggregates_whole() -> None:
    aggregations = aggregations_with(14)
    use(FakeSource(explored=exploration(aggregations=aggregations)))
    body = ok(FLOWS)
    assert body["cohort"] == {"state": "sufficient", "minimum": 5}
    assert body["aggregations"]["volume"]["source_addresses"] == 14
    assert len(body["aggregations"]["timeline"]) == len(aggregations.timeline)


@pytest.mark.parametrize("role", DETAIL_ROLES)
def test_the_detail_tier_is_not_held_to_the_rule(role: str) -> None:
    use(FakeSource(explored=exploration(aggregations=aggregations_with(1))))
    body = ok(FLOWS, role, source_ip="10.0.0.10")
    assert body["cohort"] == {"state": "not-applied", "minimum": None}
    assert body["aggregations"]["volume"]["source_addresses"] == 1
    assert len(body["flows"]) == 1


def test_overlapping_filters_cannot_be_subtracted_to_isolate_a_source() -> None:
    """Differencing: broad minus narrow would be one source's bytes, if the narrow answer were shown."""
    broad = exploration(aggregations=aggregations_with(8))
    narrow_volume = volume_of(1, bytes=111_111_111)
    narrow = exploration(aggregations=make_aggregations(volume=narrow_volume))

    def by_filter(filters: FlowFilterSet) -> Any:
        return narrow if filters.protocol == "tcp" else broad

    use(FakeSource(explorer=by_filter))
    wide = ok(FLOWS, application="Zoom")
    tight = ok(FLOWS, application="Zoom", protocol="tcp")
    assert wide["cohort"]["state"] == "sufficient"
    assert tight["cohort"]["state"] == "too-few-sources" and tight["aggregations"] is None
    assert "111111111" not in json.dumps(tight)
    # The only figure that could be subtracted is the broad one, which has no narrow counterpart.
    assert wide["aggregations"]["volume"]["bytes"] != 111_111_111


def test_a_failing_or_unconnected_source_applies_no_cohort_rule() -> None:
    use(None)
    assert ok(FLOWS)["cohort"] == {"state": "not-applied", "minimum": None}
    use(FakeSource(error=RuntimeError("boom")))
    body = ok(FLOWS)
    assert body["state"] == "unknown"
    assert body["cohort"] == {"state": "not-applied", "minimum": None}


def test_the_cohort_rule_is_recorded_in_the_audit_trail(
    caplog: pytest.LogCaptureFixture,
) -> None:
    use(FakeSource(explored=exploration(aggregations=aggregations_with(1))))
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        ok(FLOWS, application="BitTorrent")
    (record,) = [r for r in audit_records(caplog) if r["action"] == "traffic.flows.read"]
    assert record["cohort"] == "too-few-sources" and record["tier"] == "aggregate"
    assert "BitTorrent" not in json.dumps(record)


# --- device and VLAN are endpoint-level filters ------------------------------------------------------------------------


@pytest.mark.parametrize(("name", "value"), [("device", "edge-rtr-1"), ("vlan", "20")])
def test_management_may_not_narrow_to_a_device_or_vlan(name: str, value: str) -> None:
    source = FakeSource()
    use(source)
    response = Caller("management").get(FLOWS, **WINDOW, **{name: value})
    assert response.status_code == 403
    # The refusal echoes nothing (compare the message: a random correlation id may contain "20").
    assert source.calls == [] and value not in response.json()["error"]["message"]


@pytest.mark.parametrize(("name", "value"), [("device", "edge-rtr-1"), ("vlan", "20")])
@pytest.mark.parametrize("role", DETAIL_ROLES)
def test_the_detail_tier_may_narrow_to_a_device_or_vlan(role: str, name: str, value: str) -> None:
    use(FakeSource())
    assert ok(FLOWS, role, **{name: value})["state"] == "ok"


def test_the_refusal_to_filter_by_device_is_audited(caplog: pytest.LogCaptureFixture) -> None:
    use(FakeSource())
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        Caller("management").get(FLOWS, **WINDOW, device="edge-rtr-1")
    reasons = [
        r.get("reason") for r in audit_records(caplog) if r["action"] == "traffic.flows.read"
    ]
    assert reasons == ["filter-needs-detail"]


# --- internal destinations ---------------------------------------------------------------------------------------


def internal_share(**overrides: Any) -> dict[str, Any]:
    return {
        "address": "192.168.1.20",
        "host": "nas.corp.example",
        "scope": "internal",
        "visibility": "shown",
        "bytes": 50_000_000,
        "share": 0.04,
        "endpoints": 11,
        **overrides,
    }


def aggregations_with_internal(sources: int = 14) -> Any:
    destinations = make_aggregations().model_dump(mode="json")["destinations"]
    return make_aggregations(
        volume=volume_of(sources), destinations=[*destinations, internal_share()]
    )


def test_the_aggregate_tier_is_not_told_about_internal_destinations() -> None:
    use(FakeSource(explored=exploration(aggregations=aggregations_with_internal())))
    body = ok(FLOWS)
    addresses = [d["address"] for d in body["aggregations"]["destinations"]]
    assert "192.168.1.20" not in addresses and addresses
    assert {d["scope"] for d in body["aggregations"]["destinations"]} == {"external"}
    assert "nas.corp.example" not in json.dumps(body)


@pytest.mark.parametrize("role", DETAIL_ROLES)
def test_the_detail_tier_keeps_internal_destinations_labelled(role: str) -> None:
    use(FakeSource(explored=exploration(aggregations=aggregations_with_internal())))
    body = ok(FLOWS, role)
    scopes = {d["address"]: d["scope"] for d in body["aggregations"]["destinations"]}
    assert scopes["192.168.1.20"] == "internal" and scopes["203.0.113.9"] == "external"


def destination_rows() -> list[Any]:
    return [
        make_destination(rank=1, address="203.0.113.9", bytes=300_000_000, endpoints=40),
        make_destination(
            rank=2, address="10.1.1.5", bytes=200_000_000, endpoints=9, scope="internal"
        ),
        make_destination(rank=3, address="198.51.100.7", bytes=60_000_000, endpoints=2),
    ]


def test_destinations_exclude_internal_rows_for_the_aggregate_tier_and_rerank() -> None:
    use(FakeSource(destinations=destinations_read(destination_rows())))
    body = ok(DESTS)
    assert [(i["rank"], i["address"]) for i in body["items"]] == [
        (1, "203.0.113.9"),
        (2, "198.51.100.7"),
    ]
    # The total is the source's (all three rows); nothing is recomputed from what is shown.
    assert body["total_bytes"] == 560_000_000


@pytest.mark.parametrize("role", DETAIL_ROLES)
def test_destinations_keep_internal_rows_labelled_for_the_detail_tier(role: str) -> None:
    use(FakeSource(destinations=destinations_read(destination_rows())))
    body = ok(DESTS, role)
    assert [(i["rank"], i["address"], i["scope"]) for i in body["items"]] == [
        (1, "203.0.113.9", "external"),
        (2, "10.1.1.5", "internal"),
        (3, "198.51.100.7", "external"),
    ]
    assert body["cohort"] == {"state": "not-applied", "minimum": None}
    assert [i["endpoints"] for i in body["items"]] == [40, 9, 2]


# --- endpoint counts ------------------------------------------------------------------------------------------------------


def test_a_destination_below_the_minimum_is_withheld_whole() -> None:
    use(FakeSource(destinations=destinations_read(destination_rows())))
    body = ok(DESTS)
    shown, withheld = body["items"]
    assert shown["visibility"] == "shown" and shown["endpoints"] == 40
    assert withheld["visibility"] == "withheld" and withheld["address"] == "198.51.100.7"
    for field in (
        "bytes",
        "packets",
        "share",
        "endpoints",
        "users",
        "domain",
        "asn",
        "country",
        "first_seen",
        "last_seen",
    ):
        assert withheld[field] is None, field
    assert body["cohort"] == {"state": "too-few-sources", "minimum": 5}
    assert '"bytes": 60000000' not in json.dumps(body)


def test_destination_counts_at_the_minimum_are_listed() -> None:
    rows = [
        make_destination(rank=1, endpoints=5),
        make_destination(rank=2, address="198.51.100.9", endpoints=6),
    ]
    use(FakeSource(destinations=destinations_read(rows)))
    body = ok(DESTS)
    assert [i["endpoints"] for i in body["items"]] == [5, 6]
    assert body["cohort"] == {"state": "sufficient", "minimum": 5}


NO_TREND = {"state": "unknown", "previous_bytes": None, "change_ratio": None}


def application_rows() -> list[Any]:
    return [
        make_application(
            rank=1, application="Microsoft 365", bytes=200_000_000, endpoints=25, trend=NO_TREND
        ),
        make_application(
            rank=2, application="BitTorrent", bytes=40_000_000, endpoints=1, trend=NO_TREND
        ),
    ]


def test_an_application_below_the_minimum_is_withheld_whole() -> None:
    use(FakeSource(applications=applications_read(application_rows())))
    body = ok(APPS)
    shown, withheld = body["items"]
    assert (shown["application"], shown["visibility"], shown["endpoints"]) == (
        "Microsoft 365",
        "shown",
        25,
    )
    assert (withheld["application"], withheld["visibility"]) == ("BitTorrent", "withheld")
    for field in ("bytes", "packets", "share", "endpoints", "users"):
        assert withheld[field] is None, field
    assert withheld["trend"] == NO_TREND
    assert body["cohort"]["state"] == "too-few-sources"
    assert '"bytes": 40000000' not in json.dumps(body)


def test_application_counts_for_the_detail_tier_are_never_withheld() -> None:
    use(FakeSource(applications=applications_read(application_rows())))
    for role in DETAIL_ROLES:
        body = ok(APPS, role)
        assert [i["endpoints"] for i in body["items"]] == [25, 1]
        assert body["cohort"] == {"state": "not-applied", "minimum": None}


def test_applications_with_every_count_sufficient_say_so() -> None:
    use(FakeSource(applications=applications_read([make_application(endpoints=25)])))
    assert ok(APPS)["cohort"] == {"state": "sufficient", "minimum": 5}


def test_a_lower_configured_minimum_lists_more(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(cohort.MIN_COHORT_ENV, "2")
    use(FakeSource(applications=applications_read(application_rows())))
    body = ok(APPS)
    assert [i["endpoints"] for i in body["items"]] == [25, None]  # 1 is still below 2
    assert [i["visibility"] for i in body["items"]] == ["shown", "withheld"]


# --- first-seen destinations -----------------------------------------------------------------------------------------------


def anomaly_inputs(*rows: Any) -> Any:
    base = spike_inputs(NOW.replace(hour=11), spike=9 * 1024**3)
    return inputs(
        hourly_total=base.hourly_total,
        first_seen=tuple(rows),
    )


HOUR = {"from": "2026-10-11T11:00:00Z", "to": "2026-10-11T12:00:00Z"}


def seen(role: str) -> dict[str, Any]:
    response = Caller(role).get(ANOMS, **HOUR)
    assert response.status_code == 200, response.text
    body = response.json()
    validate("traffic_anomalies", body)
    return body  # type: ignore[no-any-return]


def test_first_seen_destinations_few_sources_reached_are_withheld_from_the_aggregate_tier() -> None:
    use(
        FakeSource(
            inputs=anomaly_inputs(
                first_seen(address="198.51.100.7", endpoints=12, bytes=300),
                first_seen(address="198.51.100.8", endpoints=2, bytes=200),
                first_seen(address="198.51.100.9", endpoints=None, bytes=100),
            )
        )
    )
    body = seen("management")
    assert [f["address"] for f in body["first_seen"]] == ["198.51.100.7"]
    assert body["cohort"] == {"state": "too-few-sources", "minimum": 5}
    assert "198.51.100.8" not in json.dumps(body) and "198.51.100.9" not in json.dumps(body)


def test_first_seen_asns_are_held_to_the_same_rule() -> None:
    use(
        FakeSource(
            inputs=anomaly_inputs(
                first_seen(kind="first-seen-asn", asn=64500, address=None, endpoints=1),
                first_seen(kind="first-seen-asn", asn=64501, address=None, endpoints=30, bytes=5),
            )
        )
    )
    body = seen("management")
    assert [f["asn"] for f in body["first_seen"]] == [64501]


@pytest.mark.parametrize("role", DETAIL_ROLES)
def test_the_detail_tier_sees_every_first_seen_row(role: str) -> None:
    use(
        FakeSource(
            inputs=anomaly_inputs(
                first_seen(address="198.51.100.7", endpoints=12, bytes=300),
                first_seen(address="198.51.100.8", endpoints=2, bytes=200),
            )
        )
    )
    body = seen(role)
    assert len(body["first_seen"]) == 2
    assert body["cohort"] == {"state": "not-applied", "minimum": None}


def test_first_seen_rows_that_all_meet_the_minimum_say_sufficient() -> None:
    use(FakeSource(inputs=anomaly_inputs(first_seen(endpoints=12))))
    body = seen("management")
    assert body["cohort"] == {"state": "sufficient", "minimum": 5}
    assert len(body["first_seen"]) == 1


def test_the_cached_baseline_is_filtered_per_request_not_per_cache_entry() -> None:
    """Detail then aggregate (and back) share one cached read; each caller gets its own view."""
    shared = TtlCache()
    app.dependency_overrides[traffic_routes.get_anomaly_cache] = lambda: shared
    source = FakeSource(inputs=anomaly_inputs(first_seen(endpoints=2)))
    use(source)
    assert len(seen("administrator")["first_seen"]) == 1
    assert seen("management")["first_seen"] == []
    assert len(seen("administrator")["first_seen"]) == 1
    assert source.methods().count("anomaly_inputs") == 1


def test_the_response_model_round_trips() -> None:
    use(FakeSource(explored=exploration(aggregations=aggregations_with(1))))
    response = Caller("management").get(FLOWS, **WINDOW)
    parsed = TrafficFlowsResponse.model_validate_json(response.text)
    assert parsed.cohort.state == "too-few-sources" and parsed.aggregations is None
