"""Per-row cohort withholding, the internal-endpoint denominator, source-level freshness, anomaly series.

Step 7 second re-review, HIGH 2 to 5. The aggregate tier (``traffic:read`` without
``traffic:read-detail``) used to keep the volume of a row whose endpoint count it withheld, counted
every source address in any direction, was told the newest time of a filtered answer, and had no
cohort rule on the hourly series. Now:

* a row (application, destination, Explorer mix item and destination share) that fewer than ``k``
  internal endpoints stood behind keeps its name and loses its volume, packets, share, trend, counts,
  dates, domain, ASN and country, says ``withheld``, and is listed after the shown rows (ranks run
  1..n again, so a position says nothing);
* the denominator is the number of distinct *internal* endpoints, never of source addresses;
* a response the aggregate tier is shown reports the source's own freshness, not the newest time of
  the (possibly one-machine) filtered answer;
* an hourly series with fewer than ``k`` internal endpoints behind it is not evaluated or reported.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import pytest
from alerting_support import Caller
from traffic_support import (
    GIB,
    NOW,
    WEEK,
    WINDOW,
    FakeSource,
    applications_read,
    destinations_read,
    exploration,
    hour_of,
    inputs,
    make_aggregations,
    make_application,
    make_destination,
    volume_of,
)

from netsight_api import read_limit, traffic_routes
from netsight_api.auth.rate_limit import RateLimiter
from netsight_api.auth.settings import session_policy
from netsight_api.contracts import validate
from netsight_api.main import app
from netsight_api.traffic import cohort, guards
from netsight_api.traffic.cache import TtlCache
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
DETAIL = "security_analyst"
NO_TREND = {"state": "unknown", "previous_bytes": None, "change_ratio": None}
SOURCE_LEVEL = "2026-10-11T11:58:00Z"  # NOW - 2 minutes: what the source holds, whatever the filter
FILTERED = "2026-10-11T11:59:00Z"  # NOW - 1 minute: the newest flow of the filtered answer
HOUR = {"from": "2026-10-11T11:00:00Z", "to": "2026-10-11T12:00:00Z"}


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


# --- HIGH 2: applications --------------------------------------------------------------------------------------


def application_rows() -> list[Any]:
    """The smallest cohort is also the largest volume: a position would give it away."""
    return [
        make_application(
            rank=1,
            application="BitTorrent",
            bytes=900_000_000,
            packets=7,
            endpoints=1,
            trend={"state": "up", "previous_bytes": 100_000_000, "change_ratio": 8.0},
        ),
        make_application(
            rank=2, application="Microsoft 365", bytes=200_000_000, endpoints=25, trend=NO_TREND
        ),
        make_application(
            rank=3, application="Obscure", bytes=10_000_000, endpoints=None, trend=NO_TREND
        ),
    ]


def test_a_small_application_loses_every_figure_and_moves_behind_the_shown_rows() -> None:
    use(FakeSource(applications=applications_read(application_rows(), total_bytes=2_000_000_000)))
    body = ok(APPS)
    assert [(i["rank"], i["application"], i["visibility"]) for i in body["items"]] == [
        (1, "Microsoft 365", "shown"),
        (2, "BitTorrent", "withheld"),
        (3, "Obscure", "withheld"),
    ]
    for row in body["items"][1:]:
        for field in ("bytes", "packets", "share", "endpoints", "users"):
            assert row[field] is None, field
        assert row["trend"] == NO_TREND
    text = json.dumps(body)
    for secret in ("900000000", "100000000", "10000000", '"packets": 7'):
        assert secret not in text, secret
    assert body["total_bytes"] == 2_000_000_000  # the source's total, nothing recomputed
    assert body["cohort"] == {"state": "too-few-sources", "minimum": 5}


def test_withheld_applications_are_ordered_by_name_not_by_volume() -> None:
    rows = [
        make_application(rank=1, application="Zeta", bytes=900, endpoints=1, trend=NO_TREND),
        make_application(rank=2, application="alpha", bytes=800, endpoints=2, trend=NO_TREND),
        make_application(rank=3, application="Beta", bytes=700, endpoints=3, trend=NO_TREND),
    ]
    use(FakeSource(applications=applications_read(rows)))
    names = [i["application"] for i in ok(APPS)["items"]]
    assert names == ["alpha", "Beta", "Zeta"]


def test_the_detail_tier_keeps_the_order_and_every_figure() -> None:
    use(FakeSource(applications=applications_read(application_rows())))
    body = ok(APPS, DETAIL)
    assert [(i["rank"], i["application"], i["bytes"]) for i in body["items"]] == [
        (1, "BitTorrent", 900_000_000),
        (2, "Microsoft 365", 200_000_000),
        (3, "Obscure", 10_000_000),
    ]
    assert {i["visibility"] for i in body["items"]} == {"shown"}
    assert body["items"][0]["trend"]["previous_bytes"] == 100_000_000
    assert body["cohort"] == {"state": "not-applied", "minimum": None}


def test_every_application_meeting_the_minimum_is_sufficient_and_unchanged() -> None:
    rows = [make_application(rank=1, endpoints=5, trend=NO_TREND)]
    use(FakeSource(applications=applications_read(rows)))
    body = ok(APPS)
    assert body["cohort"] == {"state": "sufficient", "minimum": 5}
    assert body["items"][0]["visibility"] == "shown" and body["items"][0]["bytes"] is not None


# --- HIGH 2: destinations --------------------------------------------------------------------------------------


def destination_rows() -> list[Any]:
    return [
        make_destination(
            rank=1,
            address="198.51.100.7",
            bytes=700_000_000,
            packets=5,
            endpoints=2,
            domain="rare.example",
            asn=64666,
            country="RU",
        ),
        make_destination(rank=2, address="203.0.113.9", bytes=300_000_000, endpoints=40),
        make_destination(rank=3, address="203.0.113.10", bytes=90_000_000, endpoints=None),
    ]


def test_a_small_destination_keeps_its_address_and_nothing_that_describes_it() -> None:
    use(FakeSource(destinations=destinations_read(destination_rows(), total_bytes=3_000_000_000)))
    body = ok(DESTS)
    assert [(i["rank"], i["address"], i["visibility"]) for i in body["items"]] == [
        (1, "203.0.113.9", "shown"),
        (2, "198.51.100.7", "withheld"),
        (3, "203.0.113.10", "withheld"),
    ]
    for row in body["items"][1:]:
        for field in (
            "bytes", "packets", "share", "endpoints", "users", "domain", "asn", "country",
            "first_seen", "last_seen",
        ):  # fmt: skip
            assert row[field] is None, field
        assert row["reputation"] in {"allow-listed", "deny-listed", "unknown"}
    text = json.dumps(body)
    for secret in ("700000000", "90000000", "rare.example", "64666", '"RU"'):
        assert secret not in text, secret
    assert body["cohort"] == {"state": "too-few-sources", "minimum": 5}


def test_the_detail_tier_keeps_every_destination_figure() -> None:
    use(FakeSource(destinations=destinations_read(destination_rows())))
    body = ok(DESTS, DETAIL)
    first = body["items"][0]
    assert (first["address"], first["bytes"], first["domain"], first["asn"]) == (
        "198.51.100.7",
        700_000_000,
        "rare.example",
        64666,
    )
    assert body["cohort"] == {"state": "not-applied", "minimum": None}


# --- HIGH 2: the Explorer's application mix and destination shares -----------------------------------------------


def mix_aggregations() -> Any:
    template = make_aggregations().model_dump(mode="json")
    mix = template["application_mix"]
    mix["items"] = [
        {"application": "BitTorrent", "visibility": "shown", "bytes": 800_000_000, "share": 0.6,
         "endpoints": 2},
        {"application": "https", "visibility": "shown", "bytes": 300_000_000, "share": 0.25,
         "endpoints": 12},
    ]  # fmt: skip
    mix["other_bytes"] = 100_000_000
    mix["total_bytes"] = 1_200_000_000
    template["destinations"] = [
        {"address": "198.51.100.7", "host": "rare.example", "scope": "external",
         "visibility": "shown", "bytes": 700_000_000, "share": 0.5, "endpoints": 3},
        {"address": "203.0.113.9", "host": "cdn.example.net", "scope": "external",
         "visibility": "shown", "bytes": 300_000_000, "share": 0.25, "endpoints": 14},
    ]  # fmt: skip
    template["volume"] = volume_of(14)
    return make_aggregations(**{k: v for k, v in template.items()})


def test_a_small_mix_item_and_share_are_withheld_and_their_bytes_move_into_other() -> None:
    use(FakeSource(explored=exploration(aggregations=mix_aggregations())))
    body = ok(FLOWS)
    aggregations = body["aggregations"]
    mix = aggregations["application_mix"]
    assert [(i["application"], i["visibility"]) for i in mix["items"]] == [
        ("https", "shown"),
        ("BitTorrent", "withheld"),
    ]
    assert mix["items"][1]["bytes"] is None and mix["items"][1]["share"] is None
    assert mix["items"][1]["endpoints"] is None
    assert (
        mix["other_bytes"] == 100_000_000 + 800_000_000
    )  # withheld bytes are not lost, only merged
    assert mix["total_bytes"] == 1_200_000_000
    shares = aggregations["destinations"]
    assert [(s["address"], s["visibility"]) for s in shares] == [
        ("203.0.113.9", "shown"),
        ("198.51.100.7", "withheld"),
    ]
    assert shares[1]["bytes"] is None and shares[1]["host"] is None and shares[1]["share"] is None
    text = json.dumps(body)
    assert "800000000" not in text
    assert "rare.example" not in text
    assert body["cohort"] == {"state": "too-few-sources", "minimum": 5}
    assert body["aggregations"]["volume"]["internal_endpoints"] == 14


def test_the_detail_tier_keeps_the_mix_and_shares_whole() -> None:
    use(FakeSource(explored=exploration(aggregations=mix_aggregations())))
    body = ok(FLOWS, DETAIL, source_ip="10.0.0.10")
    mix = body["aggregations"]["application_mix"]["items"]
    assert [(i["application"], i["bytes"], i["visibility"]) for i in mix] == [
        ("BitTorrent", 800_000_000, "shown"),
        ("https", 300_000_000, "shown"),
    ]
    assert body["cohort"] == {"state": "not-applied", "minimum": None}


# --- HIGH 3: the denominator is internal endpoints -----------------------------------------------------------------


def test_one_internal_host_talking_to_many_remote_servers_does_not_pass_the_minimum() -> None:
    """Inbound traffic from 20 remote servers to one internal host: 20 source addresses, 1 endpoint."""
    one_host = make_aggregations(volume=volume_of(1, source_addresses=20, destination_addresses=1))
    use(FakeSource(explored=exploration(aggregations=one_host)))
    body = ok(FLOWS, direction="inbound")
    assert body["cohort"] == {"state": "too-few-sources", "minimum": 5}
    assert body["aggregations"] is None
    assert "1200000000" not in json.dumps(body)


def test_one_internal_host_with_many_remote_destinations_does_not_pass_either() -> None:
    one_host = make_aggregations(volume=volume_of(1, destination_addresses=60))
    use(FakeSource(explored=exploration(aggregations=one_host)))
    assert ok(FLOWS)["aggregations"] is None


def test_enough_internal_endpoints_pass_whatever_the_source_address_count() -> None:
    use(FakeSource(explored=exploration(aggregations=make_aggregations(
        volume=volume_of(5, source_addresses=2)))))  # fmt: skip
    body = ok(FLOWS)
    assert body["cohort"] == {"state": "sufficient", "minimum": 5}
    assert body["aggregations"] is not None


def test_an_unreported_internal_endpoint_count_is_withheld_not_assumed() -> None:
    unknown = make_aggregations(volume=volume_of(14, internal_endpoints=None))
    use(FakeSource(explored=exploration(aggregations=unknown)))
    body = ok(FLOWS)
    assert body["aggregations"] is None and body["cohort"]["state"] == "too-few-sources"


def test_the_detail_tier_is_not_held_to_the_internal_endpoint_count() -> None:
    one_host = make_aggregations(volume=volume_of(1, source_addresses=20))
    use(FakeSource(explored=exploration(aggregations=one_host)))
    body = ok(FLOWS, DETAIL, source_ip="10.0.0.10")
    assert body["aggregations"]["volume"]["internal_endpoints"] == 1


# --- HIGH 4: freshness is the source's, not the filtered answer's ------------------------------------------------------


def test_a_withheld_explorer_answer_reports_the_source_level_time_only() -> None:
    one_host = make_aggregations(volume=volume_of(1))
    use(FakeSource(explored=exploration(aggregations=one_host)))
    body = ok(FLOWS, application="BitTorrent")
    assert body["aggregations"] is None
    assert body["freshness"]["observed_at"] == SOURCE_LEVEL
    assert FILTERED not in json.dumps(body)


def test_a_shown_explorer_answer_to_the_aggregate_tier_reports_the_source_level_time() -> None:
    use(FakeSource(explored=exploration(aggregations=make_aggregations(volume=volume_of(14)))))
    assert ok(FLOWS)["freshness"]["observed_at"] == SOURCE_LEVEL


def test_the_detail_tier_keeps_the_time_of_the_filtered_answer() -> None:
    use(FakeSource(explored=exploration(aggregations=make_aggregations(volume=volume_of(1)))))
    assert ok(FLOWS, DETAIL, source_ip="10.0.0.10")["freshness"]["observed_at"] == FILTERED


@pytest.mark.parametrize("path", [APPS, DESTS])
def test_the_lists_report_the_source_level_time_to_the_aggregate_tier(path: str) -> None:
    use(FakeSource(applications=applications_read(application_rows()),
                   destinations=destinations_read(destination_rows())))  # fmt: skip
    assert ok(path)["freshness"]["observed_at"] == SOURCE_LEVEL
    assert ok(path, DETAIL)["freshness"]["observed_at"] == FILTERED


def test_without_a_source_level_time_the_aggregate_tier_is_told_unknown_never_the_filtered_time() -> (
    None
):
    use(FakeSource(applications=applications_read(application_rows(), source_observed_at=None)))
    freshness = ok(APPS)["freshness"]
    assert freshness["state"] == "unknown" and freshness["observed_at"] is None


# --- HIGH 5: the hourly series --------------------------------------------------------------------------------------------


def series(hour: int, spike: int = 8 * GIB) -> dict[int, int]:
    return {hour - k * WEEK: GIB for k in range(1, 5)} | {hour: spike}


def spiky_inputs(**overrides: Any) -> Any:
    hour = hour_of(NOW.replace(hour=11))
    values: dict[str, Any] = {
        "hourly_total": series(hour),
        "hourly_apps": {"Zoom": series(hour), "BitTorrent": series(hour)},
        "sources_total": 40,
        "sources_by_application": {"Zoom": 30, "BitTorrent": 1},
    }
    values.update(overrides)
    return inputs(**values)


def test_a_series_with_few_internal_endpoints_is_not_evaluated_for_the_aggregate_tier() -> None:
    use(FakeSource(inputs=spiky_inputs()))
    body = ok(ANOMS, **HOUR)
    labels = [a["subject"] for a in body["anomalies"]]
    assert {"kind": "application", "label": "Zoom"} in labels
    assert {"kind": "application", "label": "BitTorrent"} not in labels
    assert "BitTorrent" not in json.dumps(body)
    assert (
        body["evaluation"]["series"] == 2
    )  # the total and Zoom: only series that pass are counted
    assert body["evaluation"]["series_withheld"] == 1
    assert body["cohort"] == {"state": "too-few-sources", "minimum": 5}


def test_the_total_series_is_suppressed_when_the_whole_window_had_too_few_endpoints() -> None:
    use(FakeSource(inputs=spiky_inputs(sources_total=2, sources_by_application={"Zoom": 30})))
    body = ok(ANOMS, **HOUR)
    assert {"kind": "total", "label": None} not in [a["subject"] for a in body["anomalies"]]
    assert (
        body["evaluation"]["series_withheld"] == 2
    )  # the total and BitTorrent (no count: too few)


def test_an_unreported_endpoint_count_withholds_the_series() -> None:
    use(FakeSource(inputs=spiky_inputs(sources_total=None, sources_by_application={})))
    body = ok(ANOMS, **HOUR)
    assert body["anomalies"] == [] and body["evaluation"]["series_withheld"] == 3
    assert body["evaluation"]["series"] == 0


def test_the_detail_tier_is_given_every_series() -> None:
    use(FakeSource(inputs=spiky_inputs()))
    body = ok(ANOMS, DETAIL, **HOUR)
    assert body["evaluation"]["series"] == 3 and body["evaluation"]["series_withheld"] == 0
    assert body["cohort"]["state"] == "not-applied"
    assert {"kind": "application", "label": "BitTorrent"} in [
        a["subject"] for a in body["anomalies"]
    ]


def test_every_series_meeting_the_minimum_says_sufficient() -> None:
    use(FakeSource(inputs=spiky_inputs(sources_by_application={"Zoom": 30, "BitTorrent": 5})))
    body = ok(ANOMS, **HOUR)
    assert body["evaluation"]["series_withheld"] == 0
    assert body["cohort"] == {"state": "sufficient", "minimum": 5}


def test_a_lower_minimum_lets_a_smaller_series_through(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(cohort.MIN_COHORT_ENV, "1000")
    use(FakeSource(inputs=spiky_inputs()))
    assert ok(ANOMS, **HOUR)["evaluation"]["series_withheld"] == 3


def test_the_cached_baseline_serves_each_tier_its_own_view() -> None:
    shared = TtlCache()
    app.dependency_overrides[traffic_routes.get_anomaly_cache] = lambda: shared
    source = FakeSource(inputs=spiky_inputs())
    use(source)
    assert ok(ANOMS, DETAIL, **HOUR)["evaluation"]["series_withheld"] == 0
    assert ok(ANOMS, **HOUR)["evaluation"]["series_withheld"] == 1
    assert ok(ANOMS, DETAIL, **HOUR)["evaluation"]["series_withheld"] == 0
    assert source.methods().count("anomaly_inputs") == 1
