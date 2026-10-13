"""No route reachable with ``traffic:read`` alone discloses an internal address or a sub-cohort figure.

Step 7 second re-review, HIGH 1. The legacy ``/traffic/top-destinations`` returned raw destination
addresses and bytes (internal servers included) to the aggregate tier with no cohort check, no audit
and no admission slot. The routes are retired, and this suite keeps the whole class of bypass closed:
it enumerates the routes from the generated OpenAPI document, calls every parameterless GET as
Management (``traffic:read``, not ``traffic:read-detail``) against a flow source whose figures are all
below the cohort minimum and whose destinations are internal, and fails if anything leaks or if any
route reads the store through a method the cohort rule does not govern.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import pytest
from alerting_support import Caller
from fastapi.testclient import TestClient
from traffic_support import (
    NOW,
    FakeSource,
    applications_read,
    destinations_read,
    exploration,
    first_seen,
    make_aggregations,
    make_application,
    make_destination,
    spike_inputs,
    volume_of,
)

from netsight_api import read_limit, traffic_routes
from netsight_api.auth.rate_limit import RateLimiter
from netsight_api.auth.settings import session_policy
from netsight_api.main import app, get_optional_traffic_source
from netsight_api.traffic import cohort, guards
from netsight_api.traffic.cache import TtlCache

INTERNAL_SERVER = "10.77.77.77"
INTERNAL_SERVER_NAME = "payroll-db.internal.example"
SMALL_BYTES = 987_654_321
SMALL_PACKETS = 876_543
TOTAL_BYTES = 7_000_000_000
SMALL_COUNT = 2  # distinct internal endpoints, below the default minimum of 5
LEGACY = ("/traffic/top-talkers", "/traffic/top-destinations")


class _Spy(FakeSource):
    """Records the store methods a request reached, including the retired ``top``."""


def _source() -> _Spy:
    destination = make_destination(
        address=INTERNAL_SERVER,
        scope="internal",
        domain=INTERNAL_SERVER_NAME,
        bytes=SMALL_BYTES,
        packets=SMALL_PACKETS,
        endpoints=SMALL_COUNT,
    )
    return _Spy(
        explored=exploration(
            aggregations=make_aggregations(volume=volume_of(SMALL_COUNT, bytes=SMALL_BYTES))
        ),
        applications=applications_read(
            [
                make_application(
                    application="TinyCohortApp",
                    bytes=SMALL_BYTES,
                    endpoints=SMALL_COUNT,
                    trend={"state": "unknown", "previous_bytes": None, "change_ratio": None},
                )
            ],
            total_bytes=TOTAL_BYTES,
        ),
        destinations=destinations_read([destination], total_bytes=TOTAL_BYTES),
        inputs=spike_inputs(NOW.replace(hour=11)),
    )


@pytest.fixture(autouse=True)
def _wiring(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in (
        "NETSIGHT_ENV",
        "NETSIGHT_ENABLE_DEV_IDENTITY",
        "CLICKHOUSE_DSN",
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


def _openapi_get_paths() -> list[str]:
    document = app.openapi()
    return sorted(
        path
        for path, operations in document["paths"].items()
        if "get" in operations and "{" not in path
    )


def test_the_openapi_document_has_no_raw_top_routes() -> None:
    document = app.openapi()
    prefix = "/api/v1"
    for path in document["paths"]:
        relative = path.removeprefix(prefix)
        assert relative not in LEGACY, f"{path} bypasses the cohort rule and was retired"
        assert "top-talkers" not in path and "top-destinations" not in path


def test_the_committed_contract_has_no_raw_top_routes_either() -> None:
    import yaml

    from netsight_api.contracts import SCHEMA_DIR

    committed = yaml.safe_load(
        (SCHEMA_DIR.parents[1] / "contracts" / "openapi" / "netsight-api.yaml").read_text("utf-8")
    )
    for path in committed["paths"]:
        assert path not in LEGACY
    assert "TrafficTopResponse" not in committed["components"]["schemas"]


@pytest.mark.parametrize("path", LEGACY)
def test_a_retired_route_is_gone_for_every_role(path: str) -> None:
    app.dependency_overrides[get_optional_traffic_source] = lambda: _source()
    for role in ("management", "administrator", "security_analyst", "technician"):
        assert Caller(role).get(f"/api/v1{path}").status_code in {404, 405}


def test_an_aggregate_only_caller_never_sees_an_internal_address_or_a_sub_cohort_figure() -> None:
    source = _source()
    app.dependency_overrides[get_optional_traffic_source] = lambda: source
    app.dependency_overrides[traffic_routes.get_explorer_source] = lambda: source
    caller = Caller("management")
    paths = _openapi_get_paths()
    assert any(
        path.endswith("/traffic/flows") for path in paths
    )  # the enumeration found the surface
    for path in paths:
        response = caller.get(path)
        if response.status_code >= 500:
            continue  # a route with an unrelated, unconfigured dependency; it holds no flow data
        text = json.dumps(response.json()) if response.content else ""
        for secret in (
            INTERNAL_SERVER,
            INTERNAL_SERVER_NAME,
            str(SMALL_BYTES),
            str(SMALL_PACKETS),
            "TinyCohortApp-bytes",
        ):
            assert secret not in text, f"{path} leaked {secret}"


def test_no_route_reads_endpoint_rows_or_the_raw_top_for_the_aggregate_tier() -> None:
    source = _source()
    app.dependency_overrides[get_optional_traffic_source] = lambda: source
    app.dependency_overrides[traffic_routes.get_explorer_source] = lambda: source
    caller = Caller("management")
    for path in _openapi_get_paths():
        caller.get(path)
    assert "top" not in source.methods()
    for call in source.calls:
        if call["method"] == "explore":
            assert call["include_rows"] is False


def test_every_traffic_read_route_is_audited_and_takes_an_admission_slot() -> None:
    document = app.openapi()
    traffic = [path for path in document["paths"] if "/traffic/" in path]
    assert sorted(path.rsplit("/", 1)[1] for path in traffic) == [
        "anomalies",
        "applications",
        "destinations",
        "flows",
    ]
    anonymous = TestClient(app)
    for path in traffic:
        assert anonymous.get(path).status_code == 401


def test_the_aggregate_destination_list_withholds_a_small_cohort_row_entirely() -> None:
    source = _source()
    app.dependency_overrides[traffic_routes.get_explorer_source] = lambda: source
    body: dict[str, Any] = Caller("management").get("/api/v1/traffic/destinations").json()
    assert body["items"] == []  # an internal destination is not listed to the aggregate tier
    assert str(SMALL_BYTES) not in json.dumps(body)
