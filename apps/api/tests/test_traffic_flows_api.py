"""The Flow Explorer over HTTP: RBAC, privacy, bounds, explicit states, attribution and audit.

Hermetic: the flow source and the identity evidence are fakes; the real session, RBAC, rate limit and
audit stack is exercised through ``Caller``.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from datetime import timedelta
from typing import Any

import pytest
from alerting_support import Caller, audit_records
from fastapi.testclient import TestClient
from identity_support import (
    ALICE,
    ALICE_ACC,
    IP1,
    MAC_A,
    PC1,
    agent,
    assignment,
    dhcp,
    directory,
    radius,
)
from traffic_support import (
    HOSTILE,
    NOW,
    WINDOW,
    FakeSource,
    exploration,
    make_aggregations,
    make_flow,
)

from netsight_api import read_limit, traffic_routes
from netsight_api.auth.rate_limit import RateLimiter
from netsight_api.auth.settings import session_policy
from netsight_api.contracts import validate
from netsight_api.identity.model import CorrelationPolicy, EvidenceRecord
from netsight_api.identity.service import IdentityService, SnapshotCache
from netsight_api.identity.sources import MemoryEvidenceSource, SourceSlot
from netsight_api.main import app
from netsight_api.rbac import ROLE_PERMISSIONS, Permission, Role
from netsight_api.schemas_traffic import TrafficFlowsResponse
from netsight_api.traffic import guards

PATH = "/api/v1/traffic/flows"
FULL = ["administrator", "network_engineer", "security_analyst"]
ALL_ROLES = [*FULL, "technician", "management", "auditor"]


def ago(hours: float):
    return NOW - timedelta(hours=hours)


def stamp(record: EvidenceRecord) -> EvidenceRecord:
    return EvidenceRecord(
        source="fixture",
        native_id=record.native_id,
        kind=record.kind,
        observed_at=record.observed_at,
        valid_from=record.valid_from,
        valid_to=record.valid_to,
        confidence=record.confidence,
        assertions=record.assertions,
        guest=record.guest,
    )


def identity_service() -> IdentityService:
    records = [
        directory(ALICE, ALICE_ACC),
        radius(ALICE_ACC, MAC_A, ago(2), None, observed_at=ago(0.1)),
        dhcp(IP1, MAC_A, ago(2), ago(-4)),
        assignment(ALICE, PC1),
        agent(PC1, IP1, ago(3), ago(-3), mac=MAC_A),
    ]
    source = MemoryEvidenceSource("fixture", [stamp(r) for r in records])
    return IdentityService(
        [SourceSlot("fixture", source)], CorrelationPolicy(), cache=SnapshotCache()
    )


def use(source: FakeSource | None, service: IdentityService | None = None) -> None:
    app.dependency_overrides[traffic_routes.get_explorer_source] = lambda: source
    app.dependency_overrides[traffic_routes.get_identity_service] = lambda: service


@pytest.fixture(autouse=True)
def _wiring(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in ("NETSIGHT_ENV", "NETSIGHT_ENABLE_DEV_IDENTITY", "DATABASE_URL", "CLICKHOUSE_DSN"):
        monkeypatch.delenv(name, raising=False)
    app.dependency_overrides.clear()
    session_policy.cache_clear()
    monkeypatch.setattr(read_limit, "_read_limiter", RateLimiter())
    guards.reset_for_tests()
    app.dependency_overrides[traffic_routes.get_now] = lambda: NOW
    use(FakeSource(), identity_service())
    yield
    app.dependency_overrides.clear()
    session_policy.cache_clear()


def fetch(role: str, **params: Any) -> Any:
    return Caller(role).get(PATH, **{**WINDOW, **params})


def body_of(role: str, **params: Any) -> dict[str, Any]:
    response = fetch(role, **params)
    assert response.status_code == 200, response.text
    body = response.json()
    validate("traffic_flows", body)
    TrafficFlowsResponse.model_validate_json(response.text)
    return body  # type: ignore[no-any-return]


# --- authentication and authorisation ------------------------------------------------------------


def test_anonymous_callers_are_refused() -> None:
    assert TestClient(app).get(PATH).status_code == 401


def test_a_caller_without_a_known_role_is_refused() -> None:
    assert Caller("not-a-role").get(PATH, **WINDOW).status_code == 403


def test_technician_holds_no_traffic_permission() -> None:
    source = FakeSource()
    use(source, identity_service())
    assert fetch("technician").status_code == 403
    assert source.calls == []


@pytest.mark.parametrize("role", ALL_ROLES)
def test_the_role_matrix(role: str) -> None:
    expected = 403 if role == "technician" else 200
    assert fetch(role).status_code == expected


def test_authorisation_is_decided_before_the_rate_limit() -> None:
    caller = Caller("technician")
    codes = {caller.get(PATH, **WINDOW).status_code for _ in range(40)}
    assert codes == {403}


def test_the_surface_is_read_only() -> None:
    caller = Caller("administrator")
    for verb in ("post", "put", "delete", "patch"):
        assert getattr(caller.http, verb)(PATH).status_code in {404, 405}, verb


# --- privacy: the three views -----------------------------------------------------------------------


@pytest.mark.parametrize("role", FULL)
def test_full_roles_see_rows_and_the_person_with_the_basis(role: str) -> None:
    body = body_of(role)
    assert body["state"] == "ok" and body["flows_restricted"] is False
    assert body["attribution"]["level"] == "person" and body["attribution"]["state"] == "ok"
    (row,) = body["flows"]
    attribution = row["attribution"]
    assert attribution["basis"] in ("observed", "inferred")
    assert attribution["person"]["label"] == "Alice Example"
    assert attribution["confidence"] is not None
    assert attribution["device"]["id"] == PC1.id


def test_the_source_users_field_is_gone() -> None:
    body = body_of("administrator")
    assert "user" not in body["flows"][0]


def test_auditor_sees_endpoints_but_never_a_person() -> None:
    spy = identity_service()
    asked: list[Any] = []
    original = spy.resolve_many

    async def recording(now: Any, questions: Any) -> Any:
        asked.append(questions)
        return await original(now, questions)

    spy.resolve_many = recording  # type: ignore[method-assign]
    use(FakeSource(), spy)
    body = body_of("auditor")
    assert body["attribution"] == {"level": "none", "state": "withheld", "as_of": None}
    assert body["flows"][0]["attribution"] is None
    assert asked == []  # the identity service is not even consulted
    assert "Alice" not in json.dumps(body)


def test_management_gets_aggregates_only_and_no_rows_are_read() -> None:
    source = FakeSource()
    use(source, identity_service())
    body = body_of("management")
    assert body["flows_restricted"] is True and body["flows"] == []
    assert body["aggregations"] is not None and body["state"] == "ok"
    assert body["attribution"] == {"level": "none", "state": "withheld", "as_of": None}
    (call,) = source.calls
    assert call["include_rows"] is False  # the endpoint rows are never even read for this role


@pytest.mark.parametrize("name", ["source_ip", "destination_ip"])
def test_management_may_not_narrow_to_an_address(name: str) -> None:
    source = FakeSource()
    use(source, identity_service())
    response = fetch("management", **{name: "10.0.0.10"})
    assert response.status_code == 403
    assert source.calls == []
    assert "10.0.0.10" not in response.text


def test_management_may_use_the_other_filters() -> None:
    assert (
        fetch("management", protocol="tcp", port="443", country="ZA", asn="64500").status_code
        == 200
    )


def test_the_endpoint_level_names_the_device_but_withholds_the_person(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        ROLE_PERMISSIONS,
        Role.TECHNICIAN,
        frozenset(
            {Permission.TRAFFIC_READ, Permission.TRAFFIC_READ_DETAIL, Permission.USERS_READ_LIMITED}
        ),
    )
    body = body_of("technician")
    assert body["attribution"]["level"] == "endpoint" and body["attribution"]["state"] == "ok"
    attribution = body["flows"][0]["attribution"]
    assert attribution["person"] is None and attribution["reason"] == "restricted"
    assert attribution["device"]["id"] == PC1.id
    assert "Alice" not in json.dumps(body)


def test_a_service_principal_never_gets_a_person(monkeypatch: pytest.MonkeyPatch) -> None:
    from netsight_api.auth.deps import get_current_identity
    from netsight_api.rbac import Identity, PrincipalKind

    app.dependency_overrides[get_current_identity] = lambda: Identity(
        "svc-1", frozenset({"administrator"}), PrincipalKind.SERVICE
    )
    body = TestClient(app).get(PATH, params=WINDOW).json()
    validate("traffic_flows", body)
    assert body["attribution"]["level"] == "none" and body["flows"][0]["attribution"] is None


def test_responses_are_never_cached() -> None:
    assert fetch("administrator").headers["cache-control"] == "no-store"


# --- filters -------------------------------------------------------------------------------------------


def test_filters_reach_the_source_canonicalised_and_are_echoed() -> None:
    source = FakeSource()
    use(source, identity_service())
    body = body_of(
        "administrator",
        source_ip="::ffff:10.0.0.10",
        protocol="tcp",
        port="443",
        country="ZA",
        asn="64500",
        direction="outbound",
        application="Zoom",
        vlan="20",
        device="edge1",
        destination_ip="2001:DB8::1",
    )
    (call,) = source.calls
    filters = call["filters"]
    assert filters.source_ip == "10.0.0.10" and filters.destination_ip == "2001:db8::1"
    assert (filters.port, filters.asn, filters.vlan) == (443, 64500, 20)
    assert body["filters"] == {
        "source_ip": "10.0.0.10",
        "destination_ip": "2001:db8::1",
        "device": "edge1",
        "vlan": 20,
        "application": "Zoom",
        "protocol": "tcp",
        "port": 443,
        "country": "ZA",
        "asn": 64500,
        "direction": "outbound",
    }


def test_no_filters_means_all_null() -> None:
    assert set(body_of("administrator")["filters"].values()) == {None}


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("source_ip", "10.0.0.0/8"),
        ("source_ip", "nope"),
        ("destination_ip", "999.1.1.1"),
        ("vlan", "4095"),
        ("port", "65536"),
        ("asn", "0"),
        ("asn", "AS64500"),
        ("country", "za"),
        ("protocol", "gre"),
        ("direction", "sideways"),
        ("device", ""),
        ("application", "x" * 129),
        ("limit", "0"),
        ("limit", "501"),
        ("limit", "abc"),
        ("preset", "12h"),
    ],
)
def test_invalid_filters_and_bounds_are_a_422_that_echoes_nothing(name: str, value: str) -> None:
    source = FakeSource()
    use(source, identity_service())
    response = fetch("administrator", **{name: value})
    assert response.status_code == 422, response.text
    assert source.calls == []
    if len(value) > 3:
        # A random correlation id could contain a short value by chance; it is not an echo.
        body = response.text.replace(response.json()["error"]["correlation_id"], "")
        assert value not in body


def test_a_parameter_outside_the_allow_list_is_refused_not_ignored() -> None:
    for name in ("user", "sort", "q", "table", "where"):
        response = fetch("administrator", **{name: "alice"})
        assert response.status_code == 422, name
        assert "alice" not in response.text


def test_a_repeated_parameter_is_refused() -> None:
    response = Caller("administrator").http.get(
        PATH + "?port=80&port=443&from=" + WINDOW["from"] + "&to=" + WINDOW["to"]
    )
    assert response.status_code == 422


def test_the_window_is_server_bounded() -> None:
    assert (
        fetch(
            "administrator", **{"from": "2026-01-01T00:00:00Z", "to": "2026-10-11T00:00:00Z"}
        ).status_code
        == 422
    )
    assert (
        fetch(
            "administrator", **{"from": "2026-10-11T12:00:00Z", "to": "2026-10-11T00:00:00Z"}
        ).status_code
        == 422
    )
    assert Caller("administrator").get(PATH, **{"from": "2026-10-10T00:00:00Z"}).status_code == 422


def test_a_31_day_window_is_the_maximum() -> None:
    ok = fetch("administrator", **{"from": "2026-09-10T12:00:00Z", "to": "2026-10-11T12:00:00Z"})
    assert ok.status_code == 200
    assert (
        fetch(
            "administrator", **{"from": "2026-09-10T11:00:00Z", "to": "2026-10-11T12:00:00Z"}
        ).status_code
        == 422
    )


def test_the_limit_defaults_and_is_passed_to_the_source() -> None:
    source = FakeSource()
    use(source, identity_service())
    body_of("administrator")
    assert source.calls[0]["limit"] == 50
    body_of("administrator", limit="500")
    assert source.calls[1]["limit"] == 500


def test_the_explicit_window_is_echoed_without_a_preset() -> None:
    body = body_of("administrator")
    assert body["time_range"]["preset"] is None and body["time_range"]["from"].startswith(
        "2026-10-11T00:00:00"
    )
    preset = Caller("administrator").get(PATH, preset="6h").json()
    assert preset["time_range"]["preset"] == "6h"


# --- explicit states --------------------------------------------------------------------------------------


def test_no_source_is_not_connected_with_nothing_estimated() -> None:
    use(None, identity_service())
    body = body_of("administrator")
    assert body["state"] == "not-connected" and body["flows"] == [] and body["aggregations"] is None
    assert body["freshness"] == {"state": "unknown", "observed_at": None, "source": None}
    assert body["attribution"]["state"] == "not-evaluated"


def test_a_failing_source_is_unknown_and_leaks_nothing(caplog: pytest.LogCaptureFixture) -> None:
    use(FakeSource(error=RuntimeError("clickhouse exploded: password=hunter2")), identity_service())
    with caplog.at_level(logging.WARNING):
        body = body_of("administrator")
    assert body["state"] == "unknown" and body["flows"] == [] and body["aggregations"] is None
    assert body["freshness"]["source"] == "clickhouse"
    assert "hunter2" not in json.dumps(body)
    assert "hunter2" not in caplog.text


def test_a_filter_the_source_cannot_honour_is_unknown_with_the_names() -> None:
    use(FakeSource(explored=exploration(unsupported=("device", "vlan"))), identity_service())
    body = body_of("administrator", device="edge", vlan="20")
    assert body["state"] == "unknown" and body["unsupported"] == ["device", "vlan"]
    assert body["flows"] == [] and body["aggregations"] is None


def test_a_source_result_that_breaks_the_contract_degrades_to_unknown() -> None:
    too_many = [make_flow() for _ in range(501)]
    use(FakeSource(explored=exploration(too_many)), identity_service())
    body = body_of("administrator")
    assert body["state"] == "unknown" and body["flows"] == []


def test_an_empty_window_is_a_valid_empty_ok() -> None:
    use(FakeSource(explored=exploration([])), identity_service())
    body = body_of("administrator")
    assert body["state"] == "ok" and body["flows"] == []
    assert body["attribution"]["state"] == "not-evaluated"
    assert body["aggregations"] is not None


def test_freshness_is_the_sources_own() -> None:
    body = body_of("administrator")
    assert body["freshness"]["state"] == "fresh" and body["freshness"]["source"] == "clickhouse"
    use(FakeSource(explored=exploration(observed_at=NOW - timedelta(hours=5))), identity_service())
    assert body_of("administrator")["freshness"]["state"] == "stale"
    use(FakeSource(explored=exploration(observed_at=None)), identity_service())
    assert body_of("administrator")["freshness"]["state"] == "unknown"


def test_identity_not_connected_leaves_rows_unattributed_and_says_so() -> None:
    use(FakeSource(), None)
    body = body_of("administrator")
    assert body["state"] == "ok"
    assert body["attribution"] == {"level": "person", "state": "not-connected", "as_of": None}
    assert body["flows"][0]["attribution"] is None


def test_a_failing_identity_service_does_not_take_the_flows_down() -> None:
    class Boom(IdentityService):
        async def resolve_many(self, *_: Any, **__: Any) -> Any:
            raise RuntimeError("identity exploded: token=abc123")

    use(FakeSource(), Boom([], CorrelationPolicy()))
    body = body_of("administrator")
    assert body["state"] == "ok" and body["attribution"]["state"] == "unknown"
    assert body["flows"][0]["attribution"] is None and "abc123" not in json.dumps(body)


def test_hostile_source_text_is_carried_as_data() -> None:
    flow = make_flow(destination_host=HOSTILE, application=HOSTILE)
    aggregations = make_aggregations(
        destinations=[
            {
                "address": "203.0.113.9",
                "host": HOSTILE,
                "scope": "external",
                "visibility": "shown",
                "bytes": 5,
                "share": None,
                "endpoints": 12,
            }
        ]
    )
    use(FakeSource(explored=exploration([flow], aggregations=aggregations)), identity_service())
    body = body_of("administrator")
    assert body["flows"][0]["destination_host"] == HOSTILE
    assert body["aggregations"]["destinations"][0]["host"] == HOSTILE


# --- limits ----------------------------------------------------------------------------------------------------


def test_the_explorer_has_its_own_per_identity_budget() -> None:
    caller = Caller("administrator")
    codes = [
        caller.get(PATH, **WINDOW).status_code
        for _ in range(traffic_routes.EXPLORER_LIMIT_PER_MINUTE + 2)
    ]
    assert (
        codes[: traffic_routes.EXPLORER_LIMIT_PER_MINUTE]
        == [200] * traffic_routes.EXPLORER_LIMIT_PER_MINUTE
    )
    assert codes[-2:] == [429, 429]
    limited = caller.get(PATH, **WINDOW)
    assert limited.headers["retry-after"] == "60"
    assert limited.json()["error"]["code"] == "RATE_LIMITED"


def test_a_busy_source_is_refused_rather_than_queued(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(guards, "MAX_CONCURRENT_HEAVY", 0)
    response = fetch("administrator")
    assert response.status_code == 503
    assert (
        response.json()["error"]["code"] == "TRAFFIC_BUSY"
        and response.headers["retry-after"] == "5"
    )


# --- audit --------------------------------------------------------------------------------------------------------


def test_every_read_is_audited_without_values(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        body_of("administrator", source_ip="10.0.0.10", application="Zoom", port="443")
    (record,) = [r for r in audit_records(caplog) if r["action"] == "traffic.flows.read"]
    assert record["outcome"] == "success" and record["actor_id"]
    assert record["state"] == "ok" and record["row_count"] == 1
    assert (
        record["attribution_level"] == "person"
        and record["filters"] == "source_ip,application,port"
    )
    assert record["restricted"] is False and record["attributed_count"] == 1
    text = json.dumps(record)
    assert (
        "10.0.0.10" not in text and "Zoom" not in text and "Alice" not in text and "443" not in text
    )


def test_denials_and_rejected_input_are_audited(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        fetch("technician")
        fetch("management", source_ip="10.0.0.10")
        fetch("administrator", port="99999")
    reasons = [
        (r["outcome"], r.get("reason"))
        for r in audit_records(caplog)
        if r["action"] == "traffic.flows.read"
    ]
    assert ("denied", "permission") in reasons
    assert ("denied", "filter-needs-detail") in reasons
    assert ("failure", "invalid-filter") in reasons  # a static reason code, never the value


def test_a_rate_limit_refusal_is_audited(caplog: pytest.LogCaptureFixture) -> None:
    caller = Caller("administrator")
    for _ in range(traffic_routes.EXPLORER_LIMIT_PER_MINUTE):
        caller.get(PATH, **WINDOW)
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        assert caller.get(PATH, **WINDOW).status_code == 429
    assert ("denied", "rate-limited") in [
        (r["outcome"], r.get("reason"))
        for r in audit_records(caplog)
        if r["action"] == "traffic.flows.read"
    ]


def test_an_unknown_read_is_audited_as_a_failure(caplog: pytest.LogCaptureFixture) -> None:
    use(FakeSource(error=RuntimeError("x")), identity_service())
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        body_of("administrator")
    (record,) = [r for r in audit_records(caplog) if r["action"] == "traffic.flows.read"]
    assert record["outcome"] == "failure" and record["state"] == "unknown"


# --- the published contract ---------------------------------------------------------------------------------------


def test_the_route_is_in_the_published_openapi_document() -> None:
    operation = app.openapi()["paths"]["/api/v1/traffic/flows"]["get"]
    assert operation["operationId"] == "getTrafficFlows"
    names = {p["name"] for p in operation["parameters"]}
    assert {
        "source_ip",
        "destination_ip",
        "device",
        "vlan",
        "application",
        "protocol",
        "port",
        "country",
        "asn",
        "direction",
        "preset",
        "from",
        "to",
        "limit",
    } <= names
    assert {"200", "401", "403", "422", "429", "503"} <= set(operation["responses"])


def test_error_responses_are_never_cached_either() -> None:
    response = Caller("technician").get(PATH, **WINDOW)
    assert response.status_code == 403
    assert response.headers["cache-control"] == "no-store"
