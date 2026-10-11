"""The IPAM routes over HTTP: RBAC, strict parameters, per-dataset states, audit and limits (Step 8b).

Hermetic: the service is built over fakes; the real session, RBAC and rate-limit stack runs through
``Caller``. Every successful body is checked against the canonical JSON Schema as well.
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
from inventory_support import (
    NOW,
    FakeLibrenms,
    FakeNetbox,
    FakeWazuh,
    address,
    agent,
    device,
    prefix,
    reserved,
    vlan,
)

from netsight_api import ipam_routes, read_limit
from netsight_api.auth.rate_limit import RateLimiter
from netsight_api.auth.settings import session_policy
from netsight_api.contracts import validate
from netsight_api.inventory.cache import TtlCache
from netsight_api.ipam.service import IpamService
from netsight_api.main import app

BASE = "/api/v1/ipam"
LISTS = {
    "prefixes": "ipam_prefix_list",
    "vlans": "ipam_vlan_list",
    "addresses": "ipam_address_list",
}
ALL_ROLES = [
    "administrator",
    "network_engineer",
    "security_analyst",
    "technician",
    "management",
    "auditor",
]
ROW_ROLES = ["administrator", "network_engineer", "security_analyst", "technician", "auditor"]


def netbox(**overrides: Any) -> FakeNetbox:
    parts: dict[str, Any] = {
        "prefixes": [
            prefix("1", "10.0.0.0/16", site="HQ"),
            prefix("2", "10.0.5.0/24", site="HQ", vlan_id="11", vlan_vid=20, vlan_name="staff"),
            prefix("3", "172.16.0.0/24", site="DC", status="reserved"),
        ],
        "vlans": [vlan("11", 20, "staff"), vlan("12", 30, "guest", site="DC")],
        "addresses": [
            address("1", "10.0.5.10", dns="pc-10.example"),
            address("2", "10.0.5.11"),
            address("3", "10.0.5.12", status="reserved"),
        ],
        "ranges": [reserved("9", "10.0.5.100", "10.0.5.120")],
    }
    parts.update(overrides)
    return FakeNetbox(**parts)


def service(nb: Any = "default", librenms: Any = "default", wazuh: Any = "default") -> IpamService:
    return IpamService(
        netbox=netbox() if nb == "default" else nb,
        librenms=(
            FakeLibrenms([device("librenms", "7", "pc", ip="10.0.5.10")])
            if librenms == "default"
            else librenms
        ),
        wazuh=FakeWazuh([agent("001", "x", "10.0.5.77")]) if wazuh == "default" else wazuh,
        stale_window=timedelta(hours=24),
        clock=lambda: NOW,
        cache=TtlCache(0.0),
    )


def use(svc: IpamService) -> None:
    app.dependency_overrides[ipam_routes.get_ipam_service] = lambda: svc


@pytest.fixture(autouse=True)
def _wiring(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in ("NETSIGHT_ENV", "NETSIGHT_ENABLE_DEV_IDENTITY", "DATABASE_URL"):
        monkeypatch.delenv(name, raising=False)
    app.dependency_overrides.clear()
    session_policy.cache_clear()
    monkeypatch.setattr(read_limit, "_read_limiter", RateLimiter())
    use(service())
    yield
    app.dependency_overrides.clear()
    session_policy.cache_clear()


# --- authentication and authorisation --------------------------------------------------------------


def test_unauthenticated_callers_get_401() -> None:
    client = TestClient(app, raise_server_exceptions=False)
    for path in (BASE, f"{BASE}/prefixes", f"{BASE}/vlans", f"{BASE}/addresses"):
        assert client.get(path).status_code == 401


@pytest.mark.parametrize("role", ROW_ROLES)
@pytest.mark.parametrize("section", LISTS)
def test_row_roles_read_every_list(role: str, section: str) -> None:
    response = Caller(role).get(f"{BASE}/{section}")
    assert response.status_code == 200
    validate(LISTS[section], response.json())


@pytest.mark.parametrize("section", LISTS)
def test_management_gets_the_overview_only(section: str) -> None:
    caller = Caller("management")
    assert caller.get(f"{BASE}/{section}").status_code == 403
    overview = caller.get(BASE)
    assert overview.status_code == 200
    validate("ipam_summary_response", overview.json())
    assert "items" not in overview.json()


@pytest.mark.parametrize("role", ALL_ROLES)
def test_every_role_reads_the_overview(role: str) -> None:
    assert Caller(role).get(BASE).status_code == 200


def test_an_unknown_role_and_authorisation_before_validation_and_limits() -> None:
    assert Caller("superuser").get(f"{BASE}/prefixes").status_code == 403
    caller = Caller("management")
    assert caller.get(f"{BASE}/prefixes", page_size=9999).status_code == 403
    for _ in range(80):
        assert caller.get(f"{BASE}/addresses").status_code == 403


# --- content --------------------------------------------------------------------------------------------


def test_the_overview_reports_sources_telemetry_and_counts_only() -> None:
    body = Caller("management").get(BASE).json()
    assert body["state"] == "ok"
    assert body["telemetry"] == {
        "state": "ok",
        "window_seconds": 86400,
        "sources": ["librenms", "wazuh"],
    }
    counts = body["counts"]
    assert (
        counts["prefixes"],
        counts["vlans"],
        counts["addresses"],
        counts["reserved_ranges"],
    ) == (3, 2, 3, 1)
    assert counts["discovered_only_addresses"] == 1
    assert set(body) == {"state", "generated_at", "sources", "telemetry", "counts"}


def test_prefixes_come_as_a_tree_with_utilisation_and_basis() -> None:
    body = Caller("network_engineer").get(f"{BASE}/prefixes").json()
    assert [p["prefix"] for p in body["items"]] == ["10.0.0.0/16", "10.0.5.0/24", "172.16.0.0/24"]
    child = body["items"][1]
    assert child["parent_id"] == body["items"][0]["id"] and child["depth"] == 1
    assert child["vlan"] == {"vid": 20, "name": "staff"}
    util = child["utilisation"]
    assert (util["basis"], util["netbox_addresses"], util["discovered_only"], util["used"]) == (
        "netbox-and-discovered",
        3,
        1,
        4,
    )
    assert child["reserved_ranges_total"] == 1 and util["reserved"] == 21


def test_prefix_filters_page_and_total() -> None:
    caller = Caller("network_engineer")
    assert [p["prefix"] for p in caller.get(f"{BASE}/prefixes", site="DC").json()["items"]] == [
        "172.16.0.0/24"
    ]
    assert [
        p["prefix"] for p in caller.get(f"{BASE}/prefixes", status="reserved").json()["items"]
    ] == ["172.16.0.0/24"]
    assert [p["prefix"] for p in caller.get(f"{BASE}/prefixes", q="STAFF").json()["items"]] == [
        "10.0.5.0/24"
    ]
    assert caller.get(f"{BASE}/prefixes", family="6").json()["items"] == []
    page = caller.get(f"{BASE}/prefixes", page=2, page_size=2).json()
    assert page["total"] == 3 and len(page["items"]) == 1


def test_vlans_are_ordered_by_number_with_their_prefix_counts() -> None:
    body = Caller("technician").get(f"{BASE}/vlans").json()
    assert [(v["vid"], v["name"], v["prefix_count"]) for v in body["items"]] == [
        (20, "staff", 1),
        (30, "guest", 0),
    ]
    assert [
        v["name"] for v in Caller("technician").get(f"{BASE}/vlans", site="DC").json()["items"]
    ] == ["guest"]
    assert [
        v["name"] for v in Caller("technician").get(f"{BASE}/vlans", q="30").json()["items"]
    ] == ["guest"]


def test_addresses_show_active_versus_stale_with_the_basis_and_counts() -> None:
    body = Caller("network_engineer").get(f"{BASE}/addresses").json()
    by_ip = {a["address"]: a for a in body["items"]}
    assert by_ip["10.0.5.10"]["activity"] == "active" and by_ip["10.0.5.10"]["seen_by"] == [
        "librenms"
    ]
    assert by_ip["10.0.5.11"]["activity"] == "stale"
    assert by_ip["10.0.5.12"]["activity"] == "reserved"
    assert by_ip["10.0.5.77"]["source"] == "discovered" and by_ip["10.0.5.77"]["seen_by"] == [
        "wazuh"
    ]
    assert body["activity_counts"] == {"active": 2, "stale": 1, "unknown": 0, "reserved": 1}
    assert body["telemetry"]["state"] == "ok"


def test_address_filters() -> None:
    caller = Caller("network_engineer")
    stale = caller.get(f"{BASE}/addresses", activity="stale").json()
    assert [a["address"] for a in stale["items"]] == ["10.0.5.11"] and stale["total"] == 1
    assert stale["activity_counts"]["active"] == 2  # counts cover everything, not the filter
    assert [
        a["address"] for a in caller.get(f"{BASE}/addresses", source="discovered").json()["items"]
    ] == ["10.0.5.77"]
    assert [a["address"] for a in caller.get(f"{BASE}/addresses", q="pc-10").json()["items"]] == [
        "10.0.5.10"
    ]
    child = caller.get(f"{BASE}/prefixes").json()["items"][1]["id"]
    assert len(caller.get(f"{BASE}/addresses", prefix=child).json()["items"]) == 4


def test_without_telemetry_addresses_are_unknown_never_stale() -> None:
    use(service(librenms=None, wazuh=None))
    body = Caller("network_engineer").get(f"{BASE}/addresses").json()
    validate("ipam_address_list", body)
    assert body["telemetry"]["state"] == "not-connected"
    assert {a["activity"] for a in body["items"]} == {"unknown", "reserved"}
    assert body["activity_counts"]["stale"] == 0


# --- explicit states ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("section", LISTS)
def test_netbox_not_configured_is_not_connected_with_no_rows(section: str) -> None:
    use(service(nb=None))
    body = Caller("network_engineer").get(f"{BASE}/{section}").json()
    validate(LISTS[section], body)
    assert body["state"] == "not-connected" and body["items"] == [] and body["total"] == 0


def test_a_failing_dataset_makes_only_its_own_list_unknown() -> None:
    use(service(nb=netbox(prefixes=RuntimeError("secret-host.internal"))))
    caller = Caller("network_engineer")
    prefixes = caller.get(f"{BASE}/prefixes")
    assert prefixes.json()["state"] == "unknown" and prefixes.json()["items"] == []
    assert "secret-host" not in prefixes.text
    vlans = caller.get(f"{BASE}/vlans").json()
    assert vlans["state"] == "ok" and all(v["prefix_count"] is None for v in vlans["items"])
    assert caller.get(f"{BASE}/addresses").json()["state"] == "ok"
    overview = caller.get(BASE).json()
    assert overview["state"] == "ok" and overview["counts"]["prefixes"] is None


def test_all_of_netbox_failing_is_unknown_everywhere() -> None:
    boom = RuntimeError("boom")
    use(service(nb=FakeNetbox(prefixes=boom, vlans=boom, addresses=boom, ranges=boom)))
    caller = Caller("network_engineer")
    for section in LISTS:
        assert caller.get(f"{BASE}/{section}").json()["state"] == "unknown"
    assert caller.get(BASE).json()["counts"] is None


def test_a_service_that_raises_is_unknown_not_a_500() -> None:
    class Broken:
        async def snapshot(self) -> Any:
            raise RuntimeError("boom with secret")

    app.dependency_overrides[ipam_routes.get_ipam_service] = lambda: Broken()
    response = Caller("network_engineer").get(f"{BASE}/prefixes")
    assert response.status_code == 200 and response.json()["state"] == "unknown"
    assert "secret" not in response.text


def test_hostile_text_is_returned_as_data() -> None:
    hostile = "<script>alert(1)</script> ' OR 1=1 --"
    use(
        service(
            nb=netbox(
                prefixes=[prefix("1", "10.0.0.0/24", description=hostile)],
                vlans=[vlan("1", 5, hostile)],
            )
        )
    )
    caller = Caller("network_engineer")
    assert caller.get(f"{BASE}/prefixes").json()["items"][0]["description"] == hostile
    assert caller.get(f"{BASE}/vlans").json()["items"][0]["name"] == hostile


def test_responses_are_not_cacheable() -> None:
    for path in (BASE, f"{BASE}/prefixes", f"{BASE}/vlans", f"{BASE}/addresses"):
        assert Caller("auditor").get(path).headers["cache-control"] == "no-store"


# --- strict parameters ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("section", "query"),
    [
        ("prefixes", {"family": "5"}),
        ("prefixes", {"page": 0}),
        ("prefixes", {"page_size": 101}),
        ("prefixes", {"q": ""}),
        ("prefixes", {"q": "x" * 65}),
        ("prefixes", {"unexpected": "1"}),
        ("prefixes", {"activity": "active"}),
        ("vlans", {"site": ""}),
        ("vlans", {"family": "4"}),
        ("addresses", {"activity": "idle"}),
        ("addresses", {"source": "snmp"}),
        ("addresses", {"prefix": "ipam-prefix-1"}),
        ("addresses", {"prefix": "10.0.0.0/24"}),
        ("addresses", {"known": "true"}),
    ],
)
def test_bad_or_unknown_parameters_are_a_422(section: str, query: dict[str, Any]) -> None:
    response = Caller("network_engineer").get(f"{BASE}/{section}", **query)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_repeated_parameters_and_query_on_the_overview_are_refused() -> None:
    caller = Caller("network_engineer")
    assert caller.http.get(f"{BASE}/addresses?activity=stale&activity=active").status_code == 422
    assert caller.get(BASE, page=1).status_code == 422


# --- limits and audit -----------------------------------------------------------------------------------------


def test_lists_are_rate_limited_per_identity_after_authorisation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ipam_routes, "LIST_LIMIT_PER_MINUTE", 2)
    caller = Caller("network_engineer")
    assert [caller.get(f"{BASE}/prefixes").status_code for _ in range(3)] == [200, 200, 429]
    assert Caller("auditor", subject="sub-2").get(f"{BASE}/prefixes").status_code == 200


def test_reads_are_audited_with_counts_and_filter_names_never_values(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    caller = Caller("network_engineer")
    caller.get(f"{BASE}/addresses", q="pc-10-private", activity="stale")
    caller.get(f"{BASE}/prefixes", site="HQ")
    caller.get(BASE)
    records = {r["action"]: r for r in audit_records(caplog)}
    address_record = records["ipam.addresses.read"]
    assert (
        address_record["outcome"] == "success" and address_record["actor_id"] == caller.identity_id
    )
    assert address_record["filters"] == "activity,q"
    assert "pc-10-private" not in json.dumps(address_record) and "stale" not in json.dumps(
        address_record
    )
    assert records["ipam.prefixes.read"]["filters"] == "site"
    assert records["ipam.summary.read"]["state"] == "ok"


def test_refusals_are_audited(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    Caller("management").get(f"{BASE}/vlans")
    Caller("network_engineer").get(f"{BASE}/vlans", page=0)
    records = audit_records(caplog)
    assert any(r["outcome"] == "denied" and r["reason"] == "permission" for r in records)
    assert any(r["outcome"] == "failure" and r["reason"] == "invalid-request" for r in records)
