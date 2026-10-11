"""The inventory routes over HTTP: RBAC, strict parameters, explicit states, audit and limits (Step 8a).

Hermetic: the service is built over fakes; the real session, RBAC and rate-limit stack runs through
``Caller``. Every successful body is checked against the canonical JSON Schema as well.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from typing import Any

import pytest
from alerting_support import Caller, audit_records
from inventory_support import (
    NOW,
    FakeLibrenms,
    FakeNetbox,
    FakeWazuh,
    agent,
    asset,
    device,
)

from netsight_api import inventory_routes, read_limit
from netsight_api.adapters.netbox import AdapterError, AdapterStatus
from netsight_api.auth.rate_limit import RateLimiter
from netsight_api.auth.settings import session_policy
from netsight_api.contracts import validate
from netsight_api.inventory.cache import TtlCache
from netsight_api.inventory.classmap import CLASS_MAP_ENV, load_class_map
from netsight_api.inventory.service import InventoryService
from netsight_api.main import app

BASE = "/api/v1/inventory"
ALL_ROLES = [
    "administrator",
    "network_engineer",
    "security_analyst",
    "technician",
    "management",
    "auditor",
]
ROW_ROLES = ["administrator", "network_engineer", "security_analyst", "technician", "auditor"]
HOSTILE = "<script>alert('x')</script> \"; DROP TABLE assets; -- " + chr(0x202E) + " {{7*7}}"
CLASS_MAP = load_class_map(
    {CLASS_MAP_ENV: json.dumps({"version": 1, "roles": {"core-switch": "network-device"}})}
)


def service(
    netbox: Any = "default", librenms: Any = "default", wazuh: Any = None
) -> InventoryService:
    if netbox == "default":
        netbox = FakeNetbox(
            [
                asset("1", "core-sw-1", ip="10.0.0.2"),
                asset("2", "ap-1", role="odd", device_type="odd"),
                asset("3", "dc-fw", site="DC"),
            ]
        )
    if librenms == "default":
        librenms = FakeLibrenms(
            [
                device("librenms", "7", "core-sw-1", ip="10.0.0.2", mac="aa:bb:cc:00:11:22"),
                device("librenms", "9", "printer-x", ip="10.0.5.9"),
            ]
        )
    return InventoryService(
        netbox=netbox,
        librenms=librenms,
        wazuh=wazuh,
        agent_field=None,
        class_map=CLASS_MAP,
        clock=lambda: NOW,
        cache=TtlCache(0.0),
    )


def use(svc: InventoryService) -> None:
    app.dependency_overrides[inventory_routes.get_inventory_service] = lambda: svc


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


def items_of(body: dict[str, Any]) -> list[str]:
    return [i["name"]["value"] for i in body["items"]]


# --- authentication and authorisation -----------------------------------------------------------------


def test_unauthenticated_callers_get_401_everywhere() -> None:
    from fastapi.testclient import TestClient

    client = TestClient(app, raise_server_exceptions=False)
    for path in (BASE, f"{BASE}/summary", f"{BASE}/device-6f1c2a9e-0b1d-5c3e-8f4a-123456789abc"):
        assert client.get(path).status_code == 401


@pytest.mark.parametrize("role", ROW_ROLES)
def test_row_roles_read_the_list(role: str) -> None:
    response = Caller(role).get(BASE)
    assert response.status_code == 200
    validate("inventory_list", response.json())


def test_management_gets_counts_but_no_rows_and_no_detail() -> None:
    caller = Caller("management")
    assert caller.get(BASE).status_code == 403
    assert caller.get(f"{BASE}/device-6f1c2a9e-0b1d-5c3e-8f4a-123456789abc").status_code == 403
    summary = caller.get(f"{BASE}/summary")
    assert summary.status_code == 200
    body = summary.json()
    validate("inventory_summary_response", body)
    assert body["summary"]["total"] == 4
    assert "items" not in body


@pytest.mark.parametrize("role", ALL_ROLES)
def test_every_role_reads_the_summary(role: str) -> None:
    response = Caller(role).get(f"{BASE}/summary")
    assert response.status_code == 200


def test_a_session_with_an_unknown_role_is_denied() -> None:
    assert Caller("superuser").get(BASE).status_code == 403
    assert Caller("superuser").get(f"{BASE}/summary").status_code == 403


def test_a_service_principal_with_a_read_role_may_read() -> None:
    from netsight_api.auth.deps import get_current_identity
    from netsight_api.rbac import Identity, PrincipalKind

    app.dependency_overrides[get_current_identity] = lambda: Identity(
        "svc", frozenset({"auditor"}), PrincipalKind.SERVICE
    )
    from fastapi.testclient import TestClient

    assert TestClient(app).get(BASE).status_code == 200


def test_authorisation_runs_before_validation_and_before_the_limiter() -> None:
    caller = Caller("management")
    assert caller.get(BASE, page_size=9999).status_code == 403
    for _ in range(80):
        assert caller.get(BASE).status_code == 403  # never a 429 that would reveal limiter state


# --- list content ----------------------------------------------------------------------------------------


def test_the_list_merges_sources_and_reports_every_source_state() -> None:
    body = Caller("network_engineer").get(BASE).json()
    assert body["state"] == "ok"
    assert {s["source"]: s["state"] for s in body["sources"]} == {
        "netbox": "ok",
        "librenms": "ok",
        "wazuh": "not-connected",
    }
    assert items_of(body) == ["ap-1", "core-sw-1", "dc-fw", "printer-x"]
    assert body["total"] == 4 and body["page"] == 1 and body["page_size"] == 25
    assert body["summary"]["unknown"] == 1


def test_responses_are_not_cacheable() -> None:
    response = Caller("auditor").get(BASE)
    assert response.headers["cache-control"] == "no-store"


def test_filters_page_and_total_are_applied_on_the_server() -> None:
    caller = Caller("network_engineer")
    body = caller.get(BASE, known="false").json()
    assert items_of(body) == ["printer-x"] and body["total"] == 1
    assert body["summary"]["total"] == 4  # counts are over the whole inventory, not the filter
    body = caller.get(BASE, asset_class="network-device").json()
    assert set(items_of(body)) == {"core-sw-1", "dc-fw"}
    body = caller.get(BASE, site="DC").json()
    assert items_of(body) == ["dc-fw"]
    body = caller.get(BASE, source="both").json()
    assert items_of(body) == ["core-sw-1"]
    body = caller.get(BASE, q="aa:bb").json()
    assert items_of(body) == ["core-sw-1"]
    body = caller.get(BASE, page=2, page_size=3).json()
    assert items_of(body) == ["printer-x"] and body["total"] == 4


def test_a_filter_that_matches_nothing_is_a_valid_empty_page() -> None:
    body = Caller("network_engineer").get(BASE, q="nothing-like-this").json()
    validate("inventory_list", body)
    assert body["items"] == [] and body["total"] == 0 and body["state"] == "ok"


def test_status_filters_the_observed_status() -> None:
    use(
        service(
            librenms=FakeLibrenms(
                [
                    device("librenms", "7", "core-sw-1", status="offline"),
                    device("librenms", "9", "x"),
                ]
            )
        )
    )
    body = Caller("network_engineer").get(BASE, status="offline").json()
    assert items_of(body) == ["core-sw-1"]


# --- strict parameters -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "query",
    [
        {"page": 0},
        {"page": 1_000_000},
        {"page_size": 0},
        {"page_size": 101},
        {"asset_class": "toaster"},
        {"status": "great"},
        {"source": "snmp"},
        {"known": "maybe"},
        {"q": ""},
        {"q": "x" * 65},
        {"site": ""},
        {"site": "x" * 256},
        {"unexpected": "1"},
        {"limit": "5"},
    ],
)
def test_bad_or_unknown_parameters_are_a_422_that_echoes_nothing(query: dict[str, Any]) -> None:
    response = Caller("network_engineer").get(BASE, **query)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"
    echoed = str(next(iter(query.values())))
    assert len(echoed) < 3 or echoed not in response.text


def test_a_repeated_parameter_is_refused() -> None:
    caller = Caller("network_engineer")
    assert caller.http.get(f"{BASE}?known=true&known=false").status_code == 422
    assert caller.http.get(f"{BASE}?q=a&q=b").status_code == 422


# --- explicit states -----------------------------------------------------------------------------------------


def test_netbox_not_configured_is_not_connected_with_no_rows() -> None:
    use(service(netbox=None))
    response = Caller("network_engineer").get(BASE)
    body = response.json()
    validate("inventory_list", body)
    assert body["state"] == "not-connected" and body["items"] == [] and body["summary"] is None


def test_netbox_failing_is_unknown_and_leaks_nothing() -> None:
    secret = "https://netbox.internal/api?token=SECRET"
    use(service(netbox=FakeNetbox(AdapterError(AdapterStatus.UNAVAILABLE, secret))))
    response = Caller("network_engineer").get(BASE)
    assert response.status_code == 200
    body = response.json()
    validate("inventory_list", body)
    assert body["state"] == "unknown" and body["items"] == []
    assert "SECRET" not in response.text and "netbox.internal" not in response.text


def test_a_failing_discovery_source_keeps_the_netbox_rows() -> None:
    use(service(librenms=FakeLibrenms(RuntimeError("down"))))
    body = Caller("network_engineer").get(BASE).json()
    assert body["state"] == "ok"
    assert {s["source"]: s["state"] for s in body["sources"]}["librenms"] == "unknown"
    assert {i["reconcile"]["status"] for i in body["items"]} == {"not-checked"}


def test_the_summary_endpoint_reports_the_same_states() -> None:
    use(service(netbox=None))
    body = Caller("management").get(f"{BASE}/summary").json()
    validate("inventory_summary_response", body)
    assert body["state"] == "not-connected" and body["summary"] is None


def test_a_service_that_raises_is_unknown_not_a_500() -> None:
    class Broken:
        async def snapshot(self) -> Any:
            raise RuntimeError("boom with secret")

    app.dependency_overrides[inventory_routes.get_inventory_service] = lambda: Broken()
    response = Caller("network_engineer").get(BASE)
    assert response.status_code == 200
    assert response.json()["state"] == "unknown"
    assert "secret" not in response.text


def test_hostile_names_are_returned_as_data() -> None:
    use(service(netbox=FakeNetbox([asset("1", HOSTILE[:100])]), librenms=None))
    response = Caller("network_engineer").get(BASE)
    assert response.json()["items"][0]["name"]["value"] == HOSTILE[:100]
    assert response.headers["content-type"].startswith("application/json")


# --- detail ------------------------------------------------------------------------------------------------


def test_detail_returns_the_asset_with_provenance() -> None:
    caller = Caller("network_engineer")
    listing = caller.get(BASE).json()
    target = next(i for i in listing["items"] if i["name"]["value"] == "core-sw-1")
    response = caller.get(f"{BASE}/{target['id']}")
    assert response.status_code == 200
    body = response.json()
    validate("inventory_detail", body)
    assert body["item"] == target


def test_detail_of_an_unknown_asset_is_404_not_an_empty_success() -> None:
    response = Caller("network_engineer").get(f"{BASE}/device-00000000-0000-0000-0000-000000000000")
    assert response.status_code == 404


@pytest.mark.parametrize(
    "bad", ["x", "device-1", "DEVICE-6f1c2a9e-0b1d-5c3e-8f4a-123456789abc", "../etc"]
)
def test_a_malformed_id_is_a_422_and_never_reaches_the_service(bad: str) -> None:
    response = Caller("network_engineer").get(f"{BASE}/{bad}")
    assert response.status_code in (404, 422)


def test_detail_with_netbox_unavailable_is_an_explicit_state() -> None:
    use(service(netbox=None))
    response = Caller("network_engineer").get(f"{BASE}/device-6f1c2a9e-0b1d-5c3e-8f4a-123456789abc")
    assert response.status_code == 200
    body = response.json()
    validate("inventory_detail", body)
    assert body["state"] == "not-connected" and body["item"] is None


# --- rate limits --------------------------------------------------------------------------------------------


def test_the_list_is_rate_limited_per_identity_after_authorisation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(inventory_routes, "LIST_LIMIT_PER_MINUTE", 3)
    caller = Caller("network_engineer")
    assert [caller.get(BASE).status_code for _ in range(4)] == [200, 200, 200, 429]
    other = Caller("auditor", subject="sub-2")
    assert other.get(BASE).status_code == 200  # another identity has its own budget
    limited = caller.get(BASE)
    assert limited.headers["retry-after"] == "60"


# --- audit ----------------------------------------------------------------------------------------------------


def test_a_list_read_is_audited_with_counts_and_filter_names_never_values(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    caller = Caller("network_engineer")
    caller.get(BASE, q="core-secret-name", site="HQ")
    (record,) = [r for r in audit_records(caplog) if r["action"] == "inventory.list.read"]
    assert record["outcome"] == "success"
    assert record["actor_id"] == caller.identity_id
    assert record["state"] == "ok" and record["returned"] == 0 and record["total"] == 0
    assert record["filters"] == "site,q"
    assert "core-secret-name" not in json.dumps(record) and "HQ" not in json.dumps(record)


def test_a_detail_read_is_audited_with_its_target(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    caller = Caller("auditor")
    target = caller.get(BASE).json()["items"][0]["id"]
    caller.get(f"{BASE}/{target}")
    (record,) = [r for r in audit_records(caplog) if r["action"] == "inventory.item.read"]
    assert record["target"] == target and record["outcome"] == "success"


def test_refusals_are_audited(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    Caller("management").get(BASE)
    Caller("network_engineer").get(BASE, page=0)
    records = audit_records(caplog)
    denied = [r for r in records if r["outcome"] == "denied"]
    assert denied and denied[0]["reason"] == "permission"
    rejected = [r for r in records if r.get("reason") == "invalid-request"]
    assert rejected and rejected[0]["outcome"] == "failure"


def test_wazuh_agents_appear_when_the_join_field_is_configured() -> None:
    netbox = FakeNetbox([asset("2", "web-1")], agent_keys={"2": "001"})
    svc = InventoryService(
        netbox=netbox,
        librenms=None,
        wazuh=FakeWazuh([agent("001", "web-1", "10.0.0.20"), agent("002", "stray", "10.0.0.77")]),
        agent_field="wazuh_agent",
        class_map=CLASS_MAP,
        clock=lambda: NOW,
        cache=TtlCache(0.0),
    )
    use(svc)
    body = Caller("network_engineer").get(BASE).json()
    assert {s["source"]: s["state"] for s in body["sources"]}["wazuh"] == "ok"
    assert items_of(body) == ["stray", "web-1"]
