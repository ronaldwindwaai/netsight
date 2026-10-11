"""The Internet/WAN routes over HTTP (Step 5): RBAC, bounds, explicit states, export, audit.

Hermetic: the declaration, the LibreNMS port source and the sample store are fakes; the real
session, RBAC and rate-limit stack is exercised through ``Caller``.
"""

from __future__ import annotations

import csv
import io
import json
import logging
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from alerting_support import Caller, audit_records
from fastapi.testclient import TestClient

from netsight_api import internet_routes
from netsight_api.adapters.librenms import WanPortReading
from netsight_api.auth.settings import session_policy
from netsight_api.contracts import validate
from netsight_api.main import app
from netsight_api.storage import StorageError
from netsight_api.storage.wan import InMemoryWanSampleRepository
from netsight_api.wan import sla
from netsight_api.wan.config import load_wan_links
from netsight_api.wan.sla import Sample

NOW = datetime(2026, 10, 11, 12, 0, 0, tzinfo=UTC)
SEP = datetime(2026, 9, 1, tzinfo=UTC)
BASE = "/api/v1/internet"
ALL_ROLES = [
    "administrator",
    "network_engineer",
    "security_analyst",
    "technician",
    "management",
    "auditor",
]
EXPORTERS = ["administrator", "network_engineer", "auditor"]
NON_EXPORTERS = ["security_analyst", "technician", "management"]
LINKS = [
    {
        "id": "fibre-1",
        "name": "Primary fibre",
        "role": "primary",
        "isp": "Example ISP",
        "gateway": "192.0.2.1",
        "librenms_device": "12",
        "librenms_port": "345",
        "probe_targets": ["probe-a.example"],
        "probe_location": "branch",
        "dns_target": "dns-check.example",
        "uptime_target_pct": 99.9,
    }
]


class FakePorts:
    def __init__(self, reading: WanPortReading | Exception | None = None) -> None:
        self.reading = reading

    async def wan_port(self, device: str, port: str) -> WanPortReading | None:
        if isinstance(self.reading, Exception):
            raise self.reading
        return self.reading


def reading() -> WanPortReading:
    return WanPortReading(
        "up", 1_000_000_000, 100_000_000, 20_000_000, NOW - timedelta(minutes=1), "8.8.8.8"
    )


def add(store: InMemoryWanSampleRepository, when: datetime, outcomes: list[str]) -> None:
    rows = [
        Sample("icmp", "probe-a.example", o, 5.0 if o == "pass" else None, "branch")
        for o in outcomes
    ]  # type: ignore[arg-type]
    store.record_cycle(sla.build_cycle("fibre-1", when, 60, rows), rows)


@pytest.fixture(autouse=True)
def _wiring(monkeypatch: pytest.MonkeyPatch) -> Iterator[InMemoryWanSampleRepository]:
    for name in (
        "NETSIGHT_ENV",
        "NETSIGHT_ENABLE_DEV_IDENTITY",
        "DATABASE_URL",
        "NETSIGHT_WAN_LINKS",
    ):
        monkeypatch.delenv(name, raising=False)
    app.dependency_overrides.clear()
    session_policy.cache_clear()
    store = InMemoryWanSampleRepository()
    internet_routes.get_closed_month_cache().clear()
    app.dependency_overrides[internet_routes.get_now] = lambda: NOW
    app.dependency_overrides[internet_routes.get_wan_config] = lambda: load_wan_links(
        {"NETSIGHT_WAN_LINKS": json.dumps(LINKS)}
    )
    app.dependency_overrides[internet_routes.get_wan_ports] = lambda: FakePorts(reading())
    app.dependency_overrides[internet_routes.get_wan_store] = lambda: store
    yield store
    internet_routes.get_closed_month_cache().clear()
    app.dependency_overrides.clear()
    session_policy.cache_clear()


def _constant(value: Any) -> Any:
    # No default-argument capture: FastAPI would treat it as a query parameter and deep-copy it.
    return lambda: value


def use(**dependencies: Any) -> None:
    for name, value in dependencies.items():
        app.dependency_overrides[getattr(internet_routes, f"get_wan_{name}")] = _constant(value)


def populate_september(store: InMemoryWanSampleRepository) -> None:
    for minute in range(60):
        add(store, SEP + timedelta(minutes=minute), ["pass"])
    for minute in range(60, 70):
        add(store, SEP + timedelta(minutes=minute), ["fail"])


# --- authentication and authorisation ---------------------------------------------------------------


def test_anonymous_callers_are_refused_everywhere() -> None:
    client = TestClient(app)
    for path in (BASE, f"{BASE}/sla", f"{BASE}/sla/export"):
        assert client.get(path).status_code == 401, path


def test_a_caller_without_a_known_role_is_refused() -> None:
    caller = Caller("not-a-role")
    for path in (BASE, f"{BASE}/sla", f"{BASE}/sla/export"):
        response = caller.get(path)
        assert response.status_code == 403 and response.json()["error"]["code"] == "FORBIDDEN"


@pytest.mark.parametrize("role", ALL_ROLES)
def test_every_role_reads_the_status_and_the_sla(role: str) -> None:
    caller = Caller(role)
    assert caller.get(BASE).status_code == 200
    assert caller.get(f"{BASE}/sla").status_code == 200


@pytest.mark.parametrize("role", EXPORTERS)
def test_the_evidence_roles_may_export(role: str) -> None:
    assert Caller(role).get(f"{BASE}/sla/export", month="2026-09").status_code == 200


@pytest.mark.parametrize("role", NON_EXPORTERS)
def test_other_roles_are_refused_the_export_and_it_is_audited(
    role: str, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)
    response = Caller(role).get(f"{BASE}/sla/export", month="2026-09")
    assert response.status_code == 403 and response.json()["error"]["code"] == "FORBIDDEN"
    assert "Example ISP" not in response.text
    record = [r for r in audit_records(caplog) if r["action"] == "internet.export"][-1]
    assert record["outcome"] == "denied"


def test_authorisation_is_decided_before_the_rate_limit() -> None:
    caller = Caller("technician")
    codes = {caller.get(f"{BASE}/sla/export", month="2026-09").status_code for _ in range(30)}
    assert codes == {403}


def test_the_surface_is_read_only() -> None:
    caller = Caller("administrator")
    for path in (BASE, f"{BASE}/sla", f"{BASE}/sla/export"):
        for verb in ("post", "put", "delete", "patch"):
            response = getattr(caller.http, verb)(path)
            assert response.status_code in {404, 405}, (verb, path)


def test_the_routes_are_in_the_published_openapi_document() -> None:
    paths = app.openapi()["paths"]
    assert {"/api/v1/internet", "/api/v1/internet/sla", "/api/v1/internet/sla/export"} <= set(paths)


# --- GET /internet ----------------------------------------------------------------------------------


def test_nothing_configured_is_an_explicit_not_connected_state() -> None:
    use(config=load_wan_links({}), ports=None, store=None)
    response = Caller("administrator").get(BASE)
    body = response.json()
    assert response.status_code == 200 and body["state"] == "not-connected"
    assert body["links"] == [] and body["failover"] == {"state": "unknown", "basis": "unknown"}
    validate("internet_response", body)


def test_an_unusable_declaration_is_unknown_not_an_error() -> None:
    use(config=load_wan_links({"NETSIGHT_WAN_LINKS": "not json"}))
    body = Caller("administrator").get(BASE).json()
    assert body["state"] == "unknown" and body["links"] == []
    validate("internet_response", body)


def test_a_connected_link_is_reported_with_its_sources(
    _wiring: InMemoryWanSampleRepository,
) -> None:
    for minute in range(10, 0, -1):
        add(_wiring, NOW - timedelta(minutes=minute), ["pass"])
    response = Caller("network_engineer").get(BASE)
    body = response.json()
    assert response.status_code == 200 and body["state"] == "ok"
    validate("internet_response", body)
    link = body["links"][0]
    assert link["status"] == "up" and link["interface"]["rx_bps"] == 100_000_000
    assert link["interface"]["freshness"]["source"] == "librenms"
    assert link["quality"]["loss_pct"] == 0.0 and link["quality"]["freshness"]["state"] == "fresh"
    assert link["configured"]["isp"] == "Example ISP"
    assert body["failover"]["state"] == "single-link"


def test_a_failing_interface_source_degrades_that_block_to_unknown() -> None:
    use(ports=FakePorts(RuntimeError("secret https://librenms.internal/token")))
    response = Caller("administrator").get(BASE)
    assert response.status_code == 200
    assert response.json()["links"][0]["interface"]["state"] == "unknown"
    assert "librenms.internal" not in response.text and "secret" not in response.text


def test_an_unexpected_assembly_failure_is_unknown_and_never_a_500(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def boom(*_a: object, **_k: object) -> None:
        raise RuntimeError("internal detail /srv/app/secret.py")

    monkeypatch.setattr(internet_routes, "build_internet", boom)
    response = Caller("administrator").get(BASE)
    assert response.status_code == 200 and response.json()["state"] == "unknown"
    assert "secret.py" not in response.text


def test_hostile_configured_text_is_returned_as_data() -> None:
    hostile = "<img src=x onerror=alert(1)>"
    use(
        config=load_wan_links(
            {"NETSIGHT_WAN_LINKS": json.dumps([{**LINKS[0], "name": hostile, "isp": hostile}])}
        )
    )
    body = Caller("administrator").get(BASE).json()
    assert body["links"][0]["name"] == hostile and body["links"][0]["configured"]["isp"] == hostile
    validate("internet_response", body)


def test_the_read_limit_applies_per_identity() -> None:
    caller = Caller("administrator")
    codes = [caller.get(BASE).status_code for _ in range(301)]
    assert codes[:300] == [200] * 300 and codes[300] == 429


# --- GET /internet/sla --------------------------------------------------------------------------------


def test_the_sla_defaults_to_the_current_month(_wiring: InMemoryWanSampleRepository) -> None:
    body = Caller("management").get(f"{BASE}/sla").json()
    assert body["month"] == "2026-10" and body["state"] == "ok"
    assert body["period_end"] == "2026-10-11T12:00:00Z"
    validate("internet_sla_response", body)


def test_a_past_month_is_computed_from_the_stored_samples(
    _wiring: InMemoryWanSampleRepository,
) -> None:
    populate_september(_wiring)
    body = Caller("auditor").get(f"{BASE}/sla", month="2026-09").json()
    validate("internet_sla_response", body)
    link = body["links"][0]
    assert link["down_seconds"] == 10 * 60 + 30 and link["up_seconds"] == 60 * 60
    assert link["outage_count"] == 1
    assert link["violations"][0]["kind"] == "uptime-below-target"


def test_no_store_is_an_explicit_not_connected_sla() -> None:
    use(store=None)
    body = Caller("administrator").get(f"{BASE}/sla", month="2026-09").json()
    assert body["state"] == "not-connected" and body["links"] == []
    validate("internet_sla_response", body)


@pytest.mark.parametrize(
    "month",
    ["2026-13", "2026-1", "2024-01", "2027-01", "abc", "2026-09-01", "x" * 100, "", "2026-00"],
)
def test_an_unbounded_or_malformed_month_is_a_422(month: str) -> None:
    caller = Caller("administrator")
    for path in (f"{BASE}/sla", f"{BASE}/sla/export"):
        response = caller.get(path, month=month)
        assert response.status_code == 422, (path, month)
        assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_the_sla_read_limit_is_tighter_than_the_status_limit() -> None:
    caller = Caller("administrator")
    codes = [caller.get(f"{BASE}/sla", month="2026-09").status_code for _ in range(31)]
    assert codes[:30] == [200] * 30 and codes[30] == 429
    assert caller.get(BASE).status_code == 200  # a separate family


# --- GET /internet/sla/export --------------------------------------------------------------------------


def test_the_json_export_is_the_contract_with_a_download_name(
    _wiring: InMemoryWanSampleRepository,
) -> None:
    populate_september(_wiring)
    response = Caller("network_engineer").get(f"{BASE}/sla/export", month="2026-09")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert (
        response.headers["content-disposition"]
        == 'attachment; filename="netsight-wan-sla-2026-09.json"'
    )
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    validate("internet_sla_export", body)
    link = body["links"][0]
    assert [w["kind"] for w in link["windows"][:1]] == ["down"]
    assert link["windows"][-1]["kind"] == "unknown" and link["windows"][-1]["sample_count"] == 0
    assert body["basis"].startswith("Computed only from stored probe samples")


def test_the_csv_export_is_a_bounded_attachment(_wiring: InMemoryWanSampleRepository) -> None:
    populate_september(_wiring)
    response = Caller("auditor").get(f"{BASE}/sla/export", month="2026-09", format="csv")
    assert response.status_code == 200
    assert response.headers["content-type"] == "text/csv; charset=utf-8"
    assert (
        response.headers["content-disposition"]
        == 'attachment; filename="netsight-wan-sla-2026-09.csv"'
    )
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"
    rows = list(csv.reader(io.StringIO(response.text)))
    assert rows[0][:5] == ["month", "link_id", "link_name", "isp", "kind"]
    assert {row[4] for row in rows[1:]} == {"down", "unknown"}
    assert response.text.endswith("\r\n")


def test_the_default_export_month_is_the_current_one() -> None:
    response = Caller("administrator").get(f"{BASE}/sla/export")
    assert response.json()["month"] == "2026-10"
    assert "2026-10" in response.headers["content-disposition"]


@pytest.mark.parametrize("fmt", ["xml", "CSV", "json;x", "", "csv\r\nSet-Cookie: a=b"])
def test_an_unknown_format_is_a_422(fmt: str) -> None:
    response = Caller("administrator").get(f"{BASE}/sla/export", month="2026-09", format=fmt)
    assert response.status_code == 422


def test_no_store_exports_an_explicit_state_not_an_empty_success() -> None:
    use(store=None)
    caller = Caller("administrator")
    body = caller.get(f"{BASE}/sla/export", month="2026-09").json()
    assert body["state"] == "not-connected" and body["links"] == []
    csv_text = caller.get(f"{BASE}/sla/export", month="2026-09", format="csv").text
    assert len(csv_text.strip().splitlines()) == 1  # the header only


def test_a_successful_export_is_audited_with_actor_month_and_format(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO)
    caller = Caller("network_engineer")
    caller.get(f"{BASE}/sla/export", month="2026-09", format="csv")
    record = [r for r in audit_records(caplog) if r["action"] == "internet.export"][-1]
    assert record["outcome"] == "success" and record["actor_id"] == caller.identity_id
    assert record["target"] == "2026-09" and record["format"] == "csv"
    assert "Example ISP" not in json.dumps(record)


def test_the_export_limit_is_tight_and_per_identity() -> None:
    caller = Caller("administrator")
    codes = [caller.get(f"{BASE}/sla/export", month="2026-09").status_code for _ in range(11)]
    assert codes[:10] == [200] * 10 and codes[10] == 429
    assert Caller("auditor", "sub-2").get(f"{BASE}/sla/export", month="2026-09").status_code == 200


def test_a_failing_store_exports_unknown_without_leaking(
    _wiring: InMemoryWanSampleRepository,
) -> None:
    class Broken(InMemoryWanSampleRepository):
        def cycles_between(self, *args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("postgresql://user:pw@host/db")

    use(store=Broken())
    response = Caller("administrator").get(f"{BASE}/sla/export", month="2026-09")
    assert response.status_code == 200 and response.json()["state"] == "unknown"
    assert "postgresql" not in response.text


# --- the declaration is parsed once per distinct value ------------------------------------------------


def test_an_unusable_declaration_is_logged_once_not_on_every_request(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    app.dependency_overrides.pop(internet_routes.get_wan_config)
    internet_routes._declared.cache_clear()
    monkeypatch.setenv("NETSIGHT_WAN_LINKS", "not json")
    caplog.set_level(logging.WARNING, logger="netsight_api")
    caller = Caller("administrator")
    for _ in range(3):
        assert caller.get(BASE).json()["state"] == "unknown"
    warnings = [r for r in caplog.records if "invalid WAN link declaration" in r.getMessage()]
    assert len(warnings) == 1
    # a changed value is parsed again, so an operator's fix takes effect without a restart
    monkeypatch.setenv("NETSIGHT_WAN_LINKS", json.dumps(LINKS))
    assert caller.get(BASE).json()["state"] == "ok"
    internet_routes._declared.cache_clear()


# --- the real dependency factories ----------------------------------------------------------------------


def test_without_a_database_url_there_is_no_sample_store(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert internet_routes.get_wan_store() is None


def test_an_unusable_database_url_is_an_unavailable_store_not_a_missing_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DATABASE_URL", "mysql://u:p@h/db")
    store = internet_routes.get_wan_store()
    assert store is not None
    with pytest.raises(StorageError, match="not usable"):
        store.cycles_between("fibre-1", NOW - timedelta(hours=1), NOW)
    app.dependency_overrides.pop(internet_routes.get_wan_store)  # use the real factory
    response = Caller("administrator").get(f"{BASE}/sla", month="2026-09")
    assert response.status_code == 200 and response.json()["state"] == "unknown"


def test_a_valid_database_url_builds_the_postgres_store(monkeypatch: pytest.MonkeyPatch) -> None:
    from netsight_api.storage.postgres_wan import PostgresWanSampleRepository

    monkeypatch.setenv("DATABASE_URL", "postgresql://app:pw@127.0.0.1:5432/netsight")
    store = internet_routes.get_wan_store()
    assert isinstance(store, PostgresWanSampleRepository)
    assert "pw" not in repr(store)


@pytest.mark.parametrize(
    ("interval", "expected"),
    [(None, 60), ("30", 30), ("300", 300), ("29", 60), ("junk", 60)],
)
def test_the_store_read_cap_follows_the_configured_sampling_interval(
    monkeypatch: pytest.MonkeyPatch, interval: str | None, expected: int
) -> None:
    from netsight_api.storage.wan import cycle_read_cap

    monkeypatch.setenv("DATABASE_URL", "postgresql://app:pw@127.0.0.1:5432/netsight")
    if interval is None:
        monkeypatch.delenv("NETSIGHT_WAN_SAMPLE_INTERVAL_SECONDS", raising=False)
    else:
        monkeypatch.setenv("NETSIGHT_WAN_SAMPLE_INTERVAL_SECONDS", interval)
    store = internet_routes.get_wan_store()
    assert store is not None and store.max_cycles == cycle_read_cap(expected)  # type: ignore[attr-defined]


def test_the_port_source_is_the_librenms_client_only_when_it_is_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in ("LIBRENMS_BASE_URL", "LIBRENMS_TOKEN", "LIBRENMS_TIMEZONE"):
        monkeypatch.delenv(name, raising=False)
    assert internet_routes.get_wan_ports() is None
    monkeypatch.setenv("LIBRENMS_BASE_URL", "https://librenms.test")
    monkeypatch.setenv("LIBRENMS_TOKEN", "token-for-the-test")
    monkeypatch.setenv("LIBRENMS_TIMEZONE", "UTC")
    ports = internet_routes.get_wan_ports()
    assert ports is not None and hasattr(ports, "wan_port")
    assert "token-for-the-test" not in repr(ports)


def test_an_unexpected_sla_failure_is_unknown_and_never_a_500(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*_a: object, **_k: object) -> None:
        raise RuntimeError("internal detail /srv/app/secret.py")

    monkeypatch.setattr(internet_routes, "build_sla", boom)
    response = Caller("administrator").get(f"{BASE}/sla", month="2026-09")
    assert response.status_code == 200 and response.json()["state"] == "unknown"
    assert response.json()["links"] == [] and "secret.py" not in response.text


def test_an_unexpected_export_failure_is_an_unknown_export_and_is_audited_as_such(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def boom(*_a: object, **_k: object) -> None:
        raise RuntimeError("internal detail /srv/app/secret.py")

    caplog.set_level(logging.INFO)
    monkeypatch.setattr(internet_routes, "build_export", boom)
    caller = Caller("administrator")
    response = caller.get(f"{BASE}/sla/export", month="2026-09")
    assert response.status_code == 200 and response.json()["state"] == "unknown"
    assert "secret.py" not in response.text
    csv_response = caller.get(f"{BASE}/sla/export", month="2026-09", format="csv")
    assert len(csv_response.text.strip().splitlines()) == 1
    record = [r for r in audit_records(caplog) if r["action"] == "internet.export"][-1]
    assert record["outcome"] == "failure" and record["state"] == "unknown"


# --- internet:read_detail redaction (security review M2) -----------------------------------------------

DETAIL_ROLES = ["administrator", "network_engineer", "security_analyst"]
SUMMARY_ROLES = ["technician", "management", "auditor"]


@pytest.mark.parametrize("role", DETAIL_ROLES)
def test_detail_roles_see_the_isp_gateway_public_ip_and_throughput(role: str) -> None:
    body = Caller(role).get(BASE).json()
    validate("internet_response", body)
    link = body["links"][0]
    assert body["detail_redacted"] is False
    assert (
        link["configured"]["isp"] == "Example ISP" and link["configured"]["gateway"] == "192.0.2.1"
    )
    assert link["interface"]["public_ip"] == "8.8.8.8"
    assert link["interface"]["rx_bps"] == 100_000_000 and link["interface"]["tx_bps"] == 20_000_000
    assert link["interface"]["utilisation_pct"] == 10.0


@pytest.mark.parametrize("role", SUMMARY_ROLES)
def test_summary_roles_get_status_and_quality_but_not_the_detail(role: str) -> None:
    response = Caller(role).get(BASE)
    body = response.json()
    validate("internet_response", body)
    link = body["links"][0]
    assert body["detail_redacted"] is True
    assert link["configured"]["isp"] is None and link["configured"]["gateway"] is None
    assert link["interface"]["public_ip"] is None
    assert link["interface"]["rx_bps"] is None and link["interface"]["tx_bps"] is None
    assert link["interface"]["utilisation_pct"] is None
    # status, capacity and the probe blocks are still there
    assert link["status"] == "up" and link["interface"]["oper_status"] == "up"
    assert link["interface"]["capacity_bps"] == 1_000_000_000
    assert link["configured"]["probe_location"] == "branch"
    for secret in (
        "Example ISP",
        "192.0.2.1",
        "8.8.8.8",
        '"rx_bps":100000000,',
        '"tx_bps":20000000,',
    ):
        assert secret not in response.text


def test_a_non_ok_response_still_carries_the_redaction_flag() -> None:
    use(config=load_wan_links({}), ports=None, store=None)
    assert Caller("management").get(BASE).json()["detail_redacted"] is True
    assert Caller("administrator").get(BASE).json()["detail_redacted"] is False


def test_the_export_withholds_the_isp_from_roles_without_the_detail_permission(
    _wiring: InMemoryWanSampleRepository,
) -> None:
    populate_september(_wiring)
    auditor = Caller("auditor")
    body = auditor.get(f"{BASE}/sla/export", month="2026-09").json()
    validate("internet_sla_export", body)
    assert body["detail_redacted"] is True and body["links"][0]["isp"] is None
    assert body["links"][0]["link"]["down_seconds"] > 0  # the evidence itself is complete
    assert (
        "Example ISP" not in auditor.get(f"{BASE}/sla/export", month="2026-09", format="csv").text
    )
    full = Caller("network_engineer").get(f"{BASE}/sla/export", month="2026-09").json()
    assert full["detail_redacted"] is False and full["links"][0]["isp"] == "Example ISP"


# --- the export audit (security review M3) --------------------------------------------------------------


def test_a_successful_export_audit_records_link_count_row_count_and_format(
    _wiring: InMemoryWanSampleRepository, caplog: pytest.LogCaptureFixture
) -> None:
    populate_september(_wiring)
    caplog.set_level(logging.INFO)
    Caller("network_engineer").get(f"{BASE}/sla/export", month="2026-09", format="csv")
    record = [r for r in audit_records(caplog) if r["action"] == "internet.export"][-1]
    assert record["outcome"] == "success" and record["state"] == "ok"
    assert record["link_count"] == 1 and record["row_count"] == 2 and record["format"] == "csv"


def test_an_unknown_export_is_audited_as_a_failure(caplog: pytest.LogCaptureFixture) -> None:
    class Broken(InMemoryWanSampleRepository):
        def cycles_between(self, *args: Any, **kwargs: Any) -> Any:
            raise StorageError("down")

    use(store=Broken())
    caplog.set_level(logging.INFO)
    response = Caller("administrator").get(f"{BASE}/sla/export", month="2026-09", format="json")
    assert response.status_code == 200 and response.json()["state"] == "unknown"
    record = [r for r in audit_records(caplog) if r["action"] == "internet.export"][-1]
    assert record["outcome"] == "failure" and record["state"] == "unknown"
    assert record["link_count"] == 0 and record["row_count"] == 0 and record["format"] == "json"


def test_a_not_connected_export_is_still_a_success(caplog: pytest.LogCaptureFixture) -> None:
    use(store=None)
    caplog.set_level(logging.INFO)
    Caller("administrator").get(f"{BASE}/sla/export", month="2026-09")
    record = [r for r in audit_records(caplog) if r["action"] == "internet.export"][-1]
    assert record["outcome"] == "success" and record["state"] == "not-connected"


def test_the_routes_use_no_assert_for_validation() -> None:
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(internet_routes))
    assert not [node for node in ast.walk(tree) if isinstance(node, ast.Assert)]


def test_the_attachment_name_check_is_explicit() -> None:
    assert internet_routes._attachment("2026-09", "csv")["Content-Disposition"].endswith(
        'netsight-wan-sla-2026-09.csv"'
    )
    for bad in ("2026-9", 'x"; y', "2026-09\r\nX: y", ""):
        with pytest.raises(ValueError, match="month"):
            internet_routes._attachment(bad, "csv")


# --- closed months are served from the cache ---------------------------------------------------------------


def test_a_closed_month_is_not_recomputed_on_the_second_request(
    _wiring: InMemoryWanSampleRepository,
) -> None:
    class Counting(InMemoryWanSampleRepository):
        reads = 0

        def cycles_between(self, *args: Any, **kwargs: Any) -> Any:
            type(self).reads += 1
            return super().cycles_between(*args, **kwargs)

    store = Counting()
    populate_september(store)
    use(store=store)
    internet_routes.get_closed_month_cache().clear()
    caller = Caller("administrator")
    first = caller.get(f"{BASE}/sla", month="2026-09").json()
    second = caller.get(f"{BASE}/sla", month="2026-09").json()
    assert first == second and Counting.reads == 1
    caller.get(f"{BASE}/sla", month="2026-10")
    caller.get(f"{BASE}/sla", month="2026-10")
    assert Counting.reads == 3  # the open month is read every time
    internet_routes.get_closed_month_cache().clear()
