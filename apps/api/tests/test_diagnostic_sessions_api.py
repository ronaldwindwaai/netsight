"""Diagnostic sessions over HTTP (S7 Step 4a-e): persist at run time, read back, bounded and RBAC'd.

Hermetic: probe sources, the topology/change sources and the session store are fakes; the real
session, CSRF, RBAC and rate-limit stack is exercised through ``Caller``.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import NAMESPACE_URL, uuid5

import pytest
from alerting_support import Caller, audit_records
from diagnostic_support import (
    DIAGNOSTIC_ROLES,
    NO_DIAGNOSTIC_ROLES,
    make_session,
    session_id,
)
from fastapi.testclient import TestClient

from netsight_api import diagnostic_routes, read_limit
from netsight_api.auth.deps import get_current_identity
from netsight_api.auth.rate_limit import RateLimiter
from netsight_api.auth.settings import session_policy
from netsight_api.contracts import validate
from netsight_api.diagnostic_changes import ChangeCandidate, SourceRead
from netsight_api.diagnostic_context import (
    get_context_sources,
    get_optional_diagnostic_session_store,
)
from netsight_api.diagnostic_path import TopologyDevice, TopologyLink, TopologyRead
from netsight_api.diagnostics import Observation
from netsight_api.incident_deps import get_optional_incident_store
from netsight_api.main import app
from netsight_api.rbac import ROLE_PERMISSIONS, Identity, Permission, PrincipalKind, Role
from netsight_api.schemas import Incident
from netsight_api.schemas_diagnostic_session import INCIDENT_TITLE_PLACEHOLDER, DiagnosticChangeItem
from netsight_api.storage import InMemoryIncidentRepository, StorageError
from netsight_api.storage.diagnostics import InMemoryDiagnosticSessionRepository

BASE = "/api/v1/diagnostics"
# The code under test builds its 24-hour "recent changes" window from the real clock, so a fixed
# date here silently ages out of that window (these tests failed once the real date moved on).
# Anchor to the real clock instead; every fixture time is an offset from NOW.
NOW = datetime.now(UTC).replace(microsecond=0)


def device_id(name: str) -> str:
    return f"device-{uuid5(NAMESPACE_URL, name)}"


def topology() -> TopologyRead:
    devices = (
        TopologyDevice(device_id("SERVER01"), "SERVER01", "server", None, ()),
        TopologyDevice(device_id("fw-01"), "fw-01", "firewall", None, ()),
        TopologyDevice(device_id("core-01"), "core-01", "core", None, ()),
    )
    links = (
        TopologyLink(device_id("SERVER01"), device_id("fw-01")),
        TopologyLink(device_id("fw-01"), device_id("core-01")),
    )
    return TopologyRead("ok", devices, links, NOW)


class FakeContext:
    def __init__(
        self,
        *,
        topo: TopologyRead | None = None,
        incidents: SourceRead | None = None,
        alerts: SourceRead | None = None,
        raises: bool = False,
    ) -> None:
        self._topology = topo or TopologyRead("not-connected", (), (), None)
        self._incidents = incidents or SourceRead("not-connected")
        self._alerts = alerts or SourceRead("not-connected")
        self._raises = raises
        self.windows: list[tuple[datetime, datetime]] = []

    async def topology(self) -> TopologyRead:
        if self._raises:
            raise RuntimeError("topology backend exploded: secret-host")
        return self._topology

    async def changes(
        self, *, window_start: datetime, window_end: datetime, target: str
    ) -> tuple[SourceRead, SourceRead]:
        if self._raises:
            raise RuntimeError("change backend exploded: secret-host")
        self.windows.append((window_start, window_end))
        return self._incidents, self._alerts


class LocatedProbe:
    """A probe source at one location with declared outcomes per check kind."""

    def __init__(self, location: str | None, outcomes: dict[str, str]) -> None:
        self.location = location
        self.outcomes = outcomes

    async def probe(self, *, kind: str, target: str, vantage: str | None) -> Observation:
        status = self.outcomes.get(kind, "unknown")
        return Observation(
            kind=kind,  # type: ignore[arg-type]
            label=f"{kind} check",
            status=status,  # type: ignore[arg-type]
            vantage=self.location,
            location=self.location,  # type: ignore[arg-type]
            port=443 if kind in {"tcp", "http", "https"} else None,
            detail=None if status != "unknown" else "no data",
            observed_at=NOW,
            evidence_id=None,
        )


class ExplodingStore:
    def save_session(self, *_a: object, **_k: object) -> None:
        raise StorageError("db down: secret-dsn")

    def get_session(self, *_a: object, **_k: object) -> None:
        raise StorageError("db down: secret-dsn")

    def list_sessions(self, *_a: object, **_k: object) -> None:
        raise StorageError("db down: secret-dsn")

    def count_sessions_since(self, *_a: object, **_k: object) -> None:
        raise StorageError("db down: secret-dsn")


def body(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "target": "SERVER01",
        "symptom": "External users cannot reach the service",
        "vantage": None,
        "requested_checks": ["tcp"],
    }
    payload.update(overrides)
    return payload


@pytest.fixture(autouse=True)
def _wiring(monkeypatch: pytest.MonkeyPatch) -> Iterator[InMemoryDiagnosticSessionRepository]:
    for name in ("BLACKBOX_ALLOWED_TARGETS", "BLACKBOX_EXPORTER_SOURCES", "BLACKBOX_LOCATION"):
        monkeypatch.delenv(name, raising=False)
    app.dependency_overrides.clear()
    session_policy.cache_clear()
    monkeypatch.setattr(diagnostic_routes, "_run_limiter", RateLimiter())
    store = InMemoryDiagnosticSessionRepository()
    app.dependency_overrides[diagnostic_routes.get_now] = lambda: NOW
    app.dependency_overrides[get_optional_diagnostic_session_store] = lambda: store
    app.dependency_overrides[get_context_sources] = lambda: FakeContext()
    yield store
    app.dependency_overrides.clear()
    session_policy.cache_clear()


def use_probes(*sources: LocatedProbe) -> None:
    app.dependency_overrides[diagnostic_routes.get_probe_clients] = lambda: list(sources)


def use_context(context: FakeContext) -> None:
    app.dependency_overrides[get_context_sources] = lambda: context


def external_only_failure() -> None:
    use_probes(
        LocatedProbe("cloud-external", {"tcp": "fail"}),
        LocatedProbe("server-vlan", {"tcp": "pass"}),
    )


# --- run -> session --------------------------------------------------------------------------------


def test_a_run_is_stored_and_can_be_revisited_by_its_id() -> None:
    external_only_failure()
    use_context(
        FakeContext(
            topo=topology(),
            incidents=SourceRead(
                "ok",
                (
                    ChangeCandidate(
                        "incident", "incident-1", None, NOW - timedelta(minutes=20), "high"
                    ),
                ),
            ),
        )
    )
    caller = Caller("administrator")
    posted = caller.post(BASE, body()).json()
    validate("diagnostic_run_response", posted)
    assert posted["state"] == "ok" and posted["stored"] is True

    fetched = caller.get(f"{BASE}/{posted['run']['id']}").json()
    validate("diagnostic_session_response", fetched)
    session = fetched["session"]
    assert fetched["state"] == "ok"
    assert session["run"] == posted["run"]
    assert session["run"]["target_id"] == device_id("SERVER01")

    by_location = {row["location"]: row for row in session["locations"]}
    assert (by_location["cloud-external"]["state"], by_location["cloud-external"]["status"]) == (
        "observed",
        "fail",
    )
    assert by_location["server-vlan"]["status"] == "pass"
    for absent in ("user-lan", "branch", "wifi", "remote-site"):
        assert (
            by_location[absent]["state"] == "not-connected"
            and by_location[absent]["status"] is None
        )

    cause = session["probable_cause"]
    assert (cause["domain"], cause["pattern"], cause["basis"]) == (
        "firewall",
        "external-only-failure",
        "inferred",
    )
    assert {line["basis"] for line in cause["evidence"]} == {"observed", "inferred", "unknown"}

    hops = {hop["tier"]: hop for hop in session["path"]["hops"]}
    assert hops["firewall"]["highlight"] == "suspected" and hops["firewall"]["state"] == "known"
    assert hops["access-switch"]["state"] == "unknown"

    changes = session["recent_changes"]
    assert changes["state"] == "ok"
    assert [(i["ref_id"], i["relation"]) for i in changes["items"]] == [
        ("incident-1", "may-correlate")
    ]
    assert changes["sources"][2] == {"source": "configuration-changes", "state": "not-connected"}


def test_a_service_failing_at_its_own_vlan_is_told_apart_from_an_external_only_failure() -> None:
    use_probes(
        LocatedProbe("cloud-external", {"icmp": "fail", "tcp": "fail"}),
        LocatedProbe("server-vlan", {"icmp": "pass", "tcp": "fail"}),
    )
    caller = Caller("administrator")
    posted = caller.post(BASE, body(requested_checks=["icmp", "tcp"])).json()
    session = caller.get(f"{BASE}/{posted['run']['id']}").json()["session"]
    assert session["probable_cause"]["pattern"] == "service-failure"
    assert session["probable_cause"]["domain"] == "service"


def test_a_prober_without_a_location_leaves_every_location_not_connected() -> None:
    use_probes(LocatedProbe(None, {"tcp": "fail"}))
    caller = Caller("administrator")
    posted = caller.post(BASE, body()).json()
    session = caller.get(f"{BASE}/{posted['run']['id']}").json()["session"]
    assert {row["state"] for row in session["locations"]} == {"not-connected"}
    assert session["run"]["checks"][0]["location"] is None


def test_no_topology_or_change_source_is_said_plainly() -> None:
    external_only_failure()
    caller = Caller("administrator")
    posted = caller.post(BASE, body()).json()
    session = caller.get(f"{BASE}/{posted['run']['id']}").json()["session"]
    assert session["path"] == {
        "state": "not-connected",
        "observed_at": None,
        "hops": [],
        "links": [],
    }
    assert session["recent_changes"]["state"] == "not-connected"
    assert session["recent_changes"]["items"] == []
    assert session["run"]["target_id"] is None


def test_failing_context_sources_degrade_to_unknown_without_losing_the_session() -> None:
    external_only_failure()
    use_context(FakeContext(raises=True))
    caller = Caller("administrator")
    posted = caller.post(BASE, body()).json()
    assert posted["stored"] is True
    session = caller.get(f"{BASE}/{posted['run']['id']}").json()["session"]
    assert session["path"]["state"] == "unknown" and session["path"]["hops"] == []
    assert session["recent_changes"]["state"] == "unknown"
    assert "secret-host" not in str(session)


def test_a_target_missing_from_the_topology_leaves_the_path_unknown() -> None:
    external_only_failure()
    use_context(FakeContext(topo=topology()))
    caller = Caller("administrator")
    posted = caller.post(BASE, body(target="nobody-knows-me")).json()
    session = caller.get(f"{BASE}/{posted['run']['id']}").json()["session"]
    assert session["path"]["state"] == "unknown"
    assert session["run"]["target_id"] is None


def test_the_change_window_ends_when_the_run_ends() -> None:
    external_only_failure()
    context = FakeContext()
    use_context(context)
    posted = Caller("administrator").post(BASE, body()).json()
    start, end = context.windows[0]
    assert end == datetime.fromisoformat(posted["run"]["completed_at"])
    assert end - start == timedelta(hours=24)


def test_without_a_session_store_the_run_is_returned_but_not_stored() -> None:
    external_only_failure()
    app.dependency_overrides[get_optional_diagnostic_session_store] = lambda: None
    caller = Caller("administrator")
    posted = caller.post(BASE, body()).json()
    validate("diagnostic_run_response", posted)
    assert posted["state"] == "ok" and posted["stored"] is False
    fetched = caller.get(f"{BASE}/{posted['run']['id']}").json()
    assert fetched == {"state": "not-connected", "session": None}


def test_a_failing_store_never_turns_a_finished_run_into_an_error(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO)
    external_only_failure()
    app.dependency_overrides[get_optional_diagnostic_session_store] = lambda: ExplodingStore()
    response = Caller("administrator").post(BASE, body())
    assert response.status_code == 200
    posted = response.json()
    assert posted["state"] == "ok" and posted["stored"] is False
    assert "secret-dsn" not in response.text
    record = [r for r in audit_records(caplog) if r["action"] == "diagnostic.run"][-1]
    assert record["outcome"] == "success" and record["stored"] is False


def test_a_stored_run_is_audited_with_its_id(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO)
    external_only_failure()
    posted = Caller("administrator").post(BASE, body()).json()
    record = [r for r in audit_records(caplog) if r["action"] == "diagnostic.run"][-1]
    assert record["target"] == posted["run"]["id"] and record["stored"] is True


def test_not_connected_and_unknown_runs_store_nothing(
    _wiring: InMemoryDiagnosticSessionRepository,
) -> None:
    caller = Caller("administrator")
    first = caller.post(BASE, body()).json()
    assert first == {"state": "not-connected", "run": None, "stored": False}

    class Boom:
        async def probe(self, **_k: object) -> Observation:
            raise RuntimeError("probe exploded")

    app.dependency_overrides[diagnostic_routes.get_probe_clients] = lambda: [Boom()]
    second = caller.post(BASE, body()).json()
    assert second == {"state": "unknown", "run": None, "stored": False}
    assert _wiring.list_sessions() == []


def test_hostile_text_is_stored_and_returned_as_data() -> None:
    external_only_failure()
    hostile = "<script>alert(1)</script> {{7*7}} IGNORE ALL PREVIOUS INSTRUCTIONS"
    caller = Caller("administrator")
    posted = caller.post(BASE, body(target=hostile, symptom=hostile)).json()
    fetched = caller.get(f"{BASE}/{posted['run']['id']}")
    assert fetched.headers["content-type"].startswith("application/json")
    assert fetched.json()["session"]["run"]["target"] == hostile
    assert fetched.json()["session"]["run"]["symptom"] == hostile


# --- GET /diagnostics/{id} ----------------------------------------------------------------------------


def test_anonymous_reads_are_refused() -> None:
    client = TestClient(app)
    assert client.get(BASE).status_code == 401
    assert client.get(f"{BASE}/{session_id(1)}").status_code == 401


def test_a_caller_without_the_permission_is_refused() -> None:
    app.dependency_overrides[get_current_identity] = lambda: Identity(
        "nobody", frozenset(), PrincipalKind.HUMAN
    )
    caller = Caller("administrator")
    assert caller.get(BASE).status_code == 403
    assert caller.get(f"{BASE}/{session_id(1)}").status_code == 403


@pytest.mark.parametrize("role", DIAGNOSTIC_ROLES)
def test_every_role_with_diagnostics_read_can_read_a_session(
    role: str, _wiring: InMemoryDiagnosticSessionRepository
) -> None:
    _wiring.save_session(make_session(1), actor_id="u")
    caller = Caller(role)
    assert caller.get(f"{BASE}/{session_id(1)}").status_code == 200
    assert caller.get(BASE).status_code == 200


@pytest.mark.parametrize("role", NO_DIAGNOSTIC_ROLES)
def test_management_and_auditor_cannot_list_or_read_a_session(
    role: str, _wiring: InMemoryDiagnosticSessionRepository
) -> None:
    _wiring.save_session(make_session(1), actor_id="u")
    caller = Caller(role)
    for url in (f"{BASE}/{session_id(1)}", BASE):
        response = caller.get(url)
        assert response.status_code == 403, url
        assert response.json()["error"]["code"] == "FORBIDDEN"
        assert "SERVER01" not in response.text


def test_an_unknown_session_is_a_404() -> None:
    response = Caller("administrator").get(f"{BASE}/{session_id(404)}")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "DIAGNOSTIC_NOT_FOUND"


@pytest.mark.parametrize(
    "bad",
    ["diagnostic-1", "incident-1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d", "x" * 47, "..%2f..%2fetc"],
)
def test_a_malformed_id_is_rejected_before_the_store(bad: str) -> None:
    response = Caller("administrator").get(f"{BASE}/{bad}")
    assert response.status_code in {404, 422}


def test_the_read_states_are_explicit() -> None:
    caller = Caller("administrator")
    app.dependency_overrides[get_optional_diagnostic_session_store] = lambda: None
    assert caller.get(f"{BASE}/{session_id(1)}").json() == {
        "state": "not-connected",
        "session": None,
    }
    app.dependency_overrides[get_optional_diagnostic_session_store] = lambda: ExplodingStore()
    response = caller.get(f"{BASE}/{session_id(1)}")
    assert response.status_code == 200 and "secret-dsn" not in response.text
    assert response.json() == {"state": "unknown", "session": None}


def test_a_session_is_immutable_over_http(_wiring: InMemoryDiagnosticSessionRepository) -> None:
    _wiring.save_session(make_session(1), actor_id="u")
    caller = Caller("administrator")
    url = f"{BASE}/{session_id(1)}"
    for method in ("put", "patch", "delete", "post"):
        response = getattr(caller.http, method)(
            url, headers={"X-CSRF-Token": caller.session.csrf_token}
        )
        assert response.status_code in {404, 405}, method
    assert _wiring.get_session(session_id(1)) == make_session(1)


# --- GET /diagnostics (list) --------------------------------------------------------------------------


def test_the_list_is_newest_first_bounded_and_paged(
    _wiring: InMemoryDiagnosticSessionRepository,
) -> None:
    for number in range(1, 6):
        _wiring.save_session(
            make_session(
                number, target=f"host-{number}", completed_at=NOW + timedelta(minutes=number)
            ),
            actor_id="u",
        )
    caller = Caller("administrator")
    page = caller.get(BASE, limit=2, offset=0).json()
    validate("diagnostic_session_list_response", page)
    assert page["state"] == "ok"
    assert [row["target"] for row in page["sessions"]] == ["host-5", "host-4"]
    assert (page["limit"], page["offset"], page["next_offset"]) == (2, 0, 2)
    last = caller.get(BASE, limit=2, offset=4).json()
    assert [row["target"] for row in last["sessions"]] == ["host-1"]
    assert last["next_offset"] is None
    default = caller.get(BASE).json()
    assert default["limit"] == 50 and len(default["sessions"]) == 5


@pytest.mark.parametrize(
    "params", [{"limit": 0}, {"limit": 101}, {"offset": -1}, {"offset": 10_001}, {"limit": "x"}]
)
def test_list_bounds_are_enforced(params: dict[str, Any]) -> None:
    assert Caller("administrator").get(BASE, **params).status_code == 422


def test_the_list_states_are_explicit() -> None:
    caller = Caller("administrator")
    app.dependency_overrides[get_optional_diagnostic_session_store] = lambda: None
    page = caller.get(BASE).json()
    validate("diagnostic_session_list_response", page)
    assert (page["state"], page["sessions"], page["next_offset"]) == ("not-connected", [], None)
    app.dependency_overrides[get_optional_diagnostic_session_store] = lambda: ExplodingStore()
    page = caller.get(BASE).json()
    validate("diagnostic_session_list_response", page)
    assert (page["state"], page["sessions"]) == ("unknown", [])


def test_reads_are_rate_limited_per_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(read_limit, "READ_LIMIT_PER_MINUTE", 3)
    caller = Caller("administrator")
    statuses = [caller.get(BASE).status_code for _ in range(5)]
    assert statuses[:3] == [200, 200, 200] and statuses[3:] == [429, 429]


# --- OpenAPI -----------------------------------------------------------------------------------------


def test_openapi_exposes_exactly_the_session_operations() -> None:
    paths = app.openapi()["paths"]
    operations = {
        (path, method)
        for path, item in paths.items()
        if path.startswith("/api/v1/diagnostics")
        for method in item
    }
    assert operations == {
        ("/api/v1/diagnostics", "post"),
        ("/api/v1/diagnostics", "get"),
        ("/api/v1/diagnostics/{diagnostic_id}", "get"),
    }
    assert {"200", "401", "403", "404", "422"} <= set(
        paths["/api/v1/diagnostics/{diagnostic_id}"]["get"]["responses"]
    )


# --- incident titles: references stored, titles joined at read time (security H1) ----------------------

SECRET_TITLE = "Payroll VLAN breach under investigation"
ALERT_TITLE = "Link down on core-01"


class SpyIncidentStore(InMemoryIncidentRepository):
    def __init__(self) -> None:
        super().__init__()
        self.lookups: list[str] = []

    def get_incident(self, incident_id: str) -> Incident | None:
        self.lookups.append(incident_id)
        return super().get_incident(incident_id)


def run_with_incident(title: str = SECRET_TITLE) -> tuple[SpyIncidentStore, str, dict[str, Any]]:
    """Run the external-only failure with one recent incident; returns (store, incident id, POST)."""
    incidents = SpyIncidentStore()
    incident = incidents.create_incident(title=title, severity="critical", actor_id="seed:operator")
    app.dependency_overrides[get_optional_incident_store] = lambda: incidents
    external_only_failure()
    use_context(
        FakeContext(
            incidents=SourceRead(
                "ok",
                (
                    ChangeCandidate(
                        "incident", incident.id, None, NOW - timedelta(minutes=20), "critical"
                    ),
                ),
            ),
            alerts=SourceRead("ok", (ChangeCandidate("alert", "alert-9", ALERT_TITLE, NOW, None),)),
        )
    )
    posted: dict[str, Any] = Caller("administrator").post(BASE, body()).json()
    return incidents, incident.id, posted


def change_items(response_json: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = response_json["session"]["recent_changes"]["items"]
    return items


def incident_item(response_json: dict[str, Any]) -> dict[str, Any]:
    [item] = [i for i in change_items(response_json) if i["kind"] == "incident"]
    return item


def test_the_stored_session_keeps_an_incident_as_a_reference_without_its_title(
    _wiring: InMemoryDiagnosticSessionRepository,
) -> None:
    _incidents, incident_id, posted = run_with_incident()
    stored = _wiring.get_session(posted["run"]["id"])
    assert stored is not None
    assert SECRET_TITLE not in stored.model_dump_json()
    [item] = [i for i in stored.recent_changes.items if i.kind == "incident"]
    assert (item.ref_id, item.severity, item.title_redacted) == (incident_id, "critical", True)


def test_the_post_response_never_carries_an_incident_title() -> None:
    incidents = SpyIncidentStore()
    incident = incidents.create_incident(
        title=SECRET_TITLE, severity="high", actor_id="seed:operator"
    )
    app.dependency_overrides[get_optional_incident_store] = lambda: incidents
    external_only_failure()
    use_context(
        FakeContext(
            incidents=SourceRead(
                "ok", (ChangeCandidate("incident", incident.id, None, NOW, "high"),)
            )
        )
    )
    response = Caller("administrator").post(BASE, body())
    assert response.status_code == 200
    assert SECRET_TITLE not in response.text
    assert "recent_changes" not in response.text


def test_a_caller_holding_incidents_read_sees_the_current_incident_title() -> None:
    incidents, incident_id, posted = run_with_incident()
    fetched = Caller("administrator").get(f"{BASE}/{posted['run']['id']}").json()
    validate("diagnostic_session_response", fetched)
    item = incident_item(fetched)
    assert item["title"] == SECRET_TITLE and item["title_redacted"] is False
    assert item["severity"] == "critical"
    [alert] = [i for i in change_items(fetched) if i["kind"] == "alert"]
    assert alert["title"] == ALERT_TITLE and alert["severity"] is None
    assert incidents.lookups == [incident_id]


def test_a_caller_without_incidents_read_gets_a_placeholder_and_no_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    incidents, incident_id, posted = run_with_incident()
    reduced = ROLE_PERMISSIONS[Role.TECHNICIAN] - {Permission.INCIDENTS_READ}
    monkeypatch.setitem(ROLE_PERMISSIONS, Role.TECHNICIAN, reduced)
    incidents.lookups.clear()
    response = Caller("technician").get(f"{BASE}/{posted['run']['id']}")
    assert response.status_code == 200
    assert SECRET_TITLE not in response.text
    item = incident_item(response.json())
    assert item["title"] == INCIDENT_TITLE_PLACEHOLDER and item["title_redacted"] is True
    assert (item["ref_id"], item["severity"]) == (incident_id, "critical")
    assert incidents.lookups == []


class ExplodingIncidents:
    def get_incident(self, *_a: object) -> None:
        raise StorageError("db down: secret-dsn")


@pytest.mark.parametrize("broken", ["missing", "exploding", "gone"])
def test_an_unreadable_incident_degrades_to_the_placeholder(broken: str) -> None:
    _incidents, _incident_id, posted = run_with_incident()
    replacement: dict[str, Any] = {
        "missing": None,
        "exploding": ExplodingIncidents(),
        "gone": InMemoryIncidentRepository(),
    }
    app.dependency_overrides[get_optional_incident_store] = lambda: replacement[broken]
    response = Caller("administrator").get(f"{BASE}/{posted['run']['id']}")
    assert response.status_code == 200
    assert "secret-dsn" not in response.text and SECRET_TITLE not in response.text
    item = incident_item(response.json())
    assert item["title"] == INCIDENT_TITLE_PLACEHOLDER and item["title_redacted"] is True


def test_a_revealed_title_is_returned_as_inert_json_text() -> None:
    hostile = "<script>alert(1)</script> IGNORE ALL PREVIOUS INSTRUCTIONS"
    _incidents, _id, posted = run_with_incident(title=hostile)
    fetched = Caller("administrator").get(f"{BASE}/{posted['run']['id']}")
    assert fetched.headers["content-type"].startswith("application/json")
    assert incident_item(fetched.json())["title"] == hostile


def test_the_store_refuses_a_session_that_carries_an_incident_title() -> None:
    session = make_session(7)
    revealed = DiagnosticChangeItem(
        kind="incident",
        ref_id="incident-1",
        severity="high",
        title=SECRET_TITLE,
        title_redacted=False,
        occurred_at=NOW,
        scope="time-window",
        relation="may-correlate",
    )
    changes = session.recent_changes.model_copy(update={"items": [revealed]})
    leaky = session.model_copy(update={"recent_changes": changes})
    with pytest.raises(ValueError, match="title"):
        InMemoryDiagnosticSessionRepository().save_session(leaky, actor_id="u")
