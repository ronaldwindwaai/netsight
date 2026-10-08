"""Incident routes (S6-2): RBAC, CSRF, explicit states, state machine, audit, no leaks.

API tests use the in-memory store (same domain rules as PostgreSQL, proven by the
shared conformance suite). Authentication goes through real server-side sessions so
that session/CSRF behaviour is exercised, not bypassed with a dependency override.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient

from netsight_api import incident_routes
from netsight_api.auth.deps import get_current_identity
from netsight_api.auth.rate_limit import RateLimiter
from netsight_api.auth.session import Session, session_manager
from netsight_api.auth.settings import session_policy
from netsight_api.contracts import validate
from netsight_api.incident_routes import get_optional_incident_store
from netsight_api.main import app
from netsight_api.rbac import Identity, PrincipalKind
from netsight_api.storage import (
    IllegalTransitionError,
    InMemoryIncidentRepository,
    InvalidOperationError,
    StorageConflictError,
    StorageUnavailableError,
)

API = "/api/v1/incidents"
XSS = "<script>alert('xss')</script> \" ' ; DROP TABLE incidents; -- \u202e \U0001f525"
MISSING_ID = "incident-00000000-0000-4000-8000-000000000000"
SEED_ACTOR = "seed:operator"
ALL_ROLES = [
    "administrator",
    "network_engineer",
    "security_analyst",
    "technician",
    "management",
    "auditor",
]
FULL_ROLES = ["administrator", "network_engineer", "security_analyst"]


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in (
        "NETSIGHT_ENV",
        "NETSIGHT_ENABLE_DEV_IDENTITY",
        "DATABASE_URL",
        "DATABASE_MIGRATION_URL",
    ):
        monkeypatch.delenv(name, raising=False)
    app.dependency_overrides.clear()
    session_policy.cache_clear()
    monkeypatch.setattr(incident_routes, "_write_limiter", RateLimiter())
    yield
    app.dependency_overrides.clear()
    session_policy.cache_clear()


class TickingClock:
    """Strictly increasing clock anchored at the real now (1s per call): deterministic ordering."""

    def __init__(self) -> None:
        self._current = datetime.now(UTC)

    def __call__(self) -> datetime:
        self._current += timedelta(seconds=1)
        return self._current


@pytest.fixture
def store() -> InMemoryIncidentRepository:
    repository = InMemoryIncidentRepository(clock=TickingClock())
    app.dependency_overrides[get_optional_incident_store] = lambda: repository
    return repository


class Caller:
    """A signed-in browser: session cookie plus the CSRF token the UI would send."""

    def __init__(self, role: str, subject: str = "sub-1") -> None:
        manager = session_manager()
        self.session: Session = manager.create_session(subject, "microsoft", [role])
        self.identity_id = self.session.identity_id
        self.http = TestClient(app, raise_server_exceptions=False)
        self.http.cookies.set(manager.policy.cookie_name, manager.cookie_value(self.session))

    def get(self, path: str, **params: Any) -> Any:
        return self.http.get(path, params=params)

    def post(self, path: str, body: Any = None, *, csrf: str | None = "valid") -> Any:
        headers = {}
        if csrf == "valid":
            headers["X-CSRF-Token"] = self.session.csrf_token
        elif csrf is not None:
            headers["X-CSRF-Token"] = csrf
        return self.http.post(path, json=body, headers=headers)


def seed(
    store: InMemoryIncidentRepository,
    *,
    state: str = "open",
    title: str = "Perimeter outage",
    severity: str = "high",
    assignee: str | None = None,
) -> str:
    incident = store.create_incident(
        title=title,
        severity=severity,
        actor_id=SEED_ACTOR,  # type: ignore[arg-type]
    )
    steps = ["acknowledged", "investigating", "mitigated", "resolved", "closed"]
    for step in steps[: steps.index(state) + 1] if state != "open" else []:
        store.transition_state(
            incident.id,
            to_state=step,  # type: ignore[arg-type]
            actor_id=SEED_ACTOR,
            resolution=_resolution_input() if step == "resolved" else None,
        )
    if assignee is not None and state != "closed":
        store.set_assignee(incident.id, assignee_id=assignee, actor_id=SEED_ACTOR)
    return incident.id


def _resolution_input() -> Any:
    from netsight_api.schemas import IncidentResolutionInput

    return IncidentResolutionInput.model_validate_json(json.dumps(resolve_body()))


def iso(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat().replace("+00:00", "Z")


def resolve_body(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "summary": "Replaced failed uplink optic",
        "root_cause_status": "determined",
        "root_cause": "Failed SFP",
        "impact": "Guest Wi-Fi down 40 minutes",
        "restored_at": iso(datetime.now(UTC) - timedelta(minutes=1)),
        "follow_up_actions": ["Order spare SFPs"],
    }
    body.update(overrides)
    return body


def audit_records(caplog: pytest.LogCaptureFixture) -> list[dict[str, Any]]:
    return [json.loads(r.getMessage()) for r in caplog.records if r.name == "netsight_api.audit"]


# --- routes under test: (name, method, path suffix, body factory) ------------------

WRITE_ROUTES: list[tuple[str, str, Callable[[], Any]]] = [
    ("acknowledge", "/acknowledge", lambda: None),
    ("transition", "/transition", lambda: {"to_state": "acknowledged"}),
    ("assign", "/assign", lambda: {"assignee_id": "microsoft:sub-9"}),
    ("comment", "/comment", lambda: {"message": "Looking now"}),
    ("evidence", "/evidence", lambda: {"evidence_id": "ev-1"}),
    ("resolve", "/resolve", lambda: resolve_body()),
    ("reopen", "/reopen", lambda: {"reason": "Recurred after failover"}),
]
READ_PATHS = ["", "/{id}", "/{id}/timeline"]


# --- authentication ---------------------------------------------------------------


@pytest.mark.parametrize("suffix", READ_PATHS)
def test_reads_require_authentication(store: InMemoryIncidentRepository, suffix: str) -> None:
    incident_id = seed(store)
    response = TestClient(app).get(API + suffix.format(id=incident_id))
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "AUTHENTICATION_REQUIRED"


@pytest.mark.parametrize(("name", "suffix", "body"), WRITE_ROUTES, ids=[r[0] for r in WRITE_ROUTES])
def test_writes_require_authentication(
    store: InMemoryIncidentRepository, name: str, suffix: str, body: Callable[[], Any]
) -> None:
    incident_id = seed(store)
    response = TestClient(app).post(f"{API}/{incident_id}{suffix}", json=body())
    assert response.status_code == 401
    assert store.get_incident(incident_id).state == "open"  # type: ignore[union-attr]


def test_the_dev_identity_bridge_does_not_apply_by_default(
    store: InMemoryIncidentRepository,
) -> None:
    assert TestClient(app).get(API).status_code == 401


# --- authorisation matrix (deny by default) ------------------------------------------


@pytest.mark.parametrize("role", ALL_ROLES)
@pytest.mark.parametrize("suffix", READ_PATHS)
def test_every_role_may_read_incidents(
    store: InMemoryIncidentRepository, role: str, suffix: str
) -> None:
    incident_id = seed(store)
    response = Caller(role).get(API + suffix.format(id=incident_id))
    assert response.status_code == 200


@pytest.mark.parametrize("role", ["technician", "management", "auditor"])
@pytest.mark.parametrize(("name", "suffix", "body"), WRITE_ROUTES, ids=[r[0] for r in WRITE_ROUTES])
def test_roles_without_incident_write_cannot_mutate(
    store: InMemoryIncidentRepository,
    role: str,
    name: str,
    suffix: str,
    body: Callable[[], Any],
) -> None:
    # Technician is only "Assigned": this incident is assigned to somebody else.
    incident_id = seed(store, assignee="microsoft:somebody-else")
    before = store.get_incident(incident_id)
    history = store.list_timeline(incident_id)
    response = Caller(role).post(f"{API}/{incident_id}{suffix}", body())
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"
    assert store.get_incident(incident_id) == before
    assert store.list_timeline(incident_id) == history


@pytest.mark.parametrize("role", FULL_ROLES)
@pytest.mark.parametrize(("name", "suffix", "body"), WRITE_ROUTES, ids=[r[0] for r in WRITE_ROUTES])
def test_full_roles_are_authorised_for_every_write(
    store: InMemoryIncidentRepository,
    role: str,
    name: str,
    suffix: str,
    body: Callable[[], Any],
) -> None:
    incident_id = seed(store)
    response = Caller(role).post(f"{API}/{incident_id}{suffix}", body())
    # Authorised: the outcome is a domain result (resolve/reopen of an open incident is 409).
    assert response.status_code in (200, 201, 409), response.text
    if name in ("resolve", "reopen"):
        assert response.status_code == 409


def test_unknown_role_session_is_denied_everything_but_authentication(
    store: InMemoryIncidentRepository,
) -> None:
    incident_id = seed(store)
    caller = Caller("incident_god")
    assert caller.get(API).status_code == 403
    assert caller.post(f"{API}/{incident_id}/comment", {"message": "x"}).status_code == 403


@pytest.mark.parametrize("kind", [PrincipalKind.SERVICE, PrincipalKind.AI])
@pytest.mark.parametrize("name", ["resolve", "reopen"])
def test_service_and_ai_principals_cannot_record_a_root_cause(
    store: InMemoryIncidentRepository,
    caplog: pytest.LogCaptureFixture,
    kind: PrincipalKind,
    name: str,
) -> None:
    resolved = seed(store, state="resolved")
    mitigated = seed(store, state="mitigated")
    app.dependency_overrides[get_current_identity] = lambda: Identity(
        "svc:copilot", frozenset({"administrator"}), kind
    )
    client = TestClient(app, raise_server_exceptions=False)
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    if name == "resolve":
        response = client.post(f"{API}/{mitigated}/resolve", json=resolve_body())
        assert store.get_incident(mitigated).state == "mitigated"  # type: ignore[union-attr]
    else:
        response = client.post(f"{API}/{resolved}/reopen", json={"reason": "AI says so"})
        assert store.get_incident(resolved).state == "resolved"  # type: ignore[union-attr]
    assert response.status_code == 403
    denied = [r for r in audit_records(caplog) if r["outcome"] == "denied"]
    assert denied and denied[0]["action"] == f"incident.{name}"
    # The same principal may still contribute non-root-cause work its role allows.
    assert (
        client.post(f"{API}/{mitigated}/comment", json={"message": "AI summary"}).status_code == 201
    )


def test_default_identity_without_human_proof_cannot_resolve(
    store: InMemoryIncidentRepository,
) -> None:
    incident_id = seed(store, state="mitigated")
    app.dependency_overrides[get_current_identity] = lambda: Identity(
        "someone", frozenset({"administrator"})
    )
    response = TestClient(app).post(f"{API}/{incident_id}/resolve", json=resolve_body())
    assert response.status_code == 403


# --- technician "assigned" scope ---------------------------------------------------


@pytest.mark.parametrize(
    ("suffix", "body"),
    [
        ("/acknowledge", None),
        ("/transition", {"to_state": "acknowledged"}),
        ("/comment", {"message": "On site"}),
        ("/evidence", {"evidence_id": "ev-7"}),
    ],
)
def test_technician_can_work_incidents_assigned_to_them(
    store: InMemoryIncidentRepository, suffix: str, body: Any
) -> None:
    tech = Caller("technician", "tech-1")
    incident_id = seed(store, assignee=tech.identity_id)
    response = tech.post(f"{API}/{incident_id}{suffix}", body)
    assert response.status_code in (200, 201), response.text


def test_technician_cannot_touch_an_incident_assigned_to_someone_else(
    store: InMemoryIncidentRepository,
) -> None:
    tech = Caller("technician", "tech-1")
    mine = seed(store, assignee=tech.identity_id)
    theirs = seed(store, assignee="microsoft:tech-2")
    unassigned = seed(store)
    for incident_id in (theirs, unassigned):
        response = tech.post(f"{API}/{incident_id}/acknowledge")
        assert response.status_code == 403
        assert store.get_incident(incident_id).state == "open"  # type: ignore[union-attr]
    assert tech.post(f"{API}/{mine}/acknowledge").status_code == 200


def test_technician_cannot_assign_resolve_reopen_or_close_even_when_assigned(
    store: InMemoryIncidentRepository,
) -> None:
    tech = Caller("technician", "tech-1")
    mitigated = seed(store, state="mitigated", assignee=tech.identity_id)
    resolved_unassigned = seed(store, state="resolved")
    assert (
        tech.post(f"{API}/{mitigated}/assign", {"assignee_id": tech.identity_id}).status_code == 403
    )
    assert tech.post(f"{API}/{mitigated}/resolve", resolve_body()).status_code == 403
    assert tech.post(f"{API}/{resolved_unassigned}/reopen", {"reason": "again"}).status_code == 403
    # Closing is a lifecycle decision for the full roles.
    assert tech.post(f"{API}/{mitigated}/transition", {"to_state": "closed"}).status_code == 403
    assert store.get_incident(mitigated).state == "mitigated"  # type: ignore[union-attr]


# --- CSRF ---------------------------------------------------------------------------


@pytest.mark.parametrize("csrf", [None, "", "wrong-token", "valid-but-truncated"])
@pytest.mark.parametrize(("name", "suffix", "body"), WRITE_ROUTES, ids=[r[0] for r in WRITE_ROUTES])
def test_cookie_authenticated_writes_require_the_csrf_token(
    store: InMemoryIncidentRepository,
    name: str,
    suffix: str,
    body: Callable[[], Any],
    csrf: str | None,
) -> None:
    incident_id = seed(store)
    caller = Caller("administrator")
    token = csrf if csrf != "valid-but-truncated" else caller.session.csrf_token[:-1]
    response = caller.post(f"{API}/{incident_id}{suffix}", body(), csrf=token)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "CSRF_VALIDATION_FAILED"
    assert store.get_incident(incident_id).state == "open"  # type: ignore[union-attr]
    assert len(store.list_timeline(incident_id)) == 0


def test_csrf_failure_is_audited_and_does_not_echo_the_token(
    store: InMemoryIncidentRepository, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)
    incident_id = seed(store)
    caller = Caller("administrator")
    caller.post(f"{API}/{incident_id}/acknowledge", csrf="attacker-supplied-token")
    records = audit_records(caplog)
    assert [r["outcome"] for r in records] == ["denied"]
    assert records[0]["reason"] == "csrf"
    assert "attacker-supplied-token" not in caplog.text
    assert caller.session.csrf_token not in caplog.text


def test_reads_do_not_need_a_csrf_token(store: InMemoryIncidentRepository) -> None:
    assert Caller("auditor").get(API).status_code == 200


# --- list ---------------------------------------------------------------------------


def test_list_without_a_store_reports_not_connected(monkeypatch: pytest.MonkeyPatch) -> None:
    # No override: the real dependency with DATABASE_URL unset.
    response = Caller("auditor").get(API)
    assert response.status_code == 200
    body = response.json()
    assert body == {
        "state": "not-connected",
        "incidents": [],
        "limit": 50,
        "offset": 0,
        "next_offset": None,
    }
    validate("incident_list", body)


def test_migration_credentials_are_never_used_at_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DATABASE_MIGRATION_URL", "postgresql://owner:ownerpw@127.0.0.1:1/x")
    assert get_optional_incident_store() is None
    assert Caller("auditor").get(API).json()["state"] == "not-connected"


def test_list_returns_newest_first_and_validates_against_the_canonical_contract(
    store: InMemoryIncidentRepository,
) -> None:
    first = seed(store, title="first")
    second = seed(store, title="second", severity="low")
    body = Caller("auditor").get(API).json()
    assert body["state"] == "ok"
    assert [i["id"] for i in body["incidents"]] == [second, first]
    assert (body["limit"], body["offset"], body["next_offset"]) == (50, 0, None)
    validate("incident_list", body)


def test_list_filters_by_state_severity_and_assignee(store: InMemoryIncidentRepository) -> None:
    a = seed(store, severity="low")
    b = seed(store, severity="high", state="acknowledged", assignee="microsoft:sub-9")
    c = seed(store, severity="high")
    caller = Caller("management")

    def ids(**params: Any) -> list[str]:
        return [i["id"] for i in caller.get(API, **params).json()["incidents"]]

    assert ids(state="acknowledged") == [b]
    assert ids(severity="high") == [c, b]
    assert ids(severity="low") == [a]
    assert ids(assignee_id="microsoft:sub-9") == [b]
    assert ids(severity="high", state="open") == [c]
    assert ids(assignee_id="x' OR '1'='1") == []


def test_list_pages_with_a_bounded_limit_and_next_offset(
    store: InMemoryIncidentRepository,
) -> None:
    created = [seed(store, title=f"inc {n}") for n in range(5)]
    caller = Caller("auditor")
    page1 = caller.get(API, limit=2).json()
    assert [i["id"] for i in page1["incidents"]] == created[::-1][:2]
    assert (page1["limit"], page1["offset"], page1["next_offset"]) == (2, 0, 2)
    page3 = caller.get(API, limit=2, offset=4).json()
    assert len(page3["incidents"]) == 1
    assert page3["next_offset"] is None
    validate("incident_list", page1)
    validate("incident_list", page3)


@pytest.mark.parametrize(
    "params",
    [
        {"limit": 0},
        {"limit": 101},
        {"limit": -5},
        {"limit": "abc"},
        {"offset": -1},
        {"offset": 10_001},
        {"state": "exploded"},
        {"severity": "catastrophic"},
        {"assignee_id": "a" * 256},
        {"assignee_id": ""},
    ],
)
def test_list_rejects_out_of_bounds_queries_with_422(
    store: InMemoryIncidentRepository, params: dict[str, Any]
) -> None:
    response = Caller("auditor").get(API, **params)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_list_accepts_the_maximum_bounds(store: InMemoryIncidentRepository) -> None:
    response = Caller("auditor").get(API, limit=100, offset=10_000)
    assert response.status_code == 200
    assert response.json()["incidents"] == []


# --- explicit unknown state on store failure (no 500, no leak) ---------------------


class ExplodingStore(InMemoryIncidentRepository):
    def __init__(self, error: Exception) -> None:
        super().__init__(clock=TickingClock())
        self.error = error

    def list_incidents(self, **_: Any) -> Any:
        raise self.error

    def get_incident(self, incident_id: str) -> Any:
        raise self.error

    def list_timeline(self, incident_id: str, **_: Any) -> Any:
        raise self.error

    def transition_state(self, incident_id: str, **_: Any) -> Any:
        raise self.error

    def set_assignee(self, incident_id: str, **_: Any) -> Any:
        raise self.error

    def append_event(self, incident_id: str, **_: Any) -> Any:
        raise self.error

    def add_evidence(self, incident_id: str, **_: Any) -> Any:
        raise self.error


LEAKY = "connection to postgresql://netsight_app:hunter2-secret@db.internal:5432/ns failed"


@pytest.mark.parametrize(
    "error",
    [StorageUnavailableError(LEAKY), RuntimeError(LEAKY), ValueError(LEAKY)],
    ids=lambda e: type(e).__name__,
)
def test_read_store_failure_degrades_to_unknown_without_leaking(
    error: Exception, caplog: pytest.LogCaptureFixture
) -> None:
    app.dependency_overrides[get_optional_incident_store] = lambda: ExplodingStore(error)
    caller = Caller("auditor")
    caplog.set_level(logging.DEBUG)
    for path, key in [(API, "incidents"), (f"{API}/{MISSING_ID}/timeline", "events")]:
        response = caller.get(path)
        assert response.status_code == 200
        body = response.json()
        assert body["state"] == "unknown"
        assert body[key] == []
        assert "hunter2" not in response.text
    detail = caller.get(f"{API}/{MISSING_ID}")
    assert detail.status_code == 200
    assert detail.json() == {"state": "unknown", "incident": None}
    assert "hunter2" not in caplog.text
    assert "db.internal" not in caplog.text


def test_unreachable_database_degrades_to_unknown_and_never_leaks_the_dsn(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    dsn = "postgresql://netsight_app:hunter2-secret@127.0.0.1:1/netsight"
    monkeypatch.setenv("DATABASE_URL", dsn)
    caplog.set_level(logging.DEBUG)
    caller = Caller("administrator")
    response = caller.get(API)
    assert response.status_code == 200
    assert response.json()["state"] == "unknown"
    write = caller.post(f"{API}/{MISSING_ID}/acknowledge")
    assert write.status_code == 503
    assert write.json()["error"]["code"] == "STORE_UNAVAILABLE"
    for text in (response.text, write.text, caplog.text):
        assert "hunter2" not in text
        assert dsn not in text


def test_misconfigured_database_url_is_unknown_not_a_crash(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("DATABASE_URL", "mysql://root:hunter2-secret@db/x")
    caplog.set_level(logging.DEBUG)
    caller = Caller("administrator")
    assert caller.get(API).json()["state"] == "unknown"
    assert caller.post(f"{API}/{MISSING_ID}/acknowledge").status_code == 503
    assert "hunter2" not in caplog.text


# --- detail and timeline -------------------------------------------------------------


def test_detail_returns_the_incident(store: InMemoryIncidentRepository) -> None:
    incident_id = seed(store, state="mitigated", assignee="microsoft:sub-9")
    body = Caller("auditor").get(f"{API}/{incident_id}").json()
    assert body["state"] == "ok"
    assert body["incident"]["id"] == incident_id
    assert body["incident"]["assignee_id"] == "microsoft:sub-9"
    validate("incident_detail", body)


def test_detail_not_connected_and_unknown_id(store: InMemoryIncidentRepository) -> None:
    caller = Caller("auditor")
    missing = caller.get(f"{API}/{MISSING_ID}")
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "NOT_FOUND"
    app.dependency_overrides[get_optional_incident_store] = lambda: None
    disconnected = caller.get(f"{API}/{MISSING_ID}")
    assert disconnected.status_code == 200
    assert disconnected.json() == {"state": "not-connected", "incident": None}


@pytest.mark.parametrize(
    "bad_id",
    [
        "1",
        "incident-1",
        "incident-" + "A" * 36,
        "incident-00000000-0000-4000-8000-00000000000G",
        "incident-00000000-0000-4000-8000-000000000000 ",
        "device-00000000-0000-4000-8000-000000000000",
        "incident-00000000-0000-4000-8000-000000000000" + "0" * 50,
        "%27%20OR%201=1--",
        "..%2f..%2fetc%2fpasswd",
    ],
)
@pytest.mark.parametrize("suffix", ["", "/timeline"])
def test_malformed_incident_ids_are_rejected_before_any_lookup(
    store: InMemoryIncidentRepository, bad_id: str, suffix: str
) -> None:
    response = Caller("auditor").get(f"{API}/{bad_id}{suffix}")
    assert response.status_code in (404, 422)
    assert "traceback" not in response.text.lower()


@pytest.mark.parametrize("suffix", ["/acknowledge", "/comment"])
def test_malformed_ids_on_writes_do_not_reach_the_store(
    store: InMemoryIncidentRepository, suffix: str
) -> None:
    response = Caller("administrator").post(f"{API}/not-an-id{suffix}", {"message": "x"})
    assert response.status_code in (404, 422)


def test_timeline_is_ordered_bounded_and_pageable(store: InMemoryIncidentRepository) -> None:
    incident_id = seed(store, state="investigating")
    for n in range(3):
        store.append_event(incident_id, kind="comment", actor_id=SEED_ACTOR, message=f"note {n}")
    caller = Caller("auditor")
    full = caller.get(f"{API}/{incident_id}/timeline").json()
    assert full["state"] == "ok"
    assert full["incident_id"] == incident_id
    assert [e["seq"] for e in full["events"]] == [1, 2, 3, 4, 5]
    assert full["next_after_seq"] is None
    validate("incident_timeline", full)
    page = caller.get(f"{API}/{incident_id}/timeline", limit=2, after_seq=1).json()
    assert [e["seq"] for e in page["events"]] == [2, 3]
    assert (page["after_seq"], page["next_after_seq"]) == (1, 3)
    validate("incident_timeline", page)


@pytest.mark.parametrize(
    "params",
    [{"limit": 0}, {"limit": 501}, {"after_seq": -1}, {"after_seq": 1_000_001}, {"limit": "x"}],
)
def test_timeline_rejects_out_of_bounds_queries(
    store: InMemoryIncidentRepository, params: dict[str, Any]
) -> None:
    incident_id = seed(store)
    assert Caller("auditor").get(f"{API}/{incident_id}/timeline", **params).status_code == 422


def test_timeline_unknown_incident_and_not_connected(store: InMemoryIncidentRepository) -> None:
    caller = Caller("auditor")
    assert caller.get(f"{API}/{MISSING_ID}/timeline").status_code == 404
    app.dependency_overrides[get_optional_incident_store] = lambda: None
    body = caller.get(f"{API}/{MISSING_ID}/timeline").json()
    assert body == {
        "state": "not-connected",
        "incident_id": MISSING_ID,
        "events": [],
        "after_seq": 0,
        "next_after_seq": None,
    }
    validate("incident_timeline", body)


# --- acknowledge / transition --------------------------------------------------------


def test_acknowledge_moves_open_to_acknowledged_and_records_the_actor(
    store: InMemoryIncidentRepository,
) -> None:
    incident_id = seed(store)
    caller = Caller("network_engineer", "ne-1")
    response = caller.post(f"{API}/{incident_id}/acknowledge")
    assert response.status_code == 200
    body = response.json()
    assert body["state"] == "acknowledged"
    validate("incident", body)
    [event] = store.list_timeline(incident_id)
    assert (event.kind, event.state_from, event.state_to) == (
        "state-changed",
        "open",
        "acknowledged",
    )
    assert event.actor_id == caller.identity_id


def test_a_second_acknowledge_is_a_409_state_conflict(
    store: InMemoryIncidentRepository,
) -> None:
    incident_id = seed(store)
    first, second = Caller("administrator", "a1"), Caller("security_analyst", "a2")
    assert first.post(f"{API}/{incident_id}/acknowledge").status_code == 200
    lost = second.post(f"{API}/{incident_id}/acknowledge")
    assert lost.status_code == 409
    assert lost.json()["error"]["code"] == "ILLEGAL_TRANSITION"
    assert len(store.list_timeline(incident_id)) == 1


def test_transition_follows_the_state_machine(store: InMemoryIncidentRepository) -> None:
    incident_id = seed(store, state="acknowledged")
    caller = Caller("administrator")
    skip = caller.post(f"{API}/{incident_id}/transition", {"to_state": "mitigated"})
    assert skip.status_code == 409
    for target in ("investigating", "mitigated"):
        step = caller.post(f"{API}/{incident_id}/transition", {"to_state": target, "reason": "ok"})
        assert step.status_code == 200
        assert step.json()["state"] == target
    backwards = caller.post(f"{API}/{incident_id}/transition", {"to_state": "investigating"})
    assert backwards.status_code == 409


def test_closing_requires_a_resolved_incident(store: InMemoryIncidentRepository) -> None:
    caller = Caller("administrator")
    early = seed(store, state="mitigated")
    assert caller.post(f"{API}/{early}/transition", {"to_state": "closed"}).status_code == 409
    done = seed(store, state="resolved")
    closed = caller.post(f"{API}/{done}/transition", {"to_state": "closed"})
    assert closed.status_code == 200
    assert closed.json()["state"] == "closed"
    assert closed.json()["resolution"] is not None


@pytest.mark.parametrize(
    "body",
    [
        {"to_state": "resolved"},
        {"to_state": "open"},
        {"to_state": "nonsense"},
        {"to_state": None},
        {},
        {"to_state": "acknowledged", "unexpected": 1},
        {"to_state": "acknowledged", "reason": "x" * 1001},
    ],
)
def test_transition_rejects_resolve_reopen_and_malformed_bodies(
    store: InMemoryIncidentRepository, body: dict[str, Any]
) -> None:
    incident_id = seed(store)
    response = Caller("administrator").post(f"{API}/{incident_id}/transition", body)
    assert response.status_code == 422
    assert store.get_incident(incident_id).state == "open"  # type: ignore[union-attr]


def test_unknown_incident_on_write_is_404(store: InMemoryIncidentRepository) -> None:
    assert Caller("administrator").post(f"{API}/{MISSING_ID}/acknowledge").status_code == 404


# --- assign --------------------------------------------------------------------------


def test_assign_sets_and_clears_the_assignee_and_audits_the_timeline(
    store: InMemoryIncidentRepository,
) -> None:
    incident_id = seed(store)
    caller = Caller("security_analyst")
    assigned = caller.post(f"{API}/{incident_id}/assign", {"assignee_id": "microsoft:sub-9"})
    assert assigned.status_code == 200
    assert assigned.json()["assignee_id"] == "microsoft:sub-9"
    cleared = caller.post(f"{API}/{incident_id}/assign", {"assignee_id": None})
    assert cleared.json()["assignee_id"] is None
    kinds = [(e.kind, e.subject_id) for e in store.list_timeline(incident_id)]
    assert kinds == [("assignee-changed", "microsoft:sub-9"), ("assignee-changed", None)]


@pytest.mark.parametrize(
    "body", [{}, {"assignee_id": ""}, {"assignee_id": "a" * 256}, {"assignee_id": 5}, {"x": 1}]
)
def test_assign_rejects_malformed_bodies(
    store: InMemoryIncidentRepository, body: dict[str, Any]
) -> None:
    incident_id = seed(store)
    assert Caller("administrator").post(f"{API}/{incident_id}/assign", body).status_code == 422


def test_closed_incidents_reject_assignment_comments_and_evidence(
    store: InMemoryIncidentRepository,
) -> None:
    incident_id = seed(store, state="closed")
    caller = Caller("administrator")
    for suffix, body in [
        ("/assign", {"assignee_id": "microsoft:sub-9"}),
        ("/comment", {"message": "late"}),
        ("/evidence", {"evidence_id": "ev-1"}),
        ("/acknowledge", None),
    ]:
        assert caller.post(f"{API}/{incident_id}{suffix}", body).status_code == 409, suffix


# --- comment (untrusted text) -----------------------------------------------------------


def test_comment_is_appended_and_untrusted_text_passes_through_as_data(
    store: InMemoryIncidentRepository,
) -> None:
    incident_id = seed(store, title=XSS)
    caller = Caller("security_analyst")
    response = caller.post(f"{API}/{incident_id}/comment", {"message": XSS})
    assert response.status_code == 201
    event = response.json()
    assert event["message"] == XSS.strip()
    assert event["kind"] == "comment"
    validate("incident_timeline_event", event)
    assert response.headers["content-type"].startswith("application/json")
    timeline = caller.get(f"{API}/{incident_id}/timeline").json()["events"]
    assert timeline[-1]["message"] == XSS.strip()
    detail = caller.get(f"{API}/{incident_id}").json()
    assert detail["incident"]["title"] == XSS  # stored and returned verbatim, never interpreted


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"message": ""},
        {"message": "   "},
        {"message": "x" * 4001},
        {"message": 7},
        {"message": "a", "kind": "resolution"},
    ],
)
def test_comment_rejects_malformed_bodies(
    store: InMemoryIncidentRepository, body: dict[str, Any]
) -> None:
    incident_id = seed(store)
    response = Caller("administrator").post(f"{API}/{incident_id}/comment", body)
    assert response.status_code == 422
    assert store.list_timeline(incident_id) == []


def test_comment_accepts_the_maximum_length(store: InMemoryIncidentRepository) -> None:
    incident_id = seed(store)
    response = Caller("administrator").post(f"{API}/{incident_id}/comment", {"message": "x" * 4000})
    assert response.status_code == 201


# --- evidence --------------------------------------------------------------------------


def test_evidence_is_added_once_and_is_idempotent(store: InMemoryIncidentRepository) -> None:
    incident_id = seed(store)
    caller = Caller("network_engineer")
    first = caller.post(f"{API}/{incident_id}/evidence", {"evidence_id": "ev-<b>1</b>"})
    again = caller.post(f"{API}/{incident_id}/evidence", {"evidence_id": "ev-<b>1</b>"})
    assert first.status_code == again.status_code == 200
    assert again.json()["evidence_ids"] == ["ev-<b>1</b>"]
    assert [e.kind for e in store.list_timeline(incident_id)] == ["evidence-added"]


@pytest.mark.parametrize(
    "body", [{}, {"evidence_id": ""}, {"evidence_id": "e" * 129}, {"evidence_id": None}]
)
def test_evidence_rejects_malformed_bodies(
    store: InMemoryIncidentRepository, body: dict[str, Any]
) -> None:
    incident_id = seed(store)
    assert Caller("administrator").post(f"{API}/{incident_id}/evidence", body).status_code == 422


# --- resolve -----------------------------------------------------------------------------


def test_resolve_records_the_resolution_with_the_authenticated_human(
    store: InMemoryIncidentRepository,
) -> None:
    incident_id = seed(store, state="mitigated")
    caller = Caller("network_engineer", "ne-1")
    response = caller.post(f"{API}/{incident_id}/resolve", resolve_body())
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["state"] == "resolved"
    assert body["resolution"]["resolved_by"] == caller.identity_id
    assert body["resolution"]["root_cause"] == "Failed SFP"
    validate("incident", body)
    kinds = [e.kind for e in store.list_timeline(incident_id)][-2:]
    assert kinds == ["state-changed", "resolution"]


def test_resolve_accepts_not_determined_without_a_root_cause(
    store: InMemoryIncidentRepository,
) -> None:
    incident_id = seed(store, state="mitigated")
    response = Caller("administrator").post(
        f"{API}/{incident_id}/resolve",
        resolve_body(root_cause_status="not-determined", root_cause=None),
    )
    assert response.status_code == 200
    assert response.json()["resolution"]["root_cause_status"] == "not-determined"
    assert response.json()["resolution"]["root_cause"] is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"summary": ""},
        {"summary": "   "},
        {"summary": "x" * 2001},
        {"impact": ""},
        {"root_cause_status": "maybe"},
        {"root_cause_status": "determined", "root_cause": None},
        {"root_cause_status": "not-determined", "root_cause": "Failed SFP"},
        {"root_cause": ""},
        {"restored_at": "yesterday"},
        {"restored_at": "2026-10-08T07:30:00"},  # no timezone
        {"restored_at": iso(datetime.now(UTC) + timedelta(hours=1))},  # restored in the future
        {"follow_up_actions": ["x"] * 33},
        {"follow_up_actions": [""]},
        {"follow_up_actions": "none"},
        {"unexpected": True},
    ],
)
def test_resolve_enforces_the_resolution_requirements(
    store: InMemoryIncidentRepository, overrides: dict[str, Any]
) -> None:
    incident_id = seed(store, state="mitigated")
    response = Caller("administrator").post(
        f"{API}/{incident_id}/resolve", resolve_body(**overrides)
    )
    assert response.status_code == 422, response.text
    assert store.get_incident(incident_id).state == "mitigated"  # type: ignore[union-attr]


@pytest.mark.parametrize(
    "missing",
    ["summary", "root_cause_status", "root_cause", "impact", "restored_at", "follow_up_actions"],
)
def test_resolve_requires_every_field(store: InMemoryIncidentRepository, missing: str) -> None:
    incident_id = seed(store, state="mitigated")
    body = resolve_body()
    del body[missing]
    assert Caller("administrator").post(f"{API}/{incident_id}/resolve", body).status_code == 422


def test_resolve_from_the_wrong_state_is_a_409(store: InMemoryIncidentRepository) -> None:
    caller = Caller("administrator")
    for state in ("open", "acknowledged", "investigating", "resolved", "closed"):
        incident_id = seed(store, state=state)
        assert caller.post(f"{API}/{incident_id}/resolve", resolve_body()).status_code == 409, state


# --- reopen -----------------------------------------------------------------------------------


@pytest.mark.parametrize("state", ["resolved", "closed"])
def test_reopen_requires_a_reason_and_returns_to_open(
    store: InMemoryIncidentRepository, state: str
) -> None:
    incident_id = seed(store, state=state)
    caller = Caller("security_analyst")
    response = caller.post(
        f"{API}/{incident_id}/reopen", {"reason": "Recurred <b>after</b> failover"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["state"] == "open"
    assert body["resolution"] is None
    last = store.list_timeline(incident_id)[-1]
    assert (last.state_to, last.reason) == ("open", "Recurred <b>after</b> failover")
    assert last.actor_id == caller.identity_id


@pytest.mark.parametrize(
    "body", [{}, {"reason": ""}, {"reason": "   "}, {"reason": "r" * 1001}, {"reason": None}]
)
def test_reopen_without_a_valid_reason_is_rejected(
    store: InMemoryIncidentRepository, body: dict[str, Any]
) -> None:
    incident_id = seed(store, state="resolved")
    assert Caller("administrator").post(f"{API}/{incident_id}/reopen", body).status_code == 422
    assert store.get_incident(incident_id).state == "resolved"  # type: ignore[union-attr]


@pytest.mark.parametrize("state", ["open", "acknowledged", "investigating", "mitigated"])
def test_reopen_of_an_unresolved_incident_is_a_409(
    store: InMemoryIncidentRepository, state: str
) -> None:
    incident_id = seed(store, state=state)
    response = Caller("administrator").post(f"{API}/{incident_id}/reopen", {"reason": "again"})
    assert response.status_code == 409


# --- audit ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("action", "setup_state", "suffix", "body"),
    [
        ("incident.acknowledge", "open", "/acknowledge", None),
        ("incident.transition", "acknowledged", "/transition", {"to_state": "investigating"}),
        ("incident.assign", "open", "/assign", {"assignee_id": "microsoft:sub-9"}),
        ("incident.comment", "open", "/comment", {"message": XSS}),
        ("incident.evidence", "open", "/evidence", {"evidence_id": "ev-1"}),
        ("incident.resolve", "mitigated", "/resolve", resolve_body()),
        ("incident.reopen", "resolved", "/reopen", {"reason": XSS}),
    ],
)
def test_every_successful_mutation_emits_one_audit_event(
    store: InMemoryIncidentRepository,
    caplog: pytest.LogCaptureFixture,
    action: str,
    setup_state: str,
    suffix: str,
    body: Any,
) -> None:
    incident_id = seed(store, state=setup_state)
    caller = Caller("administrator", "audit-me")
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    response = caller.http.post(
        f"{API}/{incident_id}{suffix}",
        json=body,
        headers={"X-CSRF-Token": caller.session.csrf_token, "X-Correlation-ID": "corr-123"},
    )
    assert response.status_code in (200, 201)
    [record] = audit_records(caplog)
    assert record["action"] == action
    assert record["outcome"] == "success"
    assert record["actor_id"] == caller.identity_id
    assert record["target"] == incident_id
    assert record["correlation_id"] == "corr-123"
    # Free text and tokens never reach the audit log.
    assert "script" not in caplog.text
    assert "Failed SFP" not in caplog.text
    assert caller.session.csrf_token not in caplog.text


def test_failed_and_denied_mutations_are_audited_with_a_reason_code(
    store: InMemoryIncidentRepository, caplog: pytest.LogCaptureFixture
) -> None:
    incident_id = seed(store)
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    Caller("administrator").post(f"{API}/{incident_id}/resolve", resolve_body())  # 409
    Caller("auditor").post(f"{API}/{incident_id}/comment", {"message": "x"})  # 403
    Caller("administrator").post(f"{API}/{MISSING_ID}/acknowledge")  # 404
    outcomes = [(r["action"], r["outcome"], r.get("reason")) for r in audit_records(caplog)]
    assert outcomes == [
        ("incident.resolve", "failure", "ILLEGAL_TRANSITION"),
        ("incident.comment", "denied", "permission"),
        ("incident.acknowledge", "failure", "NOT_FOUND"),
    ]


def test_reads_are_not_audited_as_mutations(
    store: InMemoryIncidentRepository, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    Caller("auditor").get(API)
    assert audit_records(caplog) == []


# --- write failure mapping -------------------------------------------------------------------------


def test_writes_without_a_store_are_an_explicit_503_not_connected(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app.dependency_overrides[get_optional_incident_store] = lambda: None
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    response = Caller("administrator").post(f"{API}/{MISSING_ID}/acknowledge")
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "STORE_NOT_CONNECTED"
    assert [r["outcome"] for r in audit_records(caplog)] == ["failure"]


@pytest.mark.parametrize(
    ("error", "status", "code"),
    [
        (StorageConflictError(LEAKY), 409, "CONFLICT"),
        (StorageUnavailableError(LEAKY), 503, "STORE_UNAVAILABLE"),
        (
            InvalidOperationError("reason must be 1 to 1000 non-blank characters"),
            422,
            "INVALID_OPERATION",
        ),
        (
            IllegalTransitionError("cannot move an incident from open to closed"),
            409,
            "ILLEGAL_TRANSITION",
        ),
        (ValueError(LEAKY), 500, "INTERNAL_ERROR"),  # only pydantic errors are client errors
        (RuntimeError(LEAKY), 500, "INTERNAL_ERROR"),
    ],
    ids=lambda v: type(v).__name__ if isinstance(v, Exception) else None,
)
def test_store_errors_map_to_statuses_without_leaking(
    error: Exception,
    status: int,
    code: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    app.dependency_overrides[get_optional_incident_store] = lambda: ExplodingStore(error)
    caplog.set_level(logging.DEBUG)
    response = Caller("administrator").post(f"{API}/{MISSING_ID}/acknowledge")
    assert response.status_code == status
    assert response.json()["error"]["code"] == code
    assert response.json()["error"]["correlation_id"]
    assert "hunter2" not in response.text
    assert "hunter2" not in caplog.text


# --- OpenAPI ---------------------------------------------------------------------------------------------


EXPECTED_OPERATIONS = {
    ("get", "/api/v1/incidents"),
    ("get", "/api/v1/incidents/{incident_id}"),
    ("get", "/api/v1/incidents/{incident_id}/timeline"),
    ("post", "/api/v1/incidents/{incident_id}/acknowledge"),
    ("post", "/api/v1/incidents/{incident_id}/transition"),
    ("post", "/api/v1/incidents/{incident_id}/assign"),
    ("post", "/api/v1/incidents/{incident_id}/comment"),
    ("post", "/api/v1/incidents/{incident_id}/evidence"),
    ("post", "/api/v1/incidents/{incident_id}/resolve"),
    ("post", "/api/v1/incidents/{incident_id}/reopen"),
}


def test_openapi_exposes_exactly_the_incident_operations() -> None:
    paths = app.openapi()["paths"]
    found = {
        (method, path)
        for path, operations in paths.items()
        if path.startswith("/api/v1/incidents")
        for method in operations
    }
    assert found == EXPECTED_OPERATIONS


def test_openapi_documents_error_responses_for_writes() -> None:
    operation = app.openapi()["paths"]["/api/v1/incidents/{incident_id}/resolve"]["post"]
    assert {"200", "401", "403", "404", "409", "422", "503"} <= set(operation["responses"])


# --- end-to-end flow ---------------------------------------------------------------------------------------


def test_full_lifecycle_flow(store: InMemoryIncidentRepository) -> None:
    incident_id = seed(store)
    lead = Caller("network_engineer", "lead")
    for step in ("acknowledged", "investigating", "mitigated"):
        assert lead.post(f"{API}/{incident_id}/transition", {"to_state": step}).status_code == 200
    assert (
        lead.post(f"{API}/{incident_id}/comment", {"message": "Failover done"}).status_code == 201
    )
    assert lead.post(f"{API}/{incident_id}/resolve", resolve_body()).status_code == 200
    assert lead.post(f"{API}/{incident_id}/transition", {"to_state": "closed"}).status_code == 200
    assert lead.post(f"{API}/{incident_id}/reopen", {"reason": "Regression"}).status_code == 200
    timeline = lead.get(f"{API}/{incident_id}/timeline").json()["events"]
    assert [e["seq"] for e in timeline] == list(range(1, len(timeline) + 1))
    assert all(e["actor_id"] == lead.identity_id for e in timeline)


# --- write rate limit ------------------------------------------------------------------------------------


def test_writes_are_rate_limited_per_identity(
    store: InMemoryIncidentRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(incident_routes, "WRITE_LIMIT_PER_MINUTE", 3)
    incident_id = seed(store)
    busy, other = Caller("administrator", "busy"), Caller("administrator", "other")
    statuses = [
        busy.post(f"{API}/{incident_id}/comment", {"message": "n"}).status_code for _ in range(5)
    ]
    assert statuses == [201, 201, 201, 429, 429]
    assert (
        busy.post(f"{API}/{incident_id}/comment", {"message": "n"}).json()["error"]["code"]
        == "RATE_LIMITED"
    )
    assert other.post(f"{API}/{incident_id}/comment", {"message": "n"}).status_code == 201
    assert busy.get(API).status_code == 200  # reads are not write-limited
    assert len(store.list_timeline(incident_id)) == 4


def test_forged_cross_site_writes_do_not_consume_the_victims_rate_budget(
    store: InMemoryIncidentRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(incident_routes, "WRITE_LIMIT_PER_MINUTE", 2)
    incident_id = seed(store)
    victim = Caller("administrator", "victim")
    for _ in range(5):
        forged = victim.post(f"{API}/{incident_id}/comment", {"message": "x"}, csrf="forged")
        assert forged.status_code == 403
    assert victim.post(f"{API}/{incident_id}/comment", {"message": "real"}).status_code == 201
