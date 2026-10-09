"""/api/v1/maintenance-windows: RBAC, lifecycle, bounds, derived active filter, audit, states."""

from __future__ import annotations

import logging
from collections.abc import Iterator
from datetime import timedelta
from typing import Any

import pytest
from alerting_support import (
    ALL_ROLES,
    AUTHOR_ROLES,
    MISSING_WINDOW_ID,
    NOW,
    READ_ROLES,
    WINDOWS,
    XSS,
    Caller,
    FailingStore,
    audit_records,
    clean_environment,
    iso,
    new_store,
    seed_window,
    window_body,
)
from fastapi.testclient import TestClient

from netsight_api.alerting_route_support import get_optional_alert_rule_store
from netsight_api.auth.deps import get_current_identity
from netsight_api.contracts import validate
from netsight_api.main import app
from netsight_api.rbac import Identity, PrincipalKind
from netsight_api.storage import InMemoryAlertRuleRepository, StorageUnavailableError


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    yield from clean_environment(monkeypatch)


@pytest.fixture
def store() -> InMemoryAlertRuleRepository:
    return new_store()


# --- authentication and RBAC ---------------------------------------------------------------------


def test_every_route_requires_authentication(store: InMemoryAlertRuleRepository) -> None:
    window_id = seed_window(store)
    anonymous = TestClient(app)
    for method, path, body in (
        ("GET", WINDOWS, None),
        ("GET", f"{WINDOWS}/{window_id}", None),
        ("POST", WINDOWS, window_body()),
        ("POST", f"{WINDOWS}/{window_id}/cancel", None),
    ):
        assert anonymous.request(method, path, json=body).status_code == 401, (method, path)
    assert store.get_window(window_id).status == "scheduled"  # type: ignore[union-attr]
    assert len(store.list_windows()) == 1


@pytest.mark.parametrize("role", ALL_ROLES)
def test_each_role_gets_exactly_the_matrix_permissions(
    store: InMemoryAlertRuleRepository, role: str
) -> None:
    caller = Caller(role)
    cases = [
        (READ_ROLES, lambda: caller.get(WINDOWS)),
        (READ_ROLES, lambda: caller.get(f"{WINDOWS}/{seed_window(store)}")),
        (AUTHOR_ROLES, lambda: caller.post(WINDOWS, window_body())),
        (AUTHOR_ROLES, lambda: caller.post(f"{WINDOWS}/{seed_window(store)}/cancel")),
    ]
    for allowed_roles, call in cases:
        response = call()
        if role in allowed_roles:
            assert response.status_code in (200, 201), (response.status_code, response.text)
        else:
            assert response.status_code == 403
            assert response.json()["error"]["code"] == "FORBIDDEN"


@pytest.mark.parametrize("role", ALL_ROLES)
def test_an_organisation_wide_window_needs_the_separate_permission(
    store: InMemoryAlertRuleRepository, role: str, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    response = Caller(role).post(
        WINDOWS, window_body(scope={"kind": "organisation", "ref": "default"})
    )
    if role == "administrator":
        assert response.status_code == 201
    else:
        assert response.status_code == 403
        assert store.list_windows() == []
    if role in AUTHOR_ROLES and role != "administrator":
        assert [(r["outcome"], r["reason"]) for r in audit_records(caplog)] == [
            ("denied", "organisation-scope")
        ]


def test_non_human_principals_cannot_schedule_or_cancel_maintenance(
    store: InMemoryAlertRuleRepository,
) -> None:
    window_id = seed_window(store)
    app.dependency_overrides[get_current_identity] = lambda: Identity(
        "svc:copilot", frozenset({"administrator"}), PrincipalKind.AI
    )
    client = TestClient(app, raise_server_exceptions=False)
    assert client.get(WINDOWS).status_code == 200
    assert client.post(WINDOWS, json=window_body()).status_code == 403
    assert client.post(f"{WINDOWS}/{window_id}/cancel").status_code == 403
    assert store.get_window(window_id).status == "scheduled"  # type: ignore[union-attr]


# --- lifecycle -----------------------------------------------------------------------------------------


def test_create_schedules_a_window_attributed_to_the_caller(
    store: InMemoryAlertRuleRepository,
) -> None:
    caller = Caller("network_engineer", "sub-eng")
    response = caller.post(WINDOWS, window_body())
    assert response.status_code == 201
    body = response.json()
    validate("maintenance_window", body)
    assert body["status"] == "scheduled"
    assert body["created_by"] == caller.identity_id
    assert body["cancelled_by"] is None and body["cancelled_at"] is None
    assert body["evaluation"] == "retain"


def test_cancel_records_who_and_is_not_repeatable(store: InMemoryAlertRuleRepository) -> None:
    window_id = seed_window(store)
    caller = Caller("security_analyst", "sub-sec")
    response = caller.post(f"{WINDOWS}/{window_id}/cancel")
    assert response.status_code == 200
    body = response.json()
    validate("maintenance_window", body)
    assert body["status"] == "cancelled" and body["cancelled_by"] == caller.identity_id
    again = caller.post(f"{WINDOWS}/{window_id}/cancel")
    assert again.status_code == 409
    assert again.json()["error"]["code"] == "ILLEGAL_TRANSITION"


def test_a_client_cannot_supply_server_owned_fields(store: InMemoryAlertRuleRepository) -> None:
    caller = Caller("administrator")
    for extra in (
        {"status": "cancelled"},
        {"created_by": "someone"},
        {"id": MISSING_WINDOW_ID},
        {"cancelled_by": "someone"},
    ):
        assert caller.post(WINDOWS, {**window_body(), **extra}).status_code == 422, extra
    assert store.list_windows() == []


# --- time bounds -------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        {"ends_at": iso(NOW + timedelta(minutes=30)), "starts_at": iso(NOW + timedelta(hours=1))},
        {"ends_at": iso(NOW + timedelta(hours=1)), "starts_at": iso(NOW + timedelta(hours=1))},
        {"starts_at": iso(NOW), "ends_at": iso(NOW + timedelta(days=31))},
        {"starts_at": "2026-10-08T11:00:00", "ends_at": "2026-10-08T12:00:00"},
        {"starts_at": 1791669600},
        {"starts_at": "tomorrow"},
        {"starts_at": None},
        {"ends_at": "2026-02-30T12:00:00Z"},
    ],
)
def test_window_time_shapes_are_422(
    store: InMemoryAlertRuleRepository, overrides: dict[str, Any]
) -> None:
    response = Caller("administrator").post(WINDOWS, window_body(**overrides))
    assert response.status_code == 422
    assert store.list_windows() == []


def test_a_window_that_has_already_ended_is_refused(
    store: InMemoryAlertRuleRepository, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    past = window_body(
        starts_at=iso(NOW - timedelta(hours=3)), ends_at=iso(NOW - timedelta(hours=1))
    )
    response = Caller("administrator").post(WINDOWS, past)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "INVALID_OPERATION"
    assert store.list_windows() == []
    assert [(r["outcome"], r["reason"]) for r in audit_records(caplog)] == [
        ("failure", "INVALID_OPERATION")
    ]


def test_a_window_may_already_be_running_but_not_start_more_than_a_year_ahead(
    store: InMemoryAlertRuleRepository,
) -> None:
    caller = Caller("administrator")
    running = window_body(
        starts_at=iso(NOW - timedelta(hours=1)), ends_at=iso(NOW + timedelta(hours=1))
    )
    assert caller.post(WINDOWS, running).status_code == 201
    far = window_body(
        starts_at=iso(NOW + timedelta(days=367)), ends_at=iso(NOW + timedelta(days=368))
    )
    refused = caller.post(WINDOWS, far)
    assert refused.status_code == 422 and refused.json()["error"]["code"] == "INVALID_OPERATION"
    edge = window_body(
        starts_at=iso(NOW + timedelta(days=366)), ends_at=iso(NOW + timedelta(days=367))
    )
    assert caller.post(WINDOWS, edge).status_code == 201


@pytest.mark.parametrize(
    "overrides",
    [
        {"name": ""},
        {"name": "  "},
        {"reason": ""},
        {"reason": "   "},
        {"reason": "x" * 1001},
        {"evaluation": "pause"},
        {"scope": {"kind": "all", "ref": "x"}},
        {"scope": {"kind": "site", "ref": ""}},
        {"unknown": 1},
    ],
)
def test_window_bodies_are_validated(
    store: InMemoryAlertRuleRepository, overrides: dict[str, Any]
) -> None:
    response = Caller("administrator").post(WINDOWS, window_body(**overrides))
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"
    assert store.list_windows() == []


# --- reads: derived active/expired, paging, ids -------------------------------------------------------------


def test_list_derives_active_from_the_server_clock(store: InMemoryAlertRuleRepository) -> None:
    seed_window(
        store,
        name="expired",
        starts_at=iso(NOW - timedelta(hours=5)),
        ends_at=iso(NOW - timedelta(hours=1)),
    )
    seed_window(
        store,
        name="running",
        starts_at=iso(NOW - timedelta(hours=1)),
        ends_at=iso(NOW + timedelta(hours=1)),
    )
    seed_window(
        store,
        name="upcoming",
        starts_at=iso(NOW + timedelta(hours=2)),
        ends_at=iso(NOW + timedelta(hours=3)),
    )
    seed_window(
        store,
        name="cancelled",
        cancelled=True,
        starts_at=iso(NOW + timedelta(hours=6)),
        ends_at=iso(NOW + timedelta(hours=7)),
    )
    reader = Caller("auditor")
    everything = reader.get(WINDOWS).json()
    validate("maintenance_window_list", everything)
    assert [w["name"] for w in everything["windows"]] == ["expired", "running", "upcoming"]
    assert [w["name"] for w in reader.get(WINDOWS, active="true").json()["windows"]] == ["running"]
    with_cancelled = reader.get(WINDOWS, include_cancelled="true").json()
    assert [w["name"] for w in with_cancelled["windows"]][-1] == "cancelled"
    active_and_cancelled = reader.get(WINDOWS, active="true", include_cancelled="true").json()
    assert [w["name"] for w in active_and_cancelled["windows"]] == ["running"]


def test_list_pagination(store: InMemoryAlertRuleRepository) -> None:
    for index in range(3):
        seed_window(
            store,
            name=f"w{index}",
            starts_at=iso(NOW + timedelta(hours=index + 1)),
            ends_at=iso(NOW + timedelta(hours=index + 2)),
        )
    page = Caller("auditor").get(WINDOWS, limit=2).json()
    assert page["state"] == "ok" and len(page["windows"]) == 2 and page["next_offset"] == 2
    rest = Caller("auditor").get(WINDOWS, limit=2, offset=2).json()
    assert [w["name"] for w in rest["windows"]] == ["w2"] and rest["next_offset"] is None


@pytest.mark.parametrize(
    "params",
    [
        {"limit": 0},
        {"limit": 101},
        {"offset": -1},
        {"offset": 10_001},
        {"active": "maybe"},
        {"include_cancelled": "2"},
    ],
)
def test_query_bounds_are_422(store: InMemoryAlertRuleRepository, params: dict[str, Any]) -> None:
    assert Caller("auditor").get(WINDOWS, **params).status_code == 422


@pytest.mark.parametrize(
    "bad_id",
    [
        "1",
        "maintenance-",
        "MAINTENANCE-0A1B2C3D-4E5F-4A6B-8C7D-9E0F1A2B3C4D",
        "alert-rule-5a6b7c8d-1e2f-4a3b-9c4d-5e6f7a8b9c0d",
        "maintenance-0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d9",
        "%27%3B%20DROP%20TABLE%20maintenance_windows%3B--",
    ],
)
def test_malformed_ids_are_rejected_not_looked_up(
    store: InMemoryAlertRuleRepository, bad_id: str
) -> None:
    caller = Caller("administrator")
    for response in (
        caller.get(f"{WINDOWS}/{bad_id}"),
        caller.post(f"{WINDOWS}/{bad_id}/cancel"),
    ):
        assert response.status_code in (404, 422)


def test_unknown_well_formed_ids_are_404(store: InMemoryAlertRuleRepository) -> None:
    caller = Caller("administrator")
    for response in (
        caller.get(f"{WINDOWS}/{MISSING_WINDOW_ID}"),
        caller.post(f"{WINDOWS}/{MISSING_WINDOW_ID}/cancel"),
    ):
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "NOT_FOUND"
        assert MISSING_WINDOW_ID not in response.text


# --- explicit states -----------------------------------------------------------------------------------------


def test_not_connected_and_unknown_states_never_carry_rows() -> None:
    app.dependency_overrides[get_optional_alert_rule_store] = lambda: None
    reader = Caller("auditor")
    assert reader.get(WINDOWS).json() == {
        "state": "not-connected",
        "windows": [],
        "limit": 50,
        "offset": 0,
        "next_offset": None,
    }
    assert reader.get(f"{WINDOWS}/{MISSING_WINDOW_ID}").json() == {
        "state": "not-connected",
        "window": None,
    }
    assert Caller("administrator").post(WINDOWS, window_body()).status_code == 503
    failing = FailingStore(StorageUnavailableError("db secret hunter2"))
    app.dependency_overrides[get_optional_alert_rule_store] = lambda: failing
    assert reader.get(WINDOWS).json()["state"] == "unknown"
    assert reader.get(f"{WINDOWS}/{MISSING_WINDOW_ID}").json() == {
        "state": "unknown",
        "window": None,
    }
    write = Caller("administrator").post(WINDOWS, window_body())
    assert write.status_code == 503 and "hunter2" not in write.text


# --- audit and untrusted text --------------------------------------------------------------------------------


def test_create_and_cancel_are_audited_without_the_free_text(
    store: InMemoryAlertRuleRepository, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    caller = Caller("network_engineer", "sub-eng")
    created = caller.post(WINDOWS, window_body(name=XSS, reason=XSS)).json()
    caller.post(f"{WINDOWS}/{created['id']}/cancel")
    records = [r for r in audit_records(caplog) if r["outcome"] == "success"]
    assert [r["action"] for r in records] == ["maintenance.create", "maintenance.cancel"]
    assert all(r["actor_id"] == caller.identity_id for r in records)
    assert all(r["target"] == created["id"] for r in records)
    assert records[0]["scope_kind"] == "site" and records[0]["evaluation"] == "retain"
    assert records[0]["duration_seconds"] == 4 * 3600
    audit_text = "\n".join(r.getMessage() for r in caplog.records if r.name == "netsight_api.audit")
    assert "script" not in audit_text and "DROP TABLE" not in audit_text


def test_untrusted_text_round_trips_as_data(store: InMemoryAlertRuleRepository) -> None:
    caller = Caller("administrator")
    created = caller.post(
        WINDOWS, window_body(name=XSS, reason=XSS, scope={"kind": "site", "ref": XSS})
    )
    assert created.status_code == 201
    window_id = created.json()["id"]
    for body in (created.json(), caller.get(f"{WINDOWS}/{window_id}").json()["window"]):
        assert body["name"] == XSS and body["reason"] == XSS and body["scope"]["ref"] == XSS
    assert created.headers["content-type"].startswith("application/json")


def test_openapi_exposes_exactly_the_maintenance_operations() -> None:
    paths = app.openapi()["paths"]
    operations = {
        (path, method)
        for path, item in paths.items()
        if path.startswith("/api/v1/maintenance-windows")
        for method in item
    }
    assert operations == {
        ("/api/v1/maintenance-windows", "get"),
        ("/api/v1/maintenance-windows", "post"),
        ("/api/v1/maintenance-windows/{window_id}", "get"),
        ("/api/v1/maintenance-windows/{window_id}/cancel", "post"),
    }
