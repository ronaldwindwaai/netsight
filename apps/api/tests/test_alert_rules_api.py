"""/api/v1/alert-rules: RBAC per role, lifecycle, approval bound to a version, validation bounds,
explicit states, audit, XSS passthrough and secret non-leak (S6-3)."""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from alerting_support import (  # noqa: F401  (fixtures)
    ALL_ROLES,
    APPROVER_ROLES,
    AUTHOR_ROLES,
    MISSING_RULE_ID,
    READ_ROLES,
    RULES,
    SEED_ACTOR,
    XSS,
    Caller,
    FailingStore,
    audit_records,
    clean_environment,
    evaluate_body,
    new_store,
    rule_body,
    seed_rule,
)
from fastapi.testclient import TestClient

from netsight_api import alerting_route_support
from netsight_api.alerting_route_support import get_optional_alert_rule_store
from netsight_api.auth.deps import get_current_identity
from netsight_api.contracts import validate
from netsight_api.main import app
from netsight_api.rbac import Identity, PrincipalKind
from netsight_api.storage import (
    InMemoryAlertRuleRepository,
    StorageConflictError,
    StorageUnavailableError,
)


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    yield from clean_environment(monkeypatch)


@pytest.fixture
def store() -> InMemoryAlertRuleRepository:
    return new_store()


def _provide(repository: InMemoryAlertRuleRepository) -> Callable[[], InMemoryAlertRuleRepository]:
    return lambda: repository


# --- authentication ------------------------------------------------------------------------------


def all_rule_routes(rule_id: str) -> list[tuple[str, str, Any]]:
    return [
        ("GET", RULES, None),
        ("GET", f"{RULES}/{rule_id}", None),
        ("POST", RULES, rule_body()),
        ("PUT", f"{RULES}/{rule_id}", {"expected_version": 1, "definition": rule_body()}),
        ("POST", f"{RULES}/{rule_id}/approve", {"expected_version": 1}),
        ("POST", f"{RULES}/{rule_id}/disable", None),
        ("POST", f"{RULES}/evaluate", evaluate_body()),
    ]


def test_every_route_requires_authentication(store: InMemoryAlertRuleRepository) -> None:
    rule_id, _ = seed_rule(store)
    anonymous = TestClient(app)
    for method, path, body in all_rule_routes(rule_id):
        response = anonymous.request(method, path, json=body)
        assert response.status_code == 401, (method, path)
        assert response.json()["error"]["code"] == "AUTHENTICATION_REQUIRED"
    assert store.get_rule(rule_id).status == "draft"  # type: ignore[union-attr]
    assert len(store.list_rules()) == 1


def test_the_dev_identity_bridge_does_not_apply_by_default(
    store: InMemoryAlertRuleRepository,
) -> None:
    assert TestClient(app).get(RULES).status_code == 401


# --- RBAC per role (RBAC-MATRIX 'Alert rules') ------------------------------------------------------


def _routes_for_matrix(
    store: InMemoryAlertRuleRepository,
) -> list[tuple[str, Callable[[Caller], Any], list[str], str]]:
    """(name, call, roles that are allowed, state-seeding hint)."""

    def draft_id() -> str:
        return seed_rule(store)[0]

    def active_id() -> str:
        return seed_rule(store, "active")[0]

    return [
        ("list", lambda c: c.get(RULES), READ_ROLES, ""),
        ("get", lambda c: c.get(f"{RULES}/{draft_id()}"), READ_ROLES, ""),
        ("create", lambda c: c.post(RULES, rule_body()), AUTHOR_ROLES, ""),
        (
            "update",
            lambda c: c.put(
                f"{RULES}/{draft_id()}", {"expected_version": 1, "definition": rule_body()}
            ),
            AUTHOR_ROLES,
            "",
        ),
        (
            "approve",
            lambda c: c.post(f"{RULES}/{draft_id()}/approve", {"expected_version": 1}),
            APPROVER_ROLES,
            "",
        ),
        ("disable", lambda c: c.post(f"{RULES}/{active_id()}/disable"), AUTHOR_ROLES, ""),
        ("evaluate", lambda c: c.post(f"{RULES}/evaluate", evaluate_body()), READ_ROLES, ""),
    ]


@pytest.mark.parametrize("role", ALL_ROLES)
def test_each_role_gets_exactly_the_matrix_permissions(
    store: InMemoryAlertRuleRepository, role: str
) -> None:
    caller = Caller(role)
    for name, call, allowed_roles, _ in _routes_for_matrix(store):
        response = call(caller)
        if role in allowed_roles:
            assert response.status_code in (200, 201), (name, response.status_code, response.text)
        else:
            assert response.status_code == 403, (name, response.status_code)
            assert response.json()["error"]["code"] == "FORBIDDEN"


@pytest.mark.parametrize("role", ["technician", "management"])
def test_denied_roles_change_nothing_and_learn_nothing(
    store: InMemoryAlertRuleRepository, role: str
) -> None:
    rule_id, _ = seed_rule(store)
    caller = Caller(role)
    before = store.get_rule(rule_id)
    assert (
        caller.put(
            f"{RULES}/{rule_id}", {"expected_version": 1, "definition": rule_body(name="x")}
        ).status_code
        == 403
    )
    assert caller.post(f"{RULES}/{rule_id}/approve", {"expected_version": 1}).status_code == 403
    assert caller.post(RULES, rule_body()).status_code == 403
    assert store.get_rule(rule_id) == before
    assert len(store.list_rules()) == 1
    # A well-formed id that does not exist answers the same 403, not a 404 that maps ids.
    assert caller.get(f"{RULES}/{MISSING_RULE_ID}").status_code == 403


def test_management_keeps_its_s6_2_incident_read_while_alert_rules_stay_denied(
    store: InMemoryAlertRuleRepository,
) -> None:
    manager = Caller("management")
    assert manager.get(RULES).status_code == 403
    assert manager.get("/api/v1/incidents").status_code != 403  # S6-2 decision unchanged


@pytest.mark.parametrize("kind", [PrincipalKind.SERVICE, PrincipalKind.AI])
def test_non_human_principals_may_read_but_never_change_monitoring_configuration(
    store: InMemoryAlertRuleRepository, kind: PrincipalKind
) -> None:
    rule_id, _ = seed_rule(store)
    robot = Identity("svc:copilot", frozenset({"administrator"}), kind)
    app.dependency_overrides[get_current_identity] = lambda: robot
    client = TestClient(app, raise_server_exceptions=False)
    assert client.get(RULES).status_code == 200
    assert client.post(RULES, json=rule_body()).status_code == 403
    assert (
        client.put(
            f"{RULES}/{rule_id}", json={"expected_version": 1, "definition": rule_body()}
        ).status_code
        == 403
    )
    assert (
        client.post(f"{RULES}/{rule_id}/approve", json={"expected_version": 1}).status_code == 403
    )
    assert client.post(f"{RULES}/{rule_id}/disable").status_code == 403
    assert store.get_rule(rule_id).status == "draft"  # type: ignore[union-attr]


# --- lifecycle ---------------------------------------------------------------------------------------


def test_create_makes_a_draft_attributed_to_the_caller(
    store: InMemoryAlertRuleRepository,
) -> None:
    caller = Caller("network_engineer", "sub-eng")
    response = caller.post(RULES, rule_body())
    assert response.status_code == 201
    body = response.json()
    validate("alert_rule", body)
    assert body["status"] == "draft"
    assert body["version"] == 1
    assert body["created_by"] == caller.identity_id
    assert body["approved_by"] is None and body["approved_at"] is None
    assert body["name"] == "After-hours large upload"


def test_a_client_cannot_create_an_active_or_attributed_rule(
    store: InMemoryAlertRuleRepository,
) -> None:
    caller = Caller("administrator")
    for extra in (
        {"status": "active"},
        {"approved_by": "identity-admin"},
        {"created_by": "identity-someone-else"},
        {"id": MISSING_RULE_ID},
        {"version": 7},
    ):
        response = caller.post(RULES, {**rule_body(), **extra})
        assert response.status_code == 422, extra
    assert store.list_rules() == []


def test_approval_activates_exactly_the_reviewed_version(
    store: InMemoryAlertRuleRepository,
) -> None:
    approver = Caller("administrator", "sub-admin")
    rule_id, version = seed_rule(store)
    response = approver.post(f"{RULES}/{rule_id}/approve", {"expected_version": version})
    assert response.status_code == 200
    body = response.json()
    validate("alert_rule", body)
    assert body["status"] == "active"
    assert body["approved_by"] == approver.identity_id
    assert body["version"] == version + 1


def test_approval_of_a_changed_rule_is_refused_with_409_and_activates_nothing(
    store: InMemoryAlertRuleRepository,
) -> None:
    author, approver = Caller("network_engineer"), Caller("administrator")
    rule_id, version = seed_rule(store)
    reviewed = version
    # The author edits after the approver loaded the rule.
    edited = author.put(
        f"{RULES}/{rule_id}",
        {"expected_version": version, "definition": rule_body(name="Changed after review")},
    )
    assert edited.status_code == 200
    response = approver.post(f"{RULES}/{rule_id}/approve", {"expected_version": reviewed})
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "CONFLICT"
    current = store.get_rule(rule_id)
    assert current is not None and current.status == "draft"
    assert current.name == "Changed after review"


def test_concurrent_edit_and_approval_never_activate_an_unreviewed_definition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Race an author's edit against the approver's approval of the reviewed version."""
    monkeypatch.setattr(alerting_route_support, "WRITE_LIMIT_PER_MINUTE", 10_000)
    for _ in range(25):
        _race_edit_against_approval()


def _race_edit_against_approval() -> None:
    repository = InMemoryAlertRuleRepository()
    app.dependency_overrides[get_optional_alert_rule_store] = _provide(repository)
    rule_id, version = seed_rule(repository)
    author, approver = Caller("network_engineer"), Caller("administrator")
    start = threading.Barrier(2)
    results: dict[str, int] = {}

    def edit() -> None:
        start.wait()
        results["edit"] = author.put(
            f"{RULES}/{rule_id}",
            {"expected_version": version, "definition": rule_body(name="Edited")},
        ).status_code

    def approve() -> None:
        start.wait()
        results["approve"] = approver.post(
            f"{RULES}/{rule_id}/approve", {"expected_version": version}
        ).status_code

    threads = [threading.Thread(target=edit), threading.Thread(target=approve)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    final = repository.get_rule(rule_id)
    assert final is not None
    if final.status == "active":
        # Approval won: the active definition is the reviewed one and the edit was refused.
        assert final.name == "After-hours large upload"
        assert results == {"edit": 409, "approve": 200}
    else:
        # Edit won: nothing was activated and the approval was refused.
        assert final.status == "draft" and final.name == "Edited"
        assert results == {"edit": 200, "approve": 409}


def test_an_active_rule_must_be_disabled_before_editing_and_an_edit_returns_it_to_draft(
    store: InMemoryAlertRuleRepository,
) -> None:
    caller = Caller("administrator")
    rule_id, version = seed_rule(store, "active")
    refused = caller.put(
        f"{RULES}/{rule_id}", {"expected_version": version, "definition": rule_body()}
    )
    assert refused.status_code == 409
    assert refused.json()["error"]["code"] == "ILLEGAL_TRANSITION"
    disabled = caller.post(f"{RULES}/{rule_id}/disable")
    assert disabled.status_code == 200 and disabled.json()["status"] == "disabled"
    edited = caller.put(
        f"{RULES}/{rule_id}",
        {"expected_version": disabled.json()["version"], "definition": rule_body(name="v2")},
    )
    assert edited.status_code == 200
    assert edited.json()["status"] == "draft"
    assert edited.json()["approved_by"] is None


def test_stale_update_is_a_409_and_double_state_changes_are_409s(
    store: InMemoryAlertRuleRepository,
) -> None:
    caller = Caller("administrator")
    rule_id, version = seed_rule(store)
    assert (
        caller.put(
            f"{RULES}/{rule_id}", {"expected_version": version + 5, "definition": rule_body()}
        ).status_code
        == 409
    )
    assert caller.post(f"{RULES}/{rule_id}/disable").status_code == 409  # draft cannot be disabled
    assert (
        caller.post(f"{RULES}/{rule_id}/approve", {"expected_version": version}).status_code == 200
    )
    again = caller.post(f"{RULES}/{rule_id}/approve", {"expected_version": version + 1})
    assert again.status_code == 409


def test_a_disabled_rule_can_be_approved_again_at_its_current_version(
    store: InMemoryAlertRuleRepository,
) -> None:
    caller = Caller("administrator")
    rule_id, version = seed_rule(store, "disabled")
    response = caller.post(f"{RULES}/{rule_id}/approve", {"expected_version": version})
    assert response.status_code == 200 and response.json()["status"] == "active"


# --- fail closed: an invalid rule never activates ----------------------------------------------------------


def test_a_rule_that_cannot_be_evaluated_is_refused_at_every_write(
    store: InMemoryAlertRuleRepository,
) -> None:
    caller = Caller("administrator")
    bad = rule_body(
        schedule={
            "timezone": "Mars/Olympus",
            "active": [{"weekdays": ["mon"], "from": "01:00", "to": "02:00"}],
        }
    )
    created = caller.post(RULES, bad)
    assert created.status_code == 422
    assert created.json()["error"]["code"] == "RULE_INVALID"
    assert "SCHEDULE_TIMEZONE_UNKNOWN" in created.json()["error"]["message"]
    assert store.list_rules() == []
    rule_id, version = seed_rule(store)
    updated = caller.put(f"{RULES}/{rule_id}", {"expected_version": version, "definition": bad})
    assert updated.status_code == 422 and updated.json()["error"]["code"] == "RULE_INVALID"
    assert store.get_rule(rule_id).version == version  # type: ignore[union-attr]


def test_a_stored_draft_that_became_invalid_cannot_be_approved(
    store: InMemoryAlertRuleRepository,
) -> None:
    # Seeded straight into the store, as if the host's timezone data changed since creation.
    rule_id, version = seed_rule(
        store,
        schedule={
            "timezone": "Mars/Olympus",
            "active": [{"weekdays": ["mon"], "from": "01:00", "to": "02:00"}],
        },
    )
    response = Caller("administrator").post(
        f"{RULES}/{rule_id}/approve", {"expected_version": version}
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "RULE_INVALID"
    assert store.get_rule(rule_id).status == "draft"  # type: ignore[union-attr]


def test_inconsistent_rule_parts_are_refused() -> None:
    caller = Caller("administrator")
    repository = InMemoryAlertRuleRepository()
    app.dependency_overrides[get_optional_alert_rule_store] = lambda: repository
    orphan = rule_body(actions=["email"], incident_policy="create")
    response = caller.post(RULES, orphan)
    assert response.status_code == 422
    assert "INCIDENT_POLICY_REQUIRES_CREATE_ALERT" in response.json()["error"]["message"]


# --- reads, pagination bounds, ids ------------------------------------------------------------------------


def test_list_is_newest_first_paged_and_filtered(store: InMemoryAlertRuleRepository) -> None:
    for index in range(3):
        seed_rule(store, name=f"rule-{index}")
    seed_rule(store, "active", name="active-one")
    reader = Caller("auditor")
    page = reader.get(RULES, limit=2).json()
    validate("alert_rule_list", page)
    assert page["state"] == "ok" and len(page["rules"]) == 2
    assert page["next_offset"] == 2
    assert page["rules"][0]["name"] == "active-one"
    second = reader.get(RULES, limit=2, offset=2).json()
    assert [r["name"] for r in second["rules"]] == ["rule-1", "rule-0"]
    only_active = reader.get(RULES, status="active").json()
    assert [r["name"] for r in only_active["rules"]] == ["active-one"]


@pytest.mark.parametrize(
    "params",
    [
        {"limit": 0},
        {"limit": 101},
        {"limit": -1},
        {"limit": "x"},
        {"offset": -1},
        {"offset": 10_001},
        {"status": "deleted"},
        {"status": "ACTIVE"},
    ],
)
def test_pagination_and_filter_bounds_are_422(
    store: InMemoryAlertRuleRepository, params: dict[str, Any]
) -> None:
    response = Caller("auditor").get(RULES, **params)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


@pytest.mark.parametrize("limit", [1, 100])
@pytest.mark.parametrize("offset", [0, 10_000])
def test_pagination_extremes_are_accepted(
    store: InMemoryAlertRuleRepository, limit: int, offset: int
) -> None:
    response = Caller("auditor").get(RULES, limit=limit, offset=offset)
    assert response.status_code == 200 and response.json()["state"] == "ok"


MALFORMED_IDS = [
    "1",
    "alert-rule-",
    "alert-rule-xyz",
    "ALERT-RULE-5A6B7C8D-1E2F-4A3B-9C4D-5E6F7A8B9C0D",
    "alert-rule-5a6b7c8d-1e2f-4a3b-9c4d-5e6f7a8b9c0d ",
    "maintenance-5a6b7c8d-1e2f-4a3b-9c4d-5e6f7a8b9c0d",
    "alert-rule-5a6b7c8d-1e2f-4a3b-9c4d-5e6f7a8b9c0d-extra",
    "alert-rule-5a6b7c8d-1e2f-4a3b-9c4d-5e6f7a8b9c0g",
    "..%2F..%2Fetc%2Fpasswd",
    "alert-rule-%00",
    "%27%3B%20DROP%20TABLE%20alert_rules%3B--",
]


@pytest.mark.parametrize("bad_id", MALFORMED_IDS)
def test_malformed_ids_are_422_on_every_id_route(
    store: InMemoryAlertRuleRepository, bad_id: str, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    caller = Caller("administrator")
    for response in (
        caller.get(f"{RULES}/{bad_id}"),
        caller.put(f"{RULES}/{bad_id}", {"expected_version": 1, "definition": rule_body()}),
        caller.post(f"{RULES}/{bad_id}/approve", {"expected_version": 1}),
        caller.post(f"{RULES}/{bad_id}/disable"),
    ):
        assert response.status_code in (404, 422), response.text
        assert response.status_code != 500
    # A malformed id never reaches the audit log or the store.
    assert all(bad_id not in str(record) for record in audit_records(caplog))


def test_unknown_but_well_formed_ids_are_404_for_every_id_route(
    store: InMemoryAlertRuleRepository,
) -> None:
    caller = Caller("administrator")
    for response in (
        caller.get(f"{RULES}/{MISSING_RULE_ID}"),
        caller.put(
            f"{RULES}/{MISSING_RULE_ID}", {"expected_version": 1, "definition": rule_body()}
        ),
        caller.post(f"{RULES}/{MISSING_RULE_ID}/approve", {"expected_version": 1}),
        caller.post(f"{RULES}/{MISSING_RULE_ID}/disable"),
    ):
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "NOT_FOUND"
        assert MISSING_RULE_ID not in response.text


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"expected_version": 0},
        {"expected_version": -1},
        {"expected_version": 1_000_001},
        {"expected_version": "1"},
        {"expected_version": True},
        {"expected_version": 1.5},
        {"expected_version": None},
        {"expected_version": 1, "approved_by": "someone-else"},
        {"expected_version": 1, "force": True},
    ],
)
def test_approve_bodies_are_validated(store: InMemoryAlertRuleRepository, body: Any) -> None:
    rule_id, _ = seed_rule(store)
    response = Caller("administrator").post(f"{RULES}/{rule_id}/approve", body)
    assert response.status_code == 422
    assert store.get_rule(rule_id).status == "draft"  # type: ignore[union-attr]


@pytest.mark.parametrize(
    "mutation",
    [
        {"name": ""},
        {"name": "   "},
        {"name": "x" * 256},
        {"severity": "urgent"},
        {"window_seconds": 59},
        {"for_seconds": -1},
        {"cooldown_seconds": 604_801},
        {"actions": []},
        {"actions": ["email", "email"]},
        {"actions": ["sms"]},
        {"labels": {"Bad Key": "x"}},
        {"scope": {"kind": "planet", "ref": "x"}},
        {"condition": {"metric": "x", "operator": "gt", "threshold": None, "pattern": None}},
        {"condition": {"metric": "x", "operator": "gt", "threshold": 1, "pattern": "*"}},
        {"condition": {"metric": "x", "operator": "gt", "threshold": "5", "pattern": None}},
        {"unknown_field": 1},
    ],
)
def test_rule_bodies_are_validated_at_the_boundary(
    store: InMemoryAlertRuleRepository, mutation: dict[str, Any]
) -> None:
    caller = Caller("administrator")
    created = caller.post(RULES, rule_body(**mutation))
    assert created.status_code == 422
    assert created.json()["error"]["code"] == "VALIDATION_ERROR"
    rule_id, version = seed_rule(store)
    updated = caller.put(
        f"{RULES}/{rule_id}", {"expected_version": version, "definition": rule_body(**mutation)}
    )
    assert updated.status_code == 422
    assert len(store.list_rules()) == 1


@pytest.mark.parametrize("payload", ["not json", "[]", "null", "42", '{"name": '])
def test_non_object_or_broken_json_is_422(store: InMemoryAlertRuleRepository, payload: str) -> None:
    caller = Caller("administrator")
    response = caller.http.post(
        RULES,
        content=payload,
        headers={"Content-Type": "application/json", "X-CSRF-Token": caller.session.csrf_token},
    )
    assert response.status_code == 422


# --- explicit states ------------------------------------------------------------------------------------------


def test_reads_without_a_store_are_explicit_not_connected_states() -> None:
    app.dependency_overrides[get_optional_alert_rule_store] = lambda: None
    reader = Caller("auditor")
    listing = reader.get(RULES)
    assert listing.status_code == 200
    assert listing.json() == {
        "state": "not-connected",
        "rules": [],
        "limit": 50,
        "offset": 0,
        "next_offset": None,
    }
    detail = reader.get(f"{RULES}/{MISSING_RULE_ID}")
    assert detail.status_code == 200
    assert detail.json() == {"state": "not-connected", "rule": None}


def test_writes_without_a_store_are_503_and_audited(caplog: pytest.LogCaptureFixture) -> None:
    app.dependency_overrides[get_optional_alert_rule_store] = lambda: None
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    caller = Caller("administrator")
    for response in (
        caller.post(RULES, rule_body()),
        caller.put(
            f"{RULES}/{MISSING_RULE_ID}", {"expected_version": 1, "definition": rule_body()}
        ),
        caller.post(f"{RULES}/{MISSING_RULE_ID}/approve", {"expected_version": 1}),
        caller.post(f"{RULES}/{MISSING_RULE_ID}/disable"),
    ):
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "STORE_NOT_CONNECTED"
    assert [r["reason"] for r in audit_records(caplog)] == ["STORE_NOT_CONNECTED"] * 4


def test_store_failure_is_unknown_for_reads_and_503_for_writes_without_leaking(
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = "postgresql://netsight_app:hunter2-secret@db:5432/netsight"
    failing = FailingStore(StorageUnavailableError(f"connection to {secret} failed"))
    app.dependency_overrides[get_optional_alert_rule_store] = lambda: failing
    caplog.set_level(logging.DEBUG)
    caller = Caller("administrator")
    listing = caller.get(RULES)
    assert listing.status_code == 200
    assert listing.json() == {
        "state": "unknown",
        "rules": [],
        "limit": 50,
        "offset": 0,
        "next_offset": None,
    }
    assert caller.get(f"{RULES}/{MISSING_RULE_ID}").json() == {"state": "unknown", "rule": None}
    write = caller.post(RULES, rule_body())
    assert write.status_code == 503
    assert write.json()["error"]["code"] == "STORE_UNAVAILABLE"
    for text in (listing.text, write.text, caplog.text):
        assert "hunter2" not in text and secret not in text


def test_misconfigured_database_url_degrades_without_leaking_it(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    dsn = "mysql://root:hunter2-secret@db/x"
    monkeypatch.setenv("DATABASE_URL", dsn)
    caplog.set_level(logging.DEBUG)
    caller = Caller("administrator")
    assert caller.get(RULES).json()["state"] == "unknown"
    write = caller.post(RULES, rule_body())
    assert write.status_code == 503
    for text in (write.text, caplog.text):
        assert "hunter2" not in text and dsn not in text


def test_unreachable_database_degrades_to_unknown_and_never_leaks_the_dsn(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    dsn = "postgresql://netsight_app:hunter2-secret@127.0.0.1:1/netsight"
    monkeypatch.setenv("DATABASE_URL", dsn)
    caplog.set_level(logging.DEBUG)
    caller = Caller("administrator")
    listing = caller.get(RULES)
    assert listing.status_code == 200 and listing.json()["state"] == "unknown"
    write = caller.post(RULES, rule_body())
    assert write.status_code == 503 and write.json()["error"]["code"] == "STORE_UNAVAILABLE"
    for text in (listing.text, write.text, caplog.text):
        assert "hunter2" not in text and dsn not in text


def test_storage_conflicts_map_to_409_and_unexpected_errors_to_a_bare_500() -> None:
    conflicting = FailingStore(StorageConflictError("serialization failure on alert_rules"))
    app.dependency_overrides[get_optional_alert_rule_store] = lambda: conflicting
    caller = Caller("administrator")
    conflict = caller.post(RULES, rule_body())
    assert conflict.status_code == 409 and conflict.json()["error"]["code"] == "CONFLICT"
    assert "serialization" not in conflict.text
    broken = FailingStore(RuntimeError("boom with secret-token-123"))
    app.dependency_overrides[get_optional_alert_rule_store] = lambda: broken
    crash = caller.post(RULES, rule_body())
    assert crash.status_code == 500
    assert crash.json()["error"]["code"] == "INTERNAL_ERROR"
    assert "secret-token-123" not in crash.text
    assert caller.get(RULES).json()["state"] == "unknown"  # reads degrade, never 500


# --- audit (closes the S6-2 gate item: rule edits and disables carry an actor) -----------------------------------


def test_every_mutation_is_audited_with_actor_rule_version_and_action(
    store: InMemoryAlertRuleRepository, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    author, admin = Caller("network_engineer", "sub-eng"), Caller("administrator", "sub-admin")
    created = author.post(RULES, rule_body()).json()
    rule_id = created["id"]
    edited = author.put(
        f"{RULES}/{rule_id}", {"expected_version": 1, "definition": rule_body(name="v2")}
    ).json()
    approved = admin.post(
        f"{RULES}/{rule_id}/approve", {"expected_version": edited["version"]}
    ).json()
    disabled = author.post(f"{RULES}/{rule_id}/disable").json()
    records = [r for r in audit_records(caplog) if r["outcome"] == "success"]
    assert [r["action"] for r in records] == [
        "alert_rule.create",
        "alert_rule.update",
        "alert_rule.approve",
        "alert_rule.disable",
    ]
    assert [r["actor_id"] for r in records] == [
        author.identity_id,
        author.identity_id,
        admin.identity_id,
        author.identity_id,
    ]
    assert {r["target"] for r in records} == {rule_id}
    assert [r["version"] for r in records] == [
        created["version"],
        edited["version"],
        approved["version"],
        disabled["version"],
    ]
    assert records[1]["expected_version"] == 1
    assert records[2]["expected_version"] == edited["version"]
    assert all(r["correlation_id"] for r in records)


def test_refused_and_failed_mutations_are_audited_too(
    store: InMemoryAlertRuleRepository, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    rule_id, version = seed_rule(store)
    Caller("technician").post(f"{RULES}/{rule_id}/approve", {"expected_version": version})
    Caller("network_engineer").post(f"{RULES}/{rule_id}/approve", {"expected_version": version})
    admin = Caller("administrator")
    admin.post(f"{RULES}/{rule_id}/approve", {"expected_version": version + 3})
    admin.post(f"{RULES}/{MISSING_RULE_ID}/disable")
    outcomes = [(r["action"], r["outcome"], r.get("reason")) for r in audit_records(caplog)]
    assert outcomes == [
        ("alert_rule.approve", "denied", "permission"),
        ("alert_rule.approve", "denied", "permission"),
        ("alert_rule.approve", "failure", "CONFLICT"),
        ("alert_rule.disable", "failure", "NOT_FOUND"),
    ]
    assert audit_records(caplog)[2]["target"] == rule_id


def test_audit_never_carries_free_text_from_the_rule(
    store: InMemoryAlertRuleRepository, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    caller = Caller("administrator")
    created = caller.post(RULES, rule_body(name=XSS, labels={"team": XSS})).json()
    caller.put(
        f"{RULES}/{created['id']}",
        {"expected_version": 1, "definition": rule_body(name=XSS + "2")},
    )
    audit_text = "\n".join(r.getMessage() for r in caplog.records if r.name == "netsight_api.audit")
    assert audit_text
    assert "script" not in audit_text and "DROP TABLE" not in audit_text
    records = audit_records(caplog)
    assert records[0]["name_length"] == len(XSS) and len(records[0]["name_hash"]) == 16


# --- untrusted text and secrets --------------------------------------------------------------------------------


def test_untrusted_text_is_stored_and_returned_verbatim_as_data(
    store: InMemoryAlertRuleRepository,
) -> None:
    caller = Caller("administrator")
    created = caller.post(
        RULES,
        rule_body(
            name=XSS,
            labels={"team": XSS},
            exceptions={"destinations": [XSS], "device_groups": []},
        ),
    )
    assert created.status_code == 201
    assert created.headers["content-type"].startswith("application/json")
    rule_id = created.json()["id"]
    for body in (
        created.json(),
        caller.get(f"{RULES}/{rule_id}").json()["rule"],
        caller.get(RULES).json()["rules"][0],
    ):
        assert body["name"] == XSS
        assert body["labels"]["team"] == XSS
        assert body["exceptions"]["destinations"] == [XSS]


def test_error_responses_never_echo_request_text(store: InMemoryAlertRuleRepository) -> None:
    caller = Caller("administrator")
    response = caller.post(RULES, rule_body(name=XSS, severity=XSS))
    assert response.status_code == 422
    assert "script" not in response.text
    assert response.headers["content-type"].startswith("application/json")


def test_success_responses_are_contract_valid_everywhere(
    store: InMemoryAlertRuleRepository,
) -> None:
    caller = Caller("administrator")
    created = caller.post(RULES, rule_body()).json()
    validate("alert_rule", created)
    updated = caller.put(
        f"{RULES}/{created['id']}", {"expected_version": 1, "definition": rule_body(name="b")}
    ).json()
    validate("alert_rule", updated)
    validate("alert_rule_list", caller.get(RULES).json())
    validate("alert_rule_detail", caller.get(f"{RULES}/{created['id']}").json())
    approved = caller.post(
        f"{RULES}/{created['id']}/approve", {"expected_version": updated["version"]}
    )
    assert approved.status_code == 200, approved.text
    validate("alert_rule", approved.json())
    disabled = caller.post(f"{RULES}/{created['id']}/disable")
    assert disabled.status_code == 200, disabled.text
    validate("alert_rule", disabled.json())


def test_openapi_exposes_exactly_the_alert_rule_operations() -> None:
    paths = app.openapi()["paths"]
    operations = {
        (path, method)
        for path, item in paths.items()
        if path.startswith("/api/v1/alert-rules")
        for method in item
    }
    assert operations == {
        ("/api/v1/alert-rules", "get"),
        ("/api/v1/alert-rules", "post"),
        ("/api/v1/alert-rules/evaluate", "post"),
        ("/api/v1/alert-rules/{rule_id}", "get"),
        ("/api/v1/alert-rules/{rule_id}", "put"),
        ("/api/v1/alert-rules/{rule_id}/approve", "post"),
        ("/api/v1/alert-rules/{rule_id}/disable", "post"),
    }
    approve = paths["/api/v1/alert-rules/{rule_id}/approve"]["post"]
    assert {"401", "403", "404", "409", "422", "429", "503"} <= set(approve["responses"])
