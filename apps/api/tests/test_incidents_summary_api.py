"""Management's summary-only incident view (human decision 2026-10-10).

``GET /api/v1/incidents/summary`` answers with a reduced shape: no evidence ids, no
resolution text, no timeline, and no assignee identity (only whether somebody is assigned).
Management holds ``incidents:read-summary`` and no longer holds ``incidents:read``.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from test_incidents_api import ALL_ROLES, XSS, Caller, TickingClock, seed

from netsight_api import read_limit
from netsight_api.auth.rate_limit import RateLimiter
from netsight_api.auth.settings import session_policy
from netsight_api.contracts import validate
from netsight_api.incident_routes import get_optional_incident_store
from netsight_api.main import app
from netsight_api.storage import InMemoryIncidentRepository

SUMMARY = "/api/v1/incidents/summary"
ASSIGNEE = "microsoft:alice.personal@example.test"
SUMMARY_KEYS = {
    "id",
    "title",
    "severity",
    "state",
    "created_at",
    "updated_at",
    "assigned",
    "resolved_at",
}


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in ("NETSIGHT_ENV", "NETSIGHT_ENABLE_DEV_IDENTITY", "DATABASE_URL"):
        monkeypatch.delenv(name, raising=False)
    app.dependency_overrides.clear()
    session_policy.cache_clear()
    yield
    app.dependency_overrides.clear()
    session_policy.cache_clear()


@pytest.fixture
def store() -> InMemoryIncidentRepository:
    repository = InMemoryIncidentRepository(clock=TickingClock())
    app.dependency_overrides[get_optional_incident_store] = lambda: repository
    return repository


def test_summary_requires_authentication(store: InMemoryIncidentRepository) -> None:
    response = TestClient(app).get(SUMMARY)
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "AUTHENTICATION_REQUIRED"


@pytest.mark.parametrize("role", ALL_ROLES)
def test_every_known_role_may_read_the_summary(
    store: InMemoryIncidentRepository, role: str
) -> None:
    seed(store)
    assert Caller(role).get(SUMMARY).status_code == 200


def test_unknown_roles_are_denied(store: InMemoryIncidentRepository) -> None:
    seed(store)
    response = Caller("incident_viewer").get(SUMMARY)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"


def test_the_summary_has_exactly_the_reduced_shape(store: InMemoryIncidentRepository) -> None:
    open_id = seed(store, title="Perimeter outage", severity="high", assignee=ASSIGNEE)
    resolved_id = seed(store, state="resolved", severity="low")
    body = Caller("management").get(SUMMARY).json()
    validate("incident_summary_list", body)
    assert body["state"] == "ok"
    assert set(body) == {"state", "incidents", "limit", "offset", "next_offset"}
    by_id = {row["id"]: row for row in body["incidents"]}
    assert set(by_id) == {open_id, resolved_id}
    for row in body["incidents"]:
        assert set(row) == SUMMARY_KEYS
    assert by_id[open_id]["assigned"] is True
    assert by_id[open_id]["resolved_at"] is None
    assert by_id[resolved_id]["assigned"] is False
    assert by_id[resolved_id]["resolved_at"] is not None


def test_no_personal_or_free_text_data_reaches_management(
    store: InMemoryIncidentRepository,
) -> None:
    incident_id = seed(store, state="resolved", assignee=None)
    store.set_assignee(incident_id, assignee_id=ASSIGNEE, actor_id="seed:operator")
    store.add_evidence(incident_id, evidence_id="evidence-secret-ref-77", actor_id="seed:operator")
    store.append_event(
        incident_id, kind="comment", actor_id="seed:operator", message="private-comment-text"
    )
    text = Caller("management").get(SUMMARY).text
    for forbidden in (
        "alice.personal",
        "evidence-secret-ref-77",
        "private-comment-text",
        "Replaced failed uplink optic",  # resolution summary
        "Failed SFP",  # root cause
        "Guest Wi-Fi down",  # impact
        "Order spare SFPs",  # follow-up
        "seed:operator",  # resolved_by / actor
        "assignee_id",
        "evidence_ids",
        "resolution",
    ):
        assert forbidden not in text, forbidden


def test_the_title_is_returned_verbatim_as_data(store: InMemoryIncidentRepository) -> None:
    seed(store, title=XSS)
    rows = Caller("management").get(SUMMARY).json()["incidents"]
    assert rows[0]["title"] == XSS


def test_filters_and_paging_match_the_full_list(store: InMemoryIncidentRepository) -> None:
    a = seed(store, severity="low")
    b = seed(store, severity="high", state="acknowledged")
    c = seed(store, severity="high")
    caller = Caller("management")

    def ids(**params: Any) -> list[str]:
        return [row["id"] for row in caller.get(SUMMARY, **params).json()["incidents"]]

    assert ids() == [c, b, a]
    assert ids(state="acknowledged") == [b]
    assert ids(severity="high") == [c, b]
    page = caller.get(SUMMARY, limit=2).json()
    assert [row["id"] for row in page["incidents"]] == [c, b]
    assert page["next_offset"] == 2
    assert ids(limit=2, offset=2) == [a]


def test_the_summary_has_no_assignee_filter(store: InMemoryIncidentRepository) -> None:
    """Filtering by identity would let a summary reader probe who holds an incident."""
    seed(store, assignee=ASSIGNEE)
    response = Caller("management").get(SUMMARY, assignee_id=ASSIGNEE)
    assert response.status_code == 200
    assert len(response.json()["incidents"]) == 1  # the unknown parameter is ignored


@pytest.mark.parametrize(
    "params", [{"limit": 0}, {"limit": 101}, {"offset": -1}, {"offset": 10_001}, {"state": "gone"}]
)
def test_invalid_query_is_a_422(store: InMemoryIncidentRepository, params: dict[str, Any]) -> None:
    assert Caller("management").get(SUMMARY, **params).status_code == 422


def test_not_connected_and_unknown_states_carry_no_rows(
    store: InMemoryIncidentRepository,
) -> None:
    app.dependency_overrides[get_optional_incident_store] = lambda: None
    body = Caller("management").get(SUMMARY).json()
    assert body["state"] == "not-connected"
    assert body["incidents"] == [] and body["next_offset"] is None
    validate("incident_summary_list", body)

    class Broken:
        def list_incidents(self, **_kwargs: object) -> None:
            raise RuntimeError("postgresql://user:secret@db/netsight exploded")

    app.dependency_overrides[get_optional_incident_store] = lambda: Broken()
    response = Caller("management").get(SUMMARY)
    assert response.json()["state"] == "unknown"
    assert response.json()["incidents"] == []
    assert "secret" not in response.text


def test_the_static_summary_path_is_not_shadowed_by_the_id_route(
    store: InMemoryIncidentRepository,
) -> None:
    response = Caller("auditor").get(SUMMARY)
    assert response.status_code == 200
    assert "incidents" in response.json()


def test_the_summary_read_is_rate_limited_per_identity(
    store: InMemoryIncidentRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(read_limit, "_read_limiter", RateLimiter())
    monkeypatch.setattr(read_limit, "READ_LIMIT_PER_MINUTE", 2)
    caller = Caller("management")
    assert [caller.get(SUMMARY).status_code for _ in range(3)] == [200, 200, 429]
