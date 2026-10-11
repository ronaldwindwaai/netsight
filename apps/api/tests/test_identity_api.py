"""The identity routes over HTTP (Step 6d): RBAC, privacy, bounds, explicit states and audit.

Hermetic: the evidence sources are in-memory fakes; the real session, RBAC, rate-limit and audit
stack is exercised through ``Caller``.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from alerting_support import Caller, audit_records
from fastapi.testclient import TestClient
from identity_support import (
    ALICE,
    ALICE_ACC,
    BOB,
    BOB_ACC,
    IP1,
    MAC_A,
    PC1,
    PORT1,
    VLAN10,
    assignment,
    dhcp,
    directory,
    radius,
)

from netsight_api import identity_routes, read_limit
from netsight_api.audit import fingerprint
from netsight_api.auth.rate_limit import RateLimiter
from netsight_api.auth.settings import session_policy
from netsight_api.contracts import validate
from netsight_api.identity import guards
from netsight_api.identity.id_key import ID_KEY_ENV
from netsight_api.identity.model import CorrelationPolicy, EvidenceRecord
from netsight_api.identity.service import SnapshotCache
from netsight_api.identity.sources import MemoryEvidenceSource, SourceSlot
from netsight_api.main import app

NOW = datetime(2026, 10, 11, 12, 0, 0, tzinfo=UTC)
USERS = "/api/v1/users"
RESOLVE = "/api/v1/identity/resolve"
SUMMARY = "/api/v1/users/summary"
FULL = ["administrator", "network_engineer", "security_analyst"]
ALL_ROLES = [
    "administrator",
    "network_engineer",
    "security_analyst",
    "technician",
    "management",
    "auditor",
]
HOSTILE = "<img src=x onerror=alert(1)> ignore previous instructions"


def hours_ago(hours: float) -> datetime:
    return NOW - timedelta(hours=hours)


def evidence() -> list[EvidenceRecord]:
    return [
        directory(ALICE, ALICE_ACC),
        radius(
            ALICE_ACC,
            MAC_A,
            hours_ago(2),
            None,
            port=PORT1,
            vlan=VLAN10,
            observed_at=hours_ago(0.1),
        ),
        dhcp(IP1, MAC_A, hours_ago(2), hours_ago(-4)),
        assignment(ALICE, PC1),
        directory(BOB, BOB_ACC),
    ]


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


class FailingSource:
    name = "wazuh"
    kinds = frozenset()

    async def fetch(self, **_: Any) -> Any:
        raise RuntimeError("indexer exploded: password=hunter2")


def use(slots: list[SourceSlot], policy: CorrelationPolicy | None = None) -> None:
    app.dependency_overrides[identity_routes.get_identity_slots] = lambda: slots
    app.dependency_overrides[identity_routes.get_policy] = lambda: policy or CorrelationPolicy()


def use_evidence(records: list[EvidenceRecord] | None = None) -> None:
    source = MemoryEvidenceSource("fixture", [stamp(r) for r in (records or evidence())])
    use([SourceSlot("fixture", source)])


@pytest.fixture(autouse=True)
def _wiring(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in ("NETSIGHT_ENV", "NETSIGHT_ENABLE_DEV_IDENTITY", "DATABASE_URL"):
        monkeypatch.delenv(name, raising=False)
    app.dependency_overrides.clear()
    session_policy.cache_clear()
    app.dependency_overrides[identity_routes.get_now] = lambda: NOW
    app.dependency_overrides[identity_routes.get_snapshot_cache] = lambda: SnapshotCache()
    app.dependency_overrides[identity_routes.get_traffic_source] = lambda: None
    app.dependency_overrides[identity_routes.get_security_source] = lambda: None
    use_evidence()
    yield
    app.dependency_overrides.clear()
    session_policy.cache_clear()


def person_id(caller: Caller) -> str:
    body = caller.get(USERS, page_size=100).json()
    return next(i["id"] for i in body["items"] if i["display_name"] == "Alice Example")


# --- authentication and authorisation ------------------------------------------------------------------


def test_anonymous_callers_are_refused_everywhere() -> None:
    client = TestClient(app)
    for path in (USERS, f"{USERS}/person-00000000-0000-4000-8000-000000000000", SUMMARY):
        assert client.get(path).status_code == 401, path
    assert client.get(RESOLVE, params={"ip": "10.0.0.10"}).status_code == 401


def test_a_caller_without_a_known_role_is_refused_everywhere() -> None:
    caller = Caller("not-a-role")
    for path in (USERS, SUMMARY):
        assert caller.get(path).status_code == 403
    assert caller.get(RESOLVE, ip="10.0.0.10").status_code == 403


@pytest.mark.parametrize("role", ALL_ROLES)
def test_the_role_matrix_for_every_route(role: str) -> None:
    caller = Caller(role)
    full = role in FULL
    limited = full or role == "technician"
    summary = limited or role == "management"
    assert caller.get(USERS).status_code == (200 if full else 403)
    assert caller.get(SUMMARY).status_code == (200 if summary else 403)
    assert caller.get(RESOLVE, ip="10.0.0.10").status_code == (200 if limited else 403)
    detail = f"{USERS}/person-00000000-0000-4000-8000-000000000000"
    assert caller.get(detail).status_code == (404 if full else 403)


def test_management_never_sees_a_name_an_id_or_a_row() -> None:
    caller = Caller("management")
    body = caller.get(SUMMARY).json()
    validate("users_aggregate", body)
    text = json.dumps(body)
    assert "Alice" not in text and "person-" not in text and "account-" not in text
    assert body["people_total"] == 2
    assert caller.get(USERS).status_code == 403  # no per-user browsing
    assert caller.get(f"{USERS}/{person_id(Caller('administrator'))}").status_code == 403


@pytest.mark.parametrize("role", ["technician", "management", "auditor"])
def test_authorisation_is_decided_before_the_rate_limit(role: str) -> None:
    caller = Caller(role)
    codes = {caller.get(USERS).status_code for _ in range(130)}
    assert codes == {403}


def test_the_surface_is_read_only() -> None:
    caller = Caller("administrator")
    for path in (USERS, SUMMARY, RESOLVE, f"{USERS}/person-00000000-0000-4000-8000-000000000000"):
        for verb in ("post", "put", "delete", "patch"):
            assert getattr(caller.http, verb)(path).status_code in {404, 405}, (verb, path)


def test_the_routes_are_in_the_published_openapi_document() -> None:
    paths = app.openapi()["paths"]
    assert {
        "/api/v1/users",
        "/api/v1/users/summary",
        "/api/v1/users/{user_id}",
        "/api/v1/identity/resolve",
    } <= set(paths)


def test_per_user_responses_are_never_cached() -> None:
    caller = Caller("administrator")
    for response in (caller.get(USERS), caller.get(RESOLVE, ip="10.0.0.10"), caller.get(SUMMARY)):
        assert response.headers["cache-control"] == "no-store"


# --- rate limits ---------------------------------------------------------------------------------------------------


def test_listing_is_rate_limited_per_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(read_limit, "_read_limiter", RateLimiter())
    caller = Caller("administrator", "sub-rl")
    codes = [
        caller.get(USERS).status_code for _ in range(identity_routes.LIST_LIMIT_PER_MINUTE + 1)
    ]
    assert codes[:-1] == [200] * identity_routes.LIST_LIMIT_PER_MINUTE and codes[-1] == 429
    assert Caller("administrator", "sub-other").get(USERS).status_code == 200


def test_resolving_is_rate_limited_harder_because_it_is_a_scraping_vector() -> None:
    assert identity_routes.RESOLVE_LIMIT_PER_MINUTE < identity_routes.LIST_LIMIT_PER_MINUTE
    caller = Caller("security_analyst", "sub-rs")
    codes = [
        caller.get(RESOLVE, ip="10.0.0.10").status_code
        for _ in range(identity_routes.RESOLVE_LIMIT_PER_MINUTE + 1)
    ]
    assert codes[-1] == 429
    response = caller.get(RESOLVE, ip="10.0.0.10")
    assert response.headers["retry-after"] and response.json()["error"]["code"] == "RATE_LIMITED"


# --- GET /users ----------------------------------------------------------------------------------------------------------


def test_nothing_configured_is_an_explicit_not_connected_state() -> None:
    use([SourceSlot("wazuh", None), SourceSlot("netbox", None)])
    body = Caller("administrator").get(USERS).json()
    validate("user_list", body)
    assert body["state"] == "not-connected" and body["items"] == [] and body["total"] == 0
    assert [s["state"] for s in body["sources"]] == ["not-connected", "not-connected"]


def test_a_failing_source_is_unknown_and_leaks_nothing() -> None:
    use([SourceSlot("wazuh", FailingSource())])
    response = Caller("administrator").get(USERS)
    body = response.json()
    validate("user_list", body)
    assert response.status_code == 200 and body["state"] == "unknown" and body["items"] == []
    assert "hunter2" not in response.text and "exploded" not in response.text


def test_the_list_returns_people_with_the_basis_of_their_presence() -> None:
    body = Caller("security_analyst").get(USERS).json()
    validate("user_list", body)
    rows = {row["display_name"]: row for row in body["items"]}
    assert rows["Alice Example"]["presence"] == "observed"
    assert (
        rows["Bob Example"]["presence"] == "unknown" and rows["Bob Example"]["session_count"] == 0
    )
    assert all(row["id"].startswith("person-") for row in body["items"])


@pytest.mark.parametrize(
    "params",
    [{"page": 0}, {"page": 1001}, {"page_size": 0}, {"page_size": 101}, {"page": "x"}],
)
def test_paging_is_server_bounded(params: dict[str, Any]) -> None:
    assert Caller("administrator").get(USERS, **params).status_code == 422


def test_the_list_pages() -> None:
    caller = Caller("administrator")
    first = caller.get(USERS, page=1, page_size=1).json()
    second = caller.get(USERS, page=2, page_size=1).json()
    assert first["total"] == 2 and len(first["items"]) == len(second["items"]) == 1
    assert first["items"][0]["id"] != second["items"][0]["id"]


# --- GET /users/{id} ---------------------------------------------------------------------------------------------------------


def test_a_person_detail_carries_sessions_with_basis_and_evidence() -> None:
    caller = Caller("security_analyst")
    response = caller.get(f"{USERS}/{person_id(caller)}")
    body = response.json()
    validate("user_detail", body)
    assert response.status_code == 200 and body["state"] == "ok"
    (session,) = body["user"]["sessions"]
    assert session["basis"] == "observed" and session["kind"] == "wired"
    assert all(link["evidence"] for link in session["links"])
    assert (
        body["traffic"]["state"] == "not-connected" and body["security"]["state"] == "not-connected"
    )


def test_an_unknown_person_is_a_404_and_a_malformed_id_a_422() -> None:
    caller = Caller("administrator")
    missing = caller.get(f"{USERS}/person-00000000-0000-4000-8000-000000000000")
    assert missing.status_code == 404 and missing.json()["error"]["code"] == "NOT_FOUND"
    for bad in ("alice@example.com", "person-1", "person-%27%3B--", "device-1"):
        assert caller.get(f"{USERS}/{bad}").status_code == 422, bad


def test_a_detail_when_nothing_is_connected_has_no_profile() -> None:
    use([SourceSlot("wazuh", None)])
    body = (
        Caller("administrator").get(f"{USERS}/person-00000000-0000-4000-8000-000000000000").json()
    )
    validate("user_detail", body)
    assert body["state"] == "not-connected" and body["user"] is None


def test_hostile_names_are_returned_as_data() -> None:
    hostile = [
        directory(
            __import__("netsight_api.identity.model", fromlist=["person_ref"]).person_ref(
                "directory", "mallory", HOSTILE
            ),
            ALICE_ACC,
        )
    ]
    use_evidence(hostile)
    body = Caller("administrator").get(USERS).json()
    assert body["items"][0]["display_name"] == HOSTILE


# --- GET /identity/resolve -----------------------------------------------------------------------------------------------------


def test_resolve_names_the_person_for_the_roles_that_may() -> None:
    body = Caller("security_analyst").get(RESOLVE, ip="10.0.0.10").json()
    validate("identity_resolve", body)
    assert body["state"] == "ok" and body["attribution"]["basis"] == "observed"
    assert body["attribution"]["links"][0]["target"]["label"] == "Alice Example"


def test_a_technician_gets_the_endpoint_but_the_person_is_withheld_and_says_so() -> None:
    response = Caller("technician").get(RESOLVE, ip="10.0.0.10")
    body = response.json()
    validate("identity_resolve", body)
    assert body["attribution"]["reason"] == "restricted" and body["attribution"]["links"] == []
    assert body["endpoint"], "the endpoint (MAC, port, VLAN) is still shown"
    assert "Alice" not in response.text and "person-" not in response.text
    assert "account-" not in response.text


@pytest.mark.parametrize(
    ("params", "kind"),
    [
        ({"ip": "10.0.0.10"}, "ip"),
        ({"mac": "AA-BB-CC-00-00-01"}, "mac"),
        ({"mac": "aabb.cc00.0001"}, "mac"),
        ({"hostname": "PC-001.Example.org."}, "hostname"),
        ({"ip": "::ffff:10.0.0.10"}, "ip"),
    ],
)
def test_each_subject_kind_is_accepted_and_canonicalised(params: dict[str, str], kind: str) -> None:
    body = Caller("administrator").get(RESOLVE, **params).json()
    assert body["subject"]["kind"] == kind
    assert body["subject"]["value"] == body["subject"]["value"].lower()
    if kind == "mac":
        assert body["subject"]["value"] == "aa:bb:cc:00:00:01"
    if params.get("ip") == "::ffff:10.0.0.10":
        assert body["subject"]["value"] == "10.0.0.10"


@pytest.mark.parametrize(
    "params",
    [
        {},
        {"ip": "10.0.0.10", "mac": "aa:bb:cc:00:00:01"},
        {"ip": "10.0.0.10", "hostname": "pc-001"},
        {"ip": "999.1.1.1"},
        {"ip": "fe80::1%eth0"},
        {"ip": "10.0.0.10/24"},
        {"ip": ""},
        {"mac": "aa:bb:cc"},
        {"mac": "zz:bb:cc:dd:ee:ff"},
        {"mac": "aa:bb:cc:dd:ee:ff:00:11"},
        {"hostname": "has space"},
        {"hostname": "x" * 129},
        {"hostname": "<script>alert(1)</script>"},
        {"hostname": "-leading-hyphen"},
        {"hostname": ""},
    ],
)
def test_an_invalid_subject_is_a_422_and_never_reflected(params: dict[str, str]) -> None:
    response = Caller("administrator").get(RESOLVE, **params)
    assert response.status_code == 422
    assert "<script>" not in response.text


def test_the_time_window_is_server_bounded() -> None:
    caller = Caller("administrator")
    ok = (NOW - timedelta(days=1)).isoformat().replace("+00:00", "Z")
    assert caller.get(RESOLVE, ip="10.0.0.10", at=ok).status_code == 200
    too_old = (NOW - timedelta(days=8)).isoformat().replace("+00:00", "Z")
    future = (NOW + timedelta(hours=2)).isoformat().replace("+00:00", "Z")
    for bad in (too_old, future, "2026-10-10T12:00:00", "yesterday"):
        assert caller.get(RESOLVE, ip="10.0.0.10", at=bad).status_code == 422, bad


def test_a_historical_question_answers_for_that_time() -> None:
    caller = Caller("administrator")
    before = (NOW - timedelta(days=1)).isoformat().replace("+00:00", "Z")
    body = caller.get(RESOLVE, ip="10.0.0.10", at=before).json()
    validate("identity_resolve", body)
    assert body["as_of"].startswith("2026-10-10T12:00:00")
    assert body["attribution"]["basis"] == "unknown"  # the lease and session did not exist yet


def test_resolve_with_nothing_connected_is_not_connected_not_unknown_person() -> None:
    use([SourceSlot("wazuh", None)])
    body = Caller("administrator").get(RESOLVE, ip="10.0.0.10").json()
    validate("identity_resolve", body)
    assert body["state"] == "not-connected" and body["endpoint"] == []
    assert body["attribution"]["basis"] == "unknown"


def test_an_ip_address_alone_is_never_identity() -> None:
    only_lease = [dhcp(IP1, MAC_A, hours_ago(2), hours_ago(-4))]
    use_evidence(only_lease)
    body = Caller("administrator").get(RESOLVE, ip="10.0.0.10").json()
    assert body["attribution"]["basis"] == "unknown" and body["attribution"]["reason"] == "ip-only"


def test_a_misconfigured_policy_is_unknown_never_a_guess() -> None:
    app.dependency_overrides[identity_routes.get_policy] = lambda: None  # an unusable policy
    body = Caller("administrator").get(RESOLVE, ip="10.0.0.10").json()
    validate("identity_resolve", body)
    assert body["state"] == "unknown" and body["attribution"]["basis"] == "unknown"
    users = Caller("administrator").get(USERS).json()
    validate("user_list", users)
    assert users["state"] == "unknown" and users["items"] == []


# --- audit -------------------------------------------------------------------------------------------------------------------------


def test_every_per_user_read_is_audited_with_actor_target_and_counts_only(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO)
    caller = Caller("security_analyst", "sub-audit")
    caller.get(USERS)
    pid = person_id(caller)
    caller.get(f"{USERS}/{pid}")
    caller.get(RESOLVE, ip="10.0.0.10")
    records = {r["action"]: r for r in audit_records(caplog) if r["action"].startswith("identity.")}
    assert set(records) >= {"identity.users.list", "identity.user.read", "identity.resolve"}
    for record in records.values():
        assert record["outcome"] == "success" and record["actor_id"] == caller.identity_id
        assert record["correlation_id"]
    assert records["identity.user.read"]["target"] == pid
    assert records["identity.resolve"]["target"] == f"ip:{fingerprint('10.0.0.10')}"
    assert records["identity.resolve"]["identified_count"] == 1
    assert records["identity.users.list"]["result_count"] == 2
    blob = json.dumps(list(records.values()))
    assert "Alice" not in blob and "Example" not in blob and "@" not in blob


def test_a_restricted_resolve_is_audited_as_restricted(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO)
    Caller("technician").get(RESOLVE, ip="10.0.0.10")
    (record,) = [r for r in audit_records(caplog) if r["action"] == "identity.resolve"]
    assert record["redacted"] is True and record["identified_count"] == 0


def test_a_denied_read_is_audited_as_denied(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO)
    Caller("management").get(USERS)
    Caller("technician").get(f"{USERS}/person-00000000-0000-4000-8000-000000000000")
    Caller("auditor").get(RESOLVE, ip="10.0.0.10")
    denied = [r for r in audit_records(caplog) if r["outcome"] == "denied"]
    assert {r["action"] for r in denied} >= {
        "identity.users.list",
        "identity.user.read",
        "identity.resolve",
    }
    assert all(r["reason"] == "permission" for r in denied)


def test_an_unreadable_source_is_audited_as_a_failure(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO)
    use([SourceSlot("wazuh", FailingSource())])
    Caller("administrator").get(USERS)
    (record,) = [r for r in audit_records(caplog) if r["action"] == "identity.users.list"]
    assert record["outcome"] == "failure" and record["state"] == "unknown"


def test_an_unknown_person_read_is_audited(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO)
    Caller("administrator").get(f"{USERS}/person-00000000-0000-4000-8000-000000000000")
    (record,) = [r for r in audit_records(caplog) if r["action"] == "identity.user.read"]
    assert record["outcome"] == "failure" and record["reason"] == "not-found"


def test_the_aggregate_is_not_per_user_data_and_is_not_audited(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO)
    Caller("management").get(SUMMARY)
    assert not [r for r in audit_records(caplog) if r["action"].startswith("identity.")]


# --- review fixes: audit coverage, no raw subjects, error caching, global limits --------------------------


def only(caplog: pytest.LogCaptureFixture, action: str) -> list[dict[str, Any]]:
    return [r for r in audit_records(caplog) if r["action"] == action]


@pytest.mark.parametrize(
    ("params", "kind", "value"),
    [
        ({"ip": "10.0.0.10"}, "ip", "10.0.0.10"),
        ({"mac": "AA-BB-CC-00-00-01"}, "mac", "aa:bb:cc:00:00:01"),
        ({"hostname": "Alice-Laptop.Example.org"}, "hostname", "alice-laptop.example.org"),
    ],
)
def test_the_resolve_audit_target_is_a_fingerprint_never_the_raw_subject(
    caplog: pytest.LogCaptureFixture, params: dict[str, str], kind: str, value: str
) -> None:
    caplog.set_level(logging.INFO)
    Caller("security_analyst").get(RESOLVE, **params)
    (record,) = only(caplog, "identity.resolve")
    assert record["target"] == f"{kind}:{fingerprint(value)}"
    blob = json.dumps(record).lower()
    assert value.lower() not in blob and "alice-laptop" not in blob and "aa:bb:cc" not in blob


def test_a_denied_summary_is_audited(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO)
    assert Caller("auditor").get(SUMMARY).status_code == 403
    (record,) = only(caplog, "identity.summary")
    assert record["outcome"] == "denied" and record["reason"] == "permission"


def test_a_denied_detail_names_the_target_person_id(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO)
    pid = "person-00000000-0000-4000-8000-000000000000"
    Caller("technician").get(f"{USERS}/{pid}")
    (record,) = only(caplog, "identity.user.read")
    assert record["outcome"] == "denied" and record["target"] == pid


def test_a_denied_detail_with_a_malformed_id_does_not_log_the_raw_text(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO)
    Caller("technician").get(f"{USERS}/alice@example.com")
    blob = json.dumps(audit_records(caplog))
    assert "alice@example.com" not in blob


@pytest.mark.parametrize(
    ("path", "params", "action", "limit", "role"),
    [
        (USERS, {}, "identity.users.list", "LIST_LIMIT_PER_MINUTE", "administrator"),
        (SUMMARY, {}, "identity.summary", "SUMMARY_LIMIT_PER_MINUTE", "management"),
        (
            RESOLVE,
            {"ip": "10.0.0.10"},
            "identity.resolve",
            "RESOLVE_LIMIT_PER_MINUTE",
            "technician",
        ),
    ],
)
def test_a_rate_limited_request_is_audited_with_a_static_reason(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    path: str,
    params: dict[str, str],
    action: str,
    limit: str,
    role: str,
) -> None:
    monkeypatch.setattr(identity_routes, limit, 2)
    caplog.set_level(logging.INFO)
    caller = Caller(role, "sub-429")
    codes = [caller.get(path, **params).status_code for _ in range(3)]
    assert codes == [200, 200, 429]
    limited = [r for r in only(caplog, action) if r["outcome"] == "denied"]
    assert len(limited) == 1 and limited[0]["reason"] == "rate-limited"
    assert limited[0]["actor_id"] == caller.identity_id


def test_a_rate_limited_detail_is_audited_with_the_target(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(identity_routes, "LIST_LIMIT_PER_MINUTE", 1)
    caplog.set_level(logging.INFO)
    pid = "person-00000000-0000-4000-8000-000000000000"
    caller = Caller("administrator", "sub-429-detail")
    caller.get(f"{USERS}/{pid}")
    assert caller.get(f"{USERS}/{pid}").status_code == 429
    limited = [r for r in only(caplog, "identity.user.read") if r["outcome"] == "denied"]
    assert limited and limited[0]["target"] == pid and limited[0]["reason"] == "rate-limited"


@pytest.mark.parametrize(
    ("params", "reason"),
    [
        ({}, "subject-count"),
        ({"ip": "10.0.0.10", "mac": "aa:bb:cc:00:00:01"}, "subject-count"),
        ({"ip": "<script>alert(1)</script>"}, "invalid-subject"),
        ({"mac": "zz:zz"}, "invalid-subject"),
        ({"hostname": "has space <b>"}, "invalid-subject"),
        ({"ip": "10.0.0.10", "at": "yesterday"}, "invalid-time"),
        ({"ip": "10.0.0.10", "at": "2026-10-10T12:00:00"}, "invalid-time"),
    ],
)
def test_a_rejected_resolve_is_audited_with_a_static_reason_and_no_echo(
    caplog: pytest.LogCaptureFixture, params: dict[str, str], reason: str
) -> None:
    caplog.set_level(logging.INFO)
    response = Caller("administrator").get(RESOLVE, **params)
    assert response.status_code == 422
    (record,) = only(caplog, "identity.resolve")
    assert record["outcome"] == "failure" and record["reason"] == reason
    blob = json.dumps(record)
    assert "script" not in blob and "has space" not in blob and "10.0.0.10" not in blob
    assert response.headers["cache-control"] == "no-store"


def test_an_out_of_range_time_is_audited(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO)
    too_old = (NOW - timedelta(days=8)).isoformat().replace("+00:00", "Z")
    Caller("administrator").get(RESOLVE, ip="10.0.0.10", at=too_old)
    (record,) = only(caplog, "identity.resolve")
    assert record["reason"] == "invalid-time"


@pytest.mark.parametrize("role", ["administrator", "technician", "management", "auditor"])
def test_error_responses_on_the_identity_routes_are_never_cached(role: str) -> None:
    caller = Caller(role)
    pid = "person-00000000-0000-4000-8000-000000000000"
    responses = [
        caller.get(USERS),
        caller.get(SUMMARY),
        caller.get(f"{USERS}/{pid}"),
        caller.get(f"{USERS}/not-a-person"),
        caller.get(RESOLVE),
        caller.get(RESOLVE, ip="10.0.0.10", at="garbage"),
    ]
    errors = [r for r in responses if r.status_code >= 400]
    assert errors
    for response in errors:
        assert response.headers["cache-control"] == "no-store", response.request.url


def test_unauthenticated_identity_errors_are_not_cached() -> None:
    client = TestClient(app)
    for path in (USERS, SUMMARY, RESOLVE):
        response = client.get(path)
        assert response.status_code == 401 and response.headers["cache-control"] == "no-store"


def test_other_routes_keep_their_own_caching_headers() -> None:
    response = TestClient(app).get("/api/v1/does-not-exist")
    assert response.headers.get("cache-control") != "no-store"


def test_historical_resolves_have_a_global_budget_across_identities(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(guards, "HISTORICAL_GLOBAL_LIMIT_PER_MINUTE", 3)
    caplog.set_level(logging.INFO)
    before = (NOW - timedelta(days=1)).isoformat().replace("+00:00", "Z")
    codes = [
        Caller("administrator", f"sub-hist-{n}").get(RESOLVE, ip="10.0.0.10", at=before).status_code
        for n in range(5)
    ]
    assert codes == [200, 200, 200, 429, 429]
    refused = [r for r in only(caplog, "identity.resolve") if r["outcome"] == "denied"]
    assert refused and all(r["reason"] == "global-limit" for r in refused)
    # a current question is cached and is not counted against the historical budget
    assert Caller("administrator", "sub-fresh").get(RESOLVE, ip="10.0.0.10").status_code == 200


def test_the_global_refusal_carries_retry_after_and_is_not_cached(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(guards, "HISTORICAL_GLOBAL_LIMIT_PER_MINUTE", 1)
    before = (NOW - timedelta(days=1)).isoformat().replace("+00:00", "Z")
    Caller("administrator", "sub-g1").get(RESOLVE, ip="10.0.0.10", at=before)
    response = Caller("administrator", "sub-g2").get(RESOLVE, ip="10.0.0.10", at=before)
    assert response.status_code == 429 and response.json()["error"]["code"] == "RATE_LIMITED"
    assert response.headers["retry-after"] and response.headers["cache-control"] == "no-store"


def test_concurrent_uncached_loads_are_capped(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    import threading

    slots = threading.BoundedSemaphore(1)
    monkeypatch.setattr(guards, "_slots", slots)
    assert slots.acquire(blocking=False)  # another request holds the only slot
    caplog.set_level(logging.INFO)
    before = (NOW - timedelta(days=1)).isoformat().replace("+00:00", "Z")
    response = Caller("administrator", "sub-busy").get(RESOLVE, ip="10.0.0.10", at=before)
    assert response.status_code == 503 and response.json()["error"]["code"] == "IDENTITY_BUSY"
    (record,) = [r for r in only(caplog, "identity.resolve") if r["outcome"] == "denied"]
    assert record["reason"] == "busy"
    slots.release()
    again = Caller("administrator", "sub-busy").get(RESOLVE, ip="10.0.0.10", at=before)
    assert again.status_code == 200


def test_the_slot_is_released_when_the_read_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    import threading

    monkeypatch.setattr(guards, "_slots", threading.BoundedSemaphore(1))
    use([SourceSlot("wazuh", FailingSource())])
    before = (NOW - timedelta(days=1)).isoformat().replace("+00:00", "Z")
    for _ in range(3):
        response = Caller("administrator", "sub-fail").get(RESOLVE, ip="10.0.0.10", at=before)
        assert response.status_code == 200 and response.json()["state"] == "unknown"


def test_without_an_evidence_id_key_a_limited_caller_gets_unknown_not_guessable_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(ID_KEY_ENV, raising=False)
    limited = Caller("technician").get(RESOLVE, ip="10.0.0.10")
    body = limited.json()
    validate("identity_resolve", body)
    assert body["state"] == "unknown" and body["endpoint"] == []
    full = Caller("security_analyst").get(RESOLVE, ip="10.0.0.10").json()
    assert full["state"] == "ok" and full["attribution"]["basis"] == "observed"


def test_a_resolve_response_carries_the_notes_list() -> None:
    body = Caller("administrator").get(RESOLVE, ip="10.0.0.10").json()
    validate("identity_resolve", body)
    assert body["notes"] == []


def test_a_historical_resolve_over_the_register_carries_the_note() -> None:
    before = (NOW - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    body = Caller("administrator").get(RESOLVE, ip="10.0.0.10", at=before).json()
    validate("identity_resolve", body)
    assert body["notes"] == ["register-is-current-state"]  # the fixture includes an assignment


def test_a_persons_traffic_needs_the_endpoint_level_traffic_permission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per-person traffic is built from source addresses, so it needs traffic:read-detail too."""
    from netsight_api.rbac import ROLE_PERMISSIONS, Permission, Role

    class _Source:
        async def top(self, **_: Any) -> tuple[list[Any], None]:
            return [], None

    app.dependency_overrides[identity_routes.get_traffic_source] = lambda: _Source()
    caller = Caller("security_analyst")
    path = f"{USERS}/{person_id(caller)}"
    assert caller.get(path).json()["traffic"]["state"] == "ok"
    monkeypatch.setitem(
        ROLE_PERMISSIONS,
        Role.SECURITY_ANALYST,
        frozenset(ROLE_PERMISSIONS[Role.SECURITY_ANALYST] - {Permission.TRAFFIC_READ_DETAIL}),
    )
    assert caller.get(path).json()["traffic"]["state"] == "not-connected"
