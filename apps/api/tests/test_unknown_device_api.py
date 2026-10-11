"""The unknown-device routes over HTTP (Step 8c): reads, the human-only workflow, scan and audit.

Hermetic: the store is the in-memory repository (same rules as PostgreSQL, proven by the storage
conformance suite) and the scanner is a stub; the real session, CSRF, origin, step-up, RBAC and
rate-limit stack runs through ``Operator``. Every successful body is checked against the canonical
schema, and nothing here can execute a quarantine: no such route exists.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Any

import pytest
from alerting_support import Caller, audit_records
from fastapi.testclient import TestClient
from unknown_support import detection

from netsight_api import read_limit, unknown_device_routes
from netsight_api.auth.deps import get_current_identity
from netsight_api.auth.rate_limit import RateLimiter
from netsight_api.auth.session import session_manager
from netsight_api.auth.settings import session_policy
from netsight_api.contracts import validate
from netsight_api.main import app
from netsight_api.rbac import Identity, PrincipalKind
from netsight_api.schemas_sources import SourceStatus
from netsight_api.storage import StorageUnavailableError
from netsight_api.storage.unknown_devices import InMemoryUnknownDeviceRepository
from netsight_api.unknown_devices.scanner import ScanResult

BASE = "/api/v1/unknown-devices"
NOW = datetime(2026, 10, 11, 12, 0, tzinfo=UTC)
ALL_ROLES = [
    "administrator",
    "network_engineer",
    "security_analyst",
    "technician",
    "management",
    "auditor",
]
READERS = ["administrator", "network_engineer", "security_analyst", "auditor"]
WRITERS = ["administrator", "network_engineer", "security_analyst"]
NON_WRITERS = ["auditor", "technician", "management"]
HOSTILE = "<script>alert('x')</script> \"; DROP TABLE findings; -- {{7*7}}"
MISSING = "unknown-device-00000000-0000-4000-8000-000000000000"
SECRET = "postgresql://netsight:hunter2@db.internal/netsight"


class Operator(Caller):
    """A signed-in browser with a chosen age of its last second factor (None: never proven)."""

    def __init__(
        self, role: str = "security_analyst", subject: str = "sub-1", mfa_age: float | None = 0.0
    ) -> None:
        super().__init__(role, subject)
        manager = session_manager()
        self.session.mfa_verified_at = None if mfa_age is None else manager.store.now() - mfa_age


class StubScanner:
    def __init__(self, result: ScanResult | Exception | None = None) -> None:
        self.result = result or ScanResult(
            "ok",
            NOW,
            (
                SourceStatus(source="netbox", state="ok", observed_at=NOW),
                SourceStatus(source="librenms", state="ok", observed_at=NOW),
                SourceStatus(source="wazuh", state="not-connected", observed_at=None),
            ),
            created=2,
            refreshed=1,
            suppressed=0,
            unverified=3,
            truncated=False,
        )
        self.calls = 0

    async def scan(self) -> ScanResult:
        self.calls += 1
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class FailingStore(InMemoryUnknownDeviceRepository):
    def __init__(self, error: Exception) -> None:
        super().__init__()
        self._error = error
        self.armed = False

    def __getattribute__(self, name: str) -> Any:
        value = super().__getattribute__(name)
        if name in {
            "get_finding",
            "list_findings",
            "counts",
            "list_timeline",
            "transition_state",
            "set_assignee",
            "add_comment",
            "observe",
        } and super().__getattribute__("armed"):

            def fail(*_a: Any, **_k: Any) -> Any:
                raise super(FailingStore, self).__getattribute__("_error")

            return fail
        return value


@pytest.fixture(autouse=True)
def _wiring(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in (
        "NETSIGHT_ENV",
        "NETSIGHT_ENABLE_DEV_IDENTITY",
        "NETSIGHT_ALLOWED_ORIGINS",
        "NETSIGHT_PUBLIC_BASE_URL",
        "DATABASE_URL",
        "NETSIGHT_STEP_UP_MAX_AGE_SECONDS",
    ):
        monkeypatch.delenv(name, raising=False)
    app.dependency_overrides.clear()
    session_policy.cache_clear()
    monkeypatch.setattr(read_limit, "_read_limiter", RateLimiter())
    monkeypatch.setattr(unknown_device_routes, "_write_limiter", RateLimiter())
    monkeypatch.setattr(unknown_device_routes, "_scan_limiter", RateLimiter())
    yield
    app.dependency_overrides.clear()
    session_policy.cache_clear()


@pytest.fixture
def store() -> InMemoryUnknownDeviceRepository:
    repository = InMemoryUnknownDeviceRepository(clock=lambda: NOW)
    app.dependency_overrides[unknown_device_routes.get_unknown_device_store] = lambda: repository
    return repository


@pytest.fixture
def scanner() -> StubScanner:
    stub = StubScanner()
    app.dependency_overrides[unknown_device_routes.get_unknown_device_scanner] = lambda: stub
    return stub


def seed(store: InMemoryUnknownDeviceRepository, **kwargs: Any) -> str:
    return store.observe(detection(**kwargs)).finding_id


def finding_url(finding_id: str, suffix: str = "") -> str:
    return f"{BASE}/{finding_id}{suffix}"


# --- reads: authentication and authorisation ----------------------------------------------------------------


def test_unauthenticated_callers_get_401_everywhere(store: InMemoryUnknownDeviceRepository) -> None:
    client = TestClient(app, raise_server_exceptions=False)
    fid = seed(store)
    for path in (BASE, f"{BASE}/summary", finding_url(fid), finding_url(fid, "/timeline")):
        assert client.get(path).status_code == 401
    assert client.post(finding_url(fid, "/acknowledge")).status_code == 401
    assert client.post(f"{BASE}/scan").status_code == 401


@pytest.mark.parametrize("role", READERS)
def test_reader_roles_read_findings(role: str, store: InMemoryUnknownDeviceRepository) -> None:
    fid = seed(store)
    caller = Caller(role)
    listing = caller.get(BASE)
    assert listing.status_code == 200
    validate("unknown_device_list", listing.json())
    detail = caller.get(finding_url(fid))
    assert detail.status_code == 200
    validate("unknown_device_detail", detail.json())
    timeline = caller.get(finding_url(fid, "/timeline"))
    assert timeline.status_code == 200
    validate("unknown_device_timeline", timeline.json())


@pytest.mark.parametrize("role", ["technician", "management", "superuser"])
def test_summary_roles_never_see_rows(role: str, store: InMemoryUnknownDeviceRepository) -> None:
    fid = seed(store)
    caller = Caller(role)
    for path in (BASE, finding_url(fid), finding_url(fid, "/timeline")):
        assert caller.get(path).status_code == 403


@pytest.mark.parametrize("role", [r for r in ALL_ROLES])
def test_every_known_role_reads_the_counts(
    role: str, store: InMemoryUnknownDeviceRepository
) -> None:
    seed(store)
    response = Caller(role).get(f"{BASE}/summary")
    assert response.status_code == 200
    body = response.json()
    validate("unknown_device_summary", body)
    assert set(body) == {"state", "generated_at", "counts"}
    assert body["counts"]["open"] == 1


def test_authorisation_comes_before_validation_and_before_the_limiter(
    store: InMemoryUnknownDeviceRepository,
) -> None:
    caller = Caller("management")
    assert caller.get(BASE, page_size=9999).status_code == 403
    for _ in range(150):
        assert caller.get(BASE).status_code == 403


# --- reads: content, filters, bounds -------------------------------------------------------------------------


def test_the_list_shows_the_chain_comparison_and_severity(
    store: InMemoryUnknownDeviceRepository,
) -> None:
    seed(store, severity="high", basis="policy-rule", with_action=True)
    body = Caller("security_analyst").get(BASE).json()
    item = body["items"][0]
    assert body["state"] == "ok" and body["total"] == 1
    assert [s["slot"] for s in item["chain"]] == ["ip", "mac", "attachment", "port", "vlan"]
    assert (
        item["chain"][2]["basis"] == "unknown"
        and item["chain"][2]["reason"] == "source-unavailable"
    )
    assert [c["result"] for c in item["comparison"]["checks"]] == ["no-match"] * 3
    assert item["severity"] == "high" and item["proposed_action"]["executable"] is False


def test_filters_and_paging_are_applied_on_the_server(
    store: InMemoryUnknownDeviceRepository,
) -> None:
    a = seed(store, severity="high", basis="policy-rule")
    b = seed(store, mac="aa:bb:cc:00:11:33", ip="10.0.5.10", severity="low", basis="policy-rule")
    store.transition_state(b, to_state="acknowledged", actor_id="u")
    store.set_assignee(b, assignee_id="u", actor_id="u")
    c = seed(store, mac="aa:bb:cc:00:11:44", ip="10.0.5.11")
    store.transition_state(c, to_state="resolved", actor_id="u", reason="done")
    caller = Caller("network_engineer")
    ids = lambda **q: {i["id"] for i in caller.get(BASE, **q).json()["items"]}
    assert ids(state="open") == {a, b}
    assert ids(state="resolved") == {c}
    assert ids(state="new") == {a}
    assert ids(severity="low") == {b}
    assert ids(assigned="true") == {b}
    assert ids(assigned="false") == {a, c}
    page = caller.get(BASE, page=2, page_size=2).json()
    assert page["total"] == 3 and len(page["items"]) == 1


@pytest.mark.parametrize(
    "query",
    [
        {"page": 0},
        {"page_size": 0},
        {"page_size": 51},
        {"state": "closed"},
        {"severity": "severe"},
        {"assigned": "maybe"},
        {"unexpected": "1"},
        {"q": "x"},
    ],
)
def test_bad_parameters_are_a_422_that_echoes_nothing(
    query: dict[str, Any], store: InMemoryUnknownDeviceRepository
) -> None:
    response = Caller("network_engineer").get(BASE, **query)
    assert response.status_code == 422 and response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_repeated_parameters_are_refused(store: InMemoryUnknownDeviceRepository) -> None:
    assert Caller("network_engineer").http.get(f"{BASE}?state=new&state=open").status_code == 422


def test_the_timeline_pages_by_sequence(store: InMemoryUnknownDeviceRepository) -> None:
    fid = seed(store)
    for index in range(4):
        store.add_comment(fid, actor_id="u", message=f"note {index}")
    caller = Caller("auditor")
    first = caller.get(finding_url(fid, "/timeline"), limit=3).json()
    assert [e["seq"] for e in first["events"]] == [1, 2, 3] and first["next_after_seq"] == 3
    second = caller.get(finding_url(fid, "/timeline"), after_seq=3, limit=3).json()
    assert [e["seq"] for e in second["events"]] == [4, 5] and second["next_after_seq"] is None
    validate("unknown_device_timeline", second)
    for bad in ({"limit": 0}, {"limit": 201}, {"after_seq": -1}, {"junk": 1}):
        assert caller.get(finding_url(fid, "/timeline"), **bad).status_code == 422


def test_unknown_and_malformed_ids(store: InMemoryUnknownDeviceRepository) -> None:
    caller = Caller("network_engineer")
    assert caller.get(finding_url(MISSING)).status_code == 404
    assert caller.get(finding_url(MISSING, "/timeline")).status_code == 404
    assert caller.get(finding_url("unknown-device-1")).status_code == 422


def test_responses_are_not_cacheable(store: InMemoryUnknownDeviceRepository) -> None:
    fid = seed(store)
    for path in (BASE, f"{BASE}/summary", finding_url(fid), finding_url(fid, "/timeline")):
        assert Caller("auditor").get(path).headers["cache-control"] == "no-store"


def test_hostile_text_is_returned_as_data(store: InMemoryUnknownDeviceRepository) -> None:
    fid = seed(store, hostname=HOSTILE[:100])
    store.add_comment(fid, actor_id="u", message=HOSTILE)
    caller = Caller("auditor")
    assert caller.get(finding_url(fid)).json()["item"]["endpoint"]["hostname"] == HOSTILE[:100]
    assert caller.get(finding_url(fid, "/timeline")).json()["events"][-1]["message"] == HOSTILE


# --- reads: explicit states -----------------------------------------------------------------------------------


def test_without_the_store_every_read_is_not_connected() -> None:
    app.dependency_overrides[unknown_device_routes.get_unknown_device_store] = lambda: None
    caller = Caller("network_engineer")
    fid = "unknown-device-6f1c2a9e-0b1d-5c3e-8f4a-123456789abc"
    for path, schema in (
        (BASE, "unknown_device_list"),
        (finding_url(fid), "unknown_device_detail"),
        (finding_url(fid, "/timeline"), "unknown_device_timeline"),
        (f"{BASE}/summary", "unknown_device_summary"),
    ):
        response = caller.get(path)
        assert response.status_code == 200
        validate(schema, response.json())
        assert response.json()["state"] == "not-connected"


def test_a_failing_store_is_unknown_and_never_leaks() -> None:
    failing = FailingStore(StorageUnavailableError(SECRET))
    seeded = failing.observe(detection()).finding_id
    failing.armed = True
    app.dependency_overrides[unknown_device_routes.get_unknown_device_store] = lambda: failing
    caller = Caller("network_engineer")
    for path in (BASE, finding_url(seeded), finding_url(seeded, "/timeline"), f"{BASE}/summary"):
        response = caller.get(path)
        assert response.status_code == 200 and response.json()["state"] == "unknown"
        assert "hunter2" not in response.text and "db.internal" not in response.text


# --- writes: who may, and the guards ---------------------------------------------------------------------------


@pytest.mark.parametrize("role", NON_WRITERS)
def test_roles_without_the_permission_cannot_change_a_finding(
    role: str, store: InMemoryUnknownDeviceRepository
) -> None:
    fid = seed(store)
    caller = Operator(role)
    for suffix, body in (
        ("/acknowledge", None),
        ("/investigate", None),
        ("/assign", {"assignee_id": "u"}),
        ("/comment", {"message": "x"}),
        ("/resolve", {"outcome": "resolved", "reason": "x"}),
    ):
        assert caller.post(finding_url(fid, suffix), body).status_code == 403
    assert store.get_finding(fid).state == "new"  # type: ignore[union-attr]


@pytest.mark.parametrize("kind", [PrincipalKind.SERVICE, PrincipalKind.AI])
def test_no_service_or_ai_principal_can_change_a_finding_whatever_its_role(
    kind: PrincipalKind, store: InMemoryUnknownDeviceRepository, scanner: StubScanner
) -> None:
    fid = seed(store)
    app.dependency_overrides[get_current_identity] = lambda: Identity(
        "svc", frozenset({"administrator"}), kind
    )
    client = TestClient(app, raise_server_exceptions=False)
    for suffix, body in (
        ("/acknowledge", None),
        ("/assign", {"assignee_id": "u"}),
        ("/comment", {"message": "x"}),
        ("/resolve", {"outcome": "resolved", "reason": "x"}),
    ):
        assert client.post(finding_url(fid, suffix), json=body).status_code == 403
    assert client.post(f"{BASE}/scan").status_code == 403
    assert scanner.calls == 0 and store.get_finding(fid).state == "new"  # type: ignore[union-attr]
    assert client.get(BASE).status_code == 200  # reads are not human-only


def test_a_missing_or_wrong_csrf_token_changes_nothing(
    store: InMemoryUnknownDeviceRepository,
) -> None:
    fid = seed(store)
    caller = Operator()
    for token in (None, "wrong"):
        response = caller.post(finding_url(fid, "/acknowledge"), csrf=token)
        assert (
            response.status_code == 403
            and response.json()["error"]["code"] == "CSRF_VALIDATION_FAILED"
        )
    assert store.get_finding(fid).state == "new"  # type: ignore[union-attr]


def test_a_foreign_origin_is_refused_even_with_a_valid_token(
    store: InMemoryUnknownDeviceRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NETSIGHT_PUBLIC_BASE_URL", "https://noc.example.test")
    session_policy.cache_clear()
    fid = seed(store)
    response = Operator().post(
        finding_url(fid, "/acknowledge"), headers={"Origin": "https://evil.example"}
    )
    assert response.status_code == 403 and response.json()["error"]["code"] == "ORIGIN_NOT_ALLOWED"
    ok = Operator().post(
        finding_url(fid, "/acknowledge"), headers={"Origin": "https://noc.example.test"}
    )
    assert ok.status_code == 200


def test_authorisation_is_decided_before_csrf(store: InMemoryUnknownDeviceRepository) -> None:
    fid = seed(store)
    response = Operator("technician").post(finding_url(fid, "/acknowledge"), csrf=None)
    assert response.status_code == 403 and response.json()["error"]["code"] == "FORBIDDEN"


# --- writes: the workflow --------------------------------------------------------------------------------------


@pytest.mark.parametrize("role", WRITERS)
def test_the_operating_roles_walk_a_finding_through_its_lifecycle(
    role: str, store: InMemoryUnknownDeviceRepository
) -> None:
    fid = seed(store)
    operator = Operator(role)
    ack = operator.post(finding_url(fid, "/acknowledge"))
    assert ack.status_code == 200 and ack.json()["state"] == "acknowledged"
    validate("unknown_device_finding", ack.json())
    inv = operator.post(finding_url(fid, "/investigate"))
    assert inv.json()["state"] == "investigating"
    done = operator.post(
        finding_url(fid, "/resolve"), {"outcome": "resolved", "reason": "Added to NetBox"}
    )
    assert done.status_code == 200 and done.json()["state"] == "resolved"
    events = store.list_timeline(fid)
    assert [e.kind for e in events] == [
        "detected",
        "state-changed",
        "state-changed",
        "state-changed",
    ]
    assert {e.actor_id for e in events[1:]} == {operator.identity_id}


def test_illegal_moves_are_a_409_and_change_nothing(store: InMemoryUnknownDeviceRepository) -> None:
    fid = seed(store)
    operator = Operator()
    early = operator.post(finding_url(fid, "/investigate"))
    assert early.status_code == 409 and early.json()["error"]["code"] == "ILLEGAL_TRANSITION"
    assert operator.post(finding_url(fid, "/acknowledge")).status_code == 200
    again = operator.post(finding_url(fid, "/acknowledge"))
    assert again.status_code == 409
    assert store.get_finding(fid).state == "acknowledged"  # type: ignore[union-attr]


def test_resolving_needs_a_recent_second_factor_and_changes_nothing_without_it(
    store: InMemoryUnknownDeviceRepository,
) -> None:
    fid = seed(store)
    body = {"outcome": "false-positive", "reason": "Lab device"}
    for age in (None, 1000.0):
        response = Operator(mfa_age=age).post(finding_url(fid, "/resolve"), body)
        assert (
            response.status_code == 403 and response.json()["error"]["code"] == "STEP_UP_REQUIRED"
        )
    assert store.get_finding(fid).state == "new"  # type: ignore[union-attr]
    ok = Operator(mfa_age=60.0).post(finding_url(fid, "/resolve"), body)
    assert ok.status_code == 200 and ok.json()["state"] == "false-positive"


def test_the_other_writes_need_no_second_factor(store: InMemoryUnknownDeviceRepository) -> None:
    fid = seed(store)
    operator = Operator(mfa_age=None)
    assert operator.post(finding_url(fid, "/acknowledge")).status_code == 200
    assert operator.post(finding_url(fid, "/assign"), {"assignee_id": "u"}).status_code == 200
    assert operator.post(finding_url(fid, "/comment"), {"message": "note"}).status_code == 201


@pytest.mark.parametrize(
    "body",
    [
        None,
        {},
        {"outcome": "resolved"},
        {"reason": "x"},
        {"outcome": "resolved", "reason": ""},
        {"outcome": "resolved", "reason": "   "},
        {"outcome": "resolved", "reason": "x" * 1001},
        {"outcome": "acknowledged", "reason": "x"},
        {"outcome": "resolved", "reason": "x", "extra": 1},
    ],
)
def test_a_resolution_must_be_well_formed(
    body: Any, store: InMemoryUnknownDeviceRepository
) -> None:
    fid = seed(store)
    response = Operator().post(finding_url(fid, "/resolve"), body)
    assert response.status_code == 422 and store.get_finding(fid).state == "new"  # type: ignore[union-attr]


def test_assigning_and_unassigning(store: InMemoryUnknownDeviceRepository) -> None:
    fid = seed(store)
    operator = Operator()
    assigned = operator.post(finding_url(fid, "/assign"), {"assignee_id": "oidc:tech-9"})
    assert assigned.json()["assignee_id"] == "oidc:tech-9"
    cleared = operator.post(finding_url(fid, "/assign"), {"assignee_id": None})
    assert cleared.json()["assignee_id"] is None
    for bad in (
        None,
        {},
        {"assignee_id": ""},
        {"assignee_id": "x" * 256},
        {"assignee_id": "u", "x": 1},
    ):
        assert operator.post(finding_url(fid, "/assign"), bad).status_code == 422


def test_a_finished_finding_cannot_be_reassigned_but_can_be_commented(
    store: InMemoryUnknownDeviceRepository,
) -> None:
    fid = seed(store)
    Operator().post(finding_url(fid, "/resolve"), {"outcome": "resolved", "reason": "done"})
    operator = Operator()
    assert operator.post(finding_url(fid, "/assign"), {"assignee_id": "u"}).status_code == 409
    assert (
        operator.post(finding_url(fid, "/comment"), {"message": "post-mortem note"}).status_code
        == 201
    )


def test_a_comment_is_stored_verbatim_and_answered_as_the_event(
    store: InMemoryUnknownDeviceRepository,
) -> None:
    fid = seed(store)
    response = Operator().post(finding_url(fid, "/comment"), {"message": HOSTILE})
    assert response.status_code == 201
    validate("unknown_device_event", response.json())
    assert response.json()["message"] == HOSTILE and response.json()["kind"] == "comment"
    for bad in (
        None,
        {},
        {"message": ""},
        {"message": "  \n"},
        {"message": "x" * 4001},
        {"message": "x", "y": 1},
    ):
        assert Operator().post(finding_url(fid, "/comment"), bad).status_code == 422


def test_writes_to_unknown_or_malformed_ids(store: InMemoryUnknownDeviceRepository) -> None:
    operator = Operator()
    for suffix, body in (
        ("/acknowledge", None),
        ("/investigate", None),
        ("/assign", {"assignee_id": "u"}),
        ("/comment", {"message": "x"}),
        ("/resolve", {"outcome": "resolved", "reason": "x"}),
    ):
        assert operator.post(finding_url(MISSING, suffix), body).status_code == 404
        assert operator.post(finding_url("unknown-device-1", suffix), body).status_code == 422


def test_concurrent_acknowledgements_have_exactly_one_winner(
    store: InMemoryUnknownDeviceRepository,
) -> None:
    fid = seed(store)
    operator = Operator()

    def attempt(_: int) -> int:
        return (
            TestClient(app, raise_server_exceptions=False, cookies=operator.http.cookies)
            .post(
                finding_url(fid, "/acknowledge"),
                headers={"X-CSRF-Token": operator.session.csrf_token},
            )
            .status_code
        )

    with ThreadPoolExecutor(max_workers=6) as pool:
        codes = list(pool.map(attempt, range(6)))
    assert sorted(codes) == [200] + [409] * 5


# --- writes: storage failures and limits -------------------------------------------------------------------------


def test_without_the_store_a_write_is_a_503_and_audited(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    app.dependency_overrides[unknown_device_routes.get_unknown_device_store] = lambda: None
    fid = "unknown-device-6f1c2a9e-0b1d-5c3e-8f4a-123456789abc"
    response = Operator().post(finding_url(fid, "/acknowledge"))
    assert response.status_code == 503 and response.json()["error"]["code"] == "STORE_NOT_CONNECTED"
    assert audit_records(caplog)[-1]["reason"] == "STORE_NOT_CONNECTED"


def test_a_failing_store_is_a_503_that_never_leaks() -> None:
    failing = FailingStore(StorageUnavailableError(SECRET))
    fid = failing.observe(detection()).finding_id
    failing.armed = True
    app.dependency_overrides[unknown_device_routes.get_unknown_device_store] = lambda: failing
    response = Operator().post(finding_url(fid, "/acknowledge"))
    assert response.status_code == 503 and response.json()["error"]["code"] == "STORE_UNAVAILABLE"
    assert "hunter2" not in response.text and "db.internal" not in response.text


def test_writes_are_rate_limited_per_identity(
    store: InMemoryUnknownDeviceRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(unknown_device_routes, "WRITE_LIMIT_PER_MINUTE", 3)
    fid = seed(store)
    operator = Operator()
    codes = [
        operator.post(finding_url(fid, "/comment"), {"message": f"n{i}"}).status_code
        for i in range(4)
    ]
    assert codes == [201, 201, 201, 429]
    assert (
        Operator(subject="sub-2").post(finding_url(fid, "/comment"), {"message": "x"}).status_code
        == 201
    )


def test_a_refused_step_up_does_not_spend_the_write_budget(
    store: InMemoryUnknownDeviceRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(unknown_device_routes, "WRITE_LIMIT_PER_MINUTE", 2)
    fid = seed(store)
    stale = Operator(mfa_age=None)
    for _ in range(5):
        assert (
            stale.post(
                finding_url(fid, "/resolve"), {"outcome": "resolved", "reason": "x"}
            ).status_code
            == 403
        )
    assert stale.post(finding_url(fid, "/comment"), {"message": "still allowed"}).status_code == 201


# --- audit ---------------------------------------------------------------------------------------------------------


def test_writes_are_audited_without_free_text(
    store: InMemoryUnknownDeviceRepository, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    fid = seed(store)
    operator = Operator()
    operator.post(finding_url(fid, "/acknowledge"))
    operator.post(finding_url(fid, "/assign"), {"assignee_id": "oidc:tech-secret-name"})
    operator.post(finding_url(fid, "/comment"), {"message": "very secret comment text"})
    operator.post(
        finding_url(fid, "/resolve"),
        {"outcome": "false-positive", "reason": "very secret reason text"},
    )
    text = json.dumps(audit_records(caplog))
    for secret in ("very secret comment text", "very secret reason text", "tech-secret-name"):
        assert secret not in text
    by_action = {r["action"]: r for r in audit_records(caplog)}
    assert by_action["unknown-device.acknowledge"]["outcome"] == "success"
    assert by_action["unknown-device.acknowledge"]["target"] == fid
    assert by_action["unknown-device.acknowledge"]["actor_id"] == operator.identity_id
    assert by_action["unknown-device.comment"]["comment_length"] == len("very secret comment text")
    assert by_action["unknown-device.resolve"]["outcome_state"] == "false-positive"
    assert "assignee_hash" in by_action["unknown-device.assign"]


def test_refusals_and_failures_are_audited_too(
    store: InMemoryUnknownDeviceRepository, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    fid = seed(store)
    Operator("auditor").post(finding_url(fid, "/acknowledge"))
    Operator().post(finding_url(fid, "/acknowledge"), csrf="bad")
    Operator(mfa_age=None).post(
        finding_url(fid, "/resolve"), {"outcome": "resolved", "reason": "x"}
    )
    Operator().post(finding_url(fid, "/investigate"))
    reasons = {r.get("reason") for r in audit_records(caplog)}
    assert {"permission", "csrf", "step-up", "ILLEGAL_TRANSITION"} <= reasons


def test_reads_are_audited_with_counts_and_filter_names(
    store: InMemoryUnknownDeviceRepository, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    fid = seed(store)
    caller = Caller("auditor")
    caller.get(BASE, state="open", severity="medium")
    caller.get(finding_url(fid))
    by_action = {r["action"]: r for r in audit_records(caplog)}
    assert by_action["unknown-device.list.read"]["filters"] == "state,severity"
    assert by_action["unknown-device.list.read"]["total"] == 1
    assert by_action["unknown-device.item.read"]["target"] == fid


# --- scan ---------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("role", WRITERS)
def test_the_operating_roles_may_scan_now(
    role: str, store: InMemoryUnknownDeviceRepository, scanner: StubScanner
) -> None:
    response = Operator(role).post(f"{BASE}/scan")
    assert response.status_code == 200
    validate("unknown_device_scan", response.json())
    assert response.json()["created"] == 2 and scanner.calls == 1


@pytest.mark.parametrize("role", NON_WRITERS)
def test_other_roles_cannot_scan(
    role: str, store: InMemoryUnknownDeviceRepository, scanner: StubScanner
) -> None:
    assert Operator(role).post(f"{BASE}/scan").status_code == 403 and scanner.calls == 0


def test_a_scan_needs_a_csrf_token_and_the_store(
    store: InMemoryUnknownDeviceRepository, scanner: StubScanner
) -> None:
    assert Operator().post(f"{BASE}/scan", csrf=None).status_code == 403 and scanner.calls == 0
    app.dependency_overrides[unknown_device_routes.get_unknown_device_store] = lambda: None
    response = Operator().post(f"{BASE}/scan")
    assert response.status_code == 503 and response.json()["error"]["code"] == "STORE_NOT_CONNECTED"


def test_a_scan_that_could_not_compare_says_so_with_a_200(
    store: InMemoryUnknownDeviceRepository,
) -> None:
    result = ScanResult(
        "unknown", NOW, (SourceStatus(source="netbox", state="unknown", observed_at=None),)
    )
    app.dependency_overrides[unknown_device_routes.get_unknown_device_scanner] = lambda: (
        StubScanner(result)
    )
    response = Operator().post(f"{BASE}/scan")
    assert response.status_code == 200 and response.json()["state"] == "unknown"
    validate("unknown_device_scan", response.json())


def test_a_scan_that_fails_is_a_503_that_never_leaks(
    store: InMemoryUnknownDeviceRepository,
) -> None:
    for error in (StorageUnavailableError(SECRET), RuntimeError(SECRET)):
        app.dependency_overrides[unknown_device_routes.get_unknown_device_scanner] = (
            lambda e=error: StubScanner(e)
        )  # type: ignore[misc]
        response = Operator().post(f"{BASE}/scan")
        assert response.status_code == 503 and "hunter2" not in response.text


def test_scans_are_rate_limited_and_audited(
    store: InMemoryUnknownDeviceRepository,
    scanner: StubScanner,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    monkeypatch.setattr(unknown_device_routes, "SCAN_LIMIT_PER_MINUTE", 2)
    operator = Operator()
    assert [operator.post(f"{BASE}/scan").status_code for _ in range(3)] == [200, 200, 429]
    scans = [r for r in audit_records(caplog) if r["action"] == "unknown-device.scan"]
    assert (
        scans[0]["created"] == 2
        and scans[0]["unverified"] == 3
        and scans[0]["outcome"] == "success"
    )
    assert scans[-1]["outcome"] == "denied" and scans[-1]["reason"] == "rate-limit"


# --- nothing can execute a quarantine ------------------------------------------------------------------------------


def test_no_route_can_execute_or_approve_a_quarantine() -> None:
    paths = [path for path in app.openapi()["paths"] if "unknown-devices" in path]
    assert len(paths) == 10
    for path in paths:
        assert not any(
            word in path.lower() for word in ("quarantine", "isolate", "execute", "approve")
        )


def test_a_proposed_quarantine_is_always_inert_over_the_wire(
    store: InMemoryUnknownDeviceRepository,
) -> None:
    fid = seed(store, severity="critical", basis="policy-rule", with_action=True)
    action = Caller("security_analyst").get(finding_url(fid)).json()["item"]["proposed_action"]
    assert (action["state"], action["executable"], action["awaiting"]) == (
        "proposed",
        False,
        "action-engine",
    )
