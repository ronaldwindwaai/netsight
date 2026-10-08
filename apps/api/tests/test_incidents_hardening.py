"""S6-2 review follow-ups: scope under lock, CSRF/session, origin checks, audit durability.

Everything here goes through the real session/CSRF stack (no dependency override of the
identity unless a test needs an identity the stack cannot produce).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi import Request
from fastapi.testclient import TestClient
from pydantic import ValidationError
from test_incidents_api import (
    API,
    MISSING_ID,
    Caller,
    ExplodingStore,
    TickingClock,
    audit_records,
    resolve_body,
    seed,
)

from netsight_api import audit, incident_routes
from netsight_api.auth.deps import AuthContext, get_current_identity
from netsight_api.auth.rate_limit import RateLimiter
from netsight_api.auth.session import SessionStore, constant_time_equals
from netsight_api.auth.settings import SessionPolicy, session_policy
from netsight_api.incident_routes import IncidentActor, _mutate, get_optional_incident_store
from netsight_api.main import app
from netsight_api.rbac import Identity, PrincipalKind
from netsight_api.schemas import IncidentResolutionInput, IncidentResolveRequest
from netsight_api.storage import (
    InMemoryIncidentRepository,
    ScopeViolationError,
    StorageUnavailableError,
)

ENV_NAMES = (
    "NETSIGHT_ENV",
    "NETSIGHT_ENABLE_DEV_IDENTITY",
    "NETSIGHT_ALLOWED_ORIGINS",
    "NETSIGHT_PUBLIC_BASE_URL",
    "NETSIGHT_SESSION_SAME_SITE",
    "NETSIGHT_SESSION_ALLOW_SAME_SITE_NONE",
    "NETSIGHT_SESSION_SECURE_COOKIE",
    "NETSIGHT_AUDIT_LOG_LEVEL",
    "NETSIGHT_AUDIT_LOG_DESTINATION",
    "NETSIGHT_AUDIT_LOG_FILE",
    "DATABASE_URL",
    "DATABASE_MIGRATION_URL",
)
GOOD_ORIGIN = "https://netsight.example.com"


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    app.dependency_overrides.clear()
    session_policy.cache_clear()
    monkeypatch.setattr(incident_routes, "_write_limiter", RateLimiter())
    yield
    app.dependency_overrides.clear()
    session_policy.cache_clear()


@pytest.fixture
def store() -> InMemoryIncidentRepository:
    repository = InMemoryIncidentRepository(clock=TickingClock())
    app.dependency_overrides[get_optional_incident_store] = lambda: repository
    return repository


@pytest.fixture
def audit_logger_state() -> Iterator[logging.Logger]:
    """Restore the audit logger exactly as found, whatever a test configures."""
    logger = logging.getLogger("netsight_api.audit")
    handlers, level, propagate = list(logger.handlers), logger.level, logger.propagate
    yield logger
    for handler in list(logger.handlers):
        if handler not in handlers:
            handler.close()
    logger.handlers[:] = handlers
    logger.setLevel(level)
    logger.propagate = propagate


# --- 1. technician scope is enforced under the row lock --------------------------------------


class SpyStore(InMemoryIncidentRepository):
    """Records the scope each write was handed and forbids any unlocked pre-read."""

    def __init__(self) -> None:
        super().__init__(clock=TickingClock())
        self.scopes: list[Any] = []
        self.allow_reads = True

    def get_incident(self, incident_id: str) -> Any:
        assert self.allow_reads, "a write must not pre-read the incident outside the row lock"
        return super().get_incident(incident_id)

    def transition_state(self, incident_id: str, **kwargs: Any) -> Any:
        self.scopes.append(kwargs.get("required_assignee", "<missing>"))
        return super().transition_state(incident_id, **kwargs)

    def append_event(self, incident_id: str, **kwargs: Any) -> Any:
        self.scopes.append(kwargs.get("required_assignee", "<missing>"))
        return super().append_event(incident_id, **kwargs)

    def add_evidence(self, incident_id: str, **kwargs: Any) -> Any:
        self.scopes.append(kwargs.get("required_assignee", "<missing>"))
        return super().add_evidence(incident_id, **kwargs)


WORK_SUFFIXES = [
    ("/acknowledge", None),
    ("/transition", {"to_state": "acknowledged"}),
    ("/comment", {"message": "On site"}),
    ("/evidence", {"evidence_id": "ev-7"}),
]


@pytest.mark.parametrize(("suffix", "body"), WORK_SUFFIXES)
def test_technician_writes_pass_their_identity_as_the_required_assignee_without_a_preread(
    suffix: str, body: Any
) -> None:
    spy = SpyStore()
    app.dependency_overrides[get_optional_incident_store] = lambda: spy
    tech = Caller("technician", "tech-1")
    incident_id = seed(spy, assignee=tech.identity_id)
    spy.allow_reads = False
    response = tech.post(f"{API}/{incident_id}{suffix}", body)
    assert response.status_code in (200, 201), response.text
    assert spy.scopes == [tech.identity_id]


@pytest.mark.parametrize(("suffix", "body"), WORK_SUFFIXES)
def test_full_roles_pass_no_scope(suffix: str, body: Any) -> None:
    spy = SpyStore()
    app.dependency_overrides[get_optional_incident_store] = lambda: spy
    incident_id = seed(spy)
    spy.allow_reads = False
    response = Caller("security_analyst").post(f"{API}/{incident_id}{suffix}", body)
    assert response.status_code in (200, 201), response.text
    assert spy.scopes == [None]


def test_a_store_scope_refusal_is_a_403_audited_as_scope(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app.dependency_overrides[get_optional_incident_store] = lambda: ExplodingStore(
        ScopeViolationError("not assigned")
    )
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    response = Caller("administrator").post(f"{API}/{MISSING_ID}/acknowledge")
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"
    [record] = audit_records(caplog)
    assert (record["outcome"], record["reason"]) == ("denied", "scope")


def test_technician_refusal_on_somebody_elses_incident_is_audited(
    store: InMemoryIncidentRepository, caplog: pytest.LogCaptureFixture
) -> None:
    tech = Caller("technician", "tech-1")
    incident_id = seed(store, assignee="microsoft:tech-2")
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    assert tech.post(f"{API}/{incident_id}/comment", {"message": "x"}).status_code == 403
    [record] = audit_records(caplog)
    assert (record["outcome"], record["reason"], record["target"]) == (
        "denied",
        "scope",
        incident_id,
    )
    assert store.list_timeline(incident_id)[-1].kind == "assignee-changed"


# --- 2. one session resolution, fail-closed CSRF, byte-safe compare ---------------------------


def test_a_request_resolves_its_session_exactly_once(
    store: InMemoryIncidentRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    incident_id = seed(store)
    caller = Caller("administrator")
    calls: list[str] = []
    original = SessionStore.get

    def counting(self: SessionStore, session_id: str, policy: Any) -> Any:
        calls.append(session_id)
        return original(self, session_id, policy)

    monkeypatch.setattr(SessionStore, "get", counting)
    assert caller.post(f"{API}/{incident_id}/comment", {"message": "x"}).status_code == 201
    assert len(calls) == 1


def _identity_with_context(context: AuthContext | None, principal: PrincipalKind) -> Any:
    def dependency(request: Request) -> Identity:
        if context is not None:
            request.state.auth = context
        return Identity("microsoft:ghost", frozenset({"administrator"}), principal)

    return dependency


def test_csrf_fails_closed_when_the_identity_came_from_a_session_that_is_missing(
    store: InMemoryIncidentRepository, caplog: pytest.LogCaptureFixture
) -> None:
    incident_id = seed(store)
    app.dependency_overrides[get_current_identity] = _identity_with_context(
        AuthContext(source="session", session=None), PrincipalKind.HUMAN
    )
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    response = TestClient(app).post(f"{API}/{incident_id}/acknowledge")
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "CSRF_VALIDATION_FAILED"
    assert store.get_incident(incident_id).state == "open"  # type: ignore[union-attr]
    assert [(r["outcome"], r["reason"]) for r in audit_records(caplog)] == [("denied", "csrf")]


def test_a_human_identity_with_no_auth_context_is_not_exempt_from_csrf(
    store: InMemoryIncidentRepository,
) -> None:
    incident_id = seed(store)
    app.dependency_overrides[get_current_identity] = _identity_with_context(
        None, PrincipalKind.HUMAN
    )
    response = TestClient(app).post(f"{API}/{incident_id}/acknowledge")
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "CSRF_VALIDATION_FAILED"


def test_a_non_human_principal_without_a_cookie_is_not_subject_to_csrf(
    store: InMemoryIncidentRepository,
) -> None:
    incident_id = seed(store)
    app.dependency_overrides[get_current_identity] = _identity_with_context(
        None, PrincipalKind.SERVICE
    )
    assert TestClient(app).post(f"{API}/{incident_id}/acknowledge").status_code == 200


@pytest.mark.parametrize("token", ["é".encode(), "☃-token".encode(), b"\xff\xfe", "Ωmega".encode()])
def test_a_non_ascii_csrf_token_is_an_audited_403_not_a_500(
    store: InMemoryIncidentRepository, caplog: pytest.LogCaptureFixture, token: bytes
) -> None:
    incident_id = seed(store)
    caller = Caller("administrator")
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    response = caller.http.post(
        f"{API}/{incident_id}/acknowledge", headers={"X-CSRF-Token": token}
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "CSRF_VALIDATION_FAILED"
    assert [(r["outcome"], r["reason"]) for r in audit_records(caplog)] == [("denied", "csrf")]
    assert store.get_incident(incident_id).state == "open"  # type: ignore[union-attr]


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("abc", "abc", True),
        ("abc", "abd", False),
        ("é", "é", True),
        ("é", "e", False),
        ("é", "É", False),
        ("", "", True),
        ("☃", "abc", False),
    ],
)
def test_constant_time_equals_is_byte_safe(left: str, right: str, expected: bool) -> None:
    assert constant_time_equals(left, right) is expected


# --- 3. dev bridge hardening, origin checks, SameSite guard -----------------------------------


@pytest.fixture
def dev_bridge(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETSIGHT_ENV", "development")
    monkeypatch.setenv("NETSIGHT_ENABLE_DEV_IDENTITY", "true")


def test_dev_bridge_reads_need_no_header(
    store: InMemoryIncidentRepository, dev_bridge: None
) -> None:
    assert TestClient(app).get(API).status_code == 200


def test_dev_bridge_writes_without_the_csrf_header_are_refused_and_audited(
    store: InMemoryIncidentRepository, dev_bridge: None, caplog: pytest.LogCaptureFixture
) -> None:
    incident_id = seed(store)
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    response = TestClient(app).post(f"{API}/{incident_id}/acknowledge")
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "CSRF_VALIDATION_FAILED"
    assert store.get_incident(incident_id).state == "open"  # type: ignore[union-attr]
    assert [(r["outcome"], r["reason"]) for r in audit_records(caplog)] == [("denied", "csrf")]


def test_dev_bridge_writes_with_the_header_are_accepted(
    store: InMemoryIncidentRepository, dev_bridge: None
) -> None:
    incident_id = seed(store)
    response = TestClient(app).post(
        f"{API}/{incident_id}/acknowledge", headers={"X-CSRF-Token": "dev"}
    )
    assert response.status_code == 200


def test_dev_bridge_writes_from_a_foreign_origin_are_refused_even_with_the_header(
    store: InMemoryIncidentRepository, dev_bridge: None
) -> None:
    incident_id = seed(store)
    response = TestClient(app).post(
        f"{API}/{incident_id}/acknowledge",
        headers={"X-CSRF-Token": "dev", "Origin": "https://evil.example"},
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "ORIGIN_NOT_ALLOWED"


def test_dev_bridge_writes_from_an_allowed_origin_are_accepted(
    store: InMemoryIncidentRepository, dev_bridge: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NETSIGHT_ALLOWED_ORIGINS", "http://localhost:3000")
    incident_id = seed(store)
    response = TestClient(app).post(
        f"{API}/{incident_id}/acknowledge",
        headers={"X-CSRF-Token": "dev", "Origin": "http://localhost:3000"},
    )
    assert response.status_code == 200


def test_the_dev_bridge_still_needs_both_flags(store: InMemoryIncidentRepository) -> None:
    assert TestClient(app).get(API).status_code == 401


def post_with(
    caller: Caller, incident_id: str, headers: dict[str, str], *, csrf: bool = True
) -> Any:
    merged = dict(headers)
    if csrf:
        merged["X-CSRF-Token"] = caller.session.csrf_token
    return caller.http.post(f"{API}/{incident_id}/comment", json={"message": "x"}, headers=merged)


@pytest.fixture
def origins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETSIGHT_ALLOWED_ORIGINS", f"{GOOD_ORIGIN}/, HTTP://Localhost:3000")


@pytest.mark.parametrize("origin", [GOOD_ORIGIN, "http://localhost:3000"])
def test_cookie_writes_from_an_allowed_origin_succeed(
    store: InMemoryIncidentRepository, origins: None, origin: str
) -> None:
    incident_id = seed(store)
    assert post_with(Caller("administrator"), incident_id, {"Origin": origin}).status_code == 201


def test_the_public_base_url_origin_is_allowed_without_extra_configuration(
    store: InMemoryIncidentRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NETSIGHT_PUBLIC_BASE_URL", "https://ns.example.org/app/")
    incident_id = seed(store)
    caller = Caller("administrator")
    assert post_with(caller, incident_id, {"Origin": "https://ns.example.org"}).status_code == 201
    assert post_with(caller, incident_id, {"Origin": "https://ns.example.org:8443"}).status_code == 403


@pytest.mark.parametrize(
    "origin",
    [
        "https://evil.example",
        "null",
        "",
        GOOD_ORIGIN + ".evil.example",
        "http://netsight.example.com",
        "https://netsight.example.com:444",
        "not a url",
        "javascript:alert(1)",
        "https://user@netsight.example.com",
    ],
)
def test_cookie_writes_from_any_other_origin_are_refused_even_with_a_valid_token(
    store: InMemoryIncidentRepository,
    origins: None,
    caplog: pytest.LogCaptureFixture,
    origin: str,
) -> None:
    incident_id = seed(store)
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    response = post_with(Caller("administrator"), incident_id, {"Origin": origin})
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "ORIGIN_NOT_ALLOWED"
    assert store.list_timeline(incident_id) == []
    assert [(r["outcome"], r["reason"]) for r in audit_records(caplog)] == [("denied", "origin")]


def test_an_origin_with_nothing_configured_fails_closed(
    store: InMemoryIncidentRepository,
) -> None:
    incident_id = seed(store)
    response = post_with(Caller("administrator"), incident_id, {"Origin": GOOD_ORIGIN})
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "ORIGIN_NOT_ALLOWED"


def test_a_non_browser_client_without_origin_or_referer_works_with_a_valid_token(
    store: InMemoryIncidentRepository, origins: None
) -> None:
    incident_id = seed(store)
    assert post_with(Caller("administrator"), incident_id, {}).status_code == 201


def test_a_non_browser_client_without_origin_still_needs_the_token(
    store: InMemoryIncidentRepository, origins: None
) -> None:
    incident_id = seed(store)
    response = post_with(Caller("administrator"), incident_id, {}, csrf=False)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "CSRF_VALIDATION_FAILED"


def test_a_bad_token_is_reported_as_csrf_even_from_an_allowed_origin(
    store: InMemoryIncidentRepository, origins: None
) -> None:
    incident_id = seed(store)
    response = post_with(Caller("administrator"), incident_id, {"Origin": GOOD_ORIGIN}, csrf=False)
    assert response.json()["error"]["code"] == "CSRF_VALIDATION_FAILED"


@pytest.mark.parametrize(
    ("referer", "status"),
    [
        (GOOD_ORIGIN + "/incidents/x?y=1", 201),
        ("http://localhost:3000/", 201),
        ("https://evil.example/" + GOOD_ORIGIN, 403),
        (GOOD_ORIGIN + ".evil.example/", 403),
        ("garbage", 403),
        ("", 403),
    ],
)
def test_referer_is_checked_when_origin_is_absent(
    store: InMemoryIncidentRepository, origins: None, referer: str, status: int
) -> None:
    incident_id = seed(store)
    response = post_with(Caller("administrator"), incident_id, {"Referer": referer})
    assert response.status_code == status, response.text


def test_origin_takes_precedence_over_a_friendly_referer(
    store: InMemoryIncidentRepository, origins: None
) -> None:
    incident_id = seed(store)
    response = post_with(
        Caller("administrator"),
        incident_id,
        {"Origin": "https://evil.example", "Referer": GOOD_ORIGIN + "/"},
    )
    assert response.status_code == 403


def test_origin_is_not_required_for_reads(store: InMemoryIncidentRepository) -> None:
    response = Caller("auditor").http.get(API, headers={"Origin": "https://evil.example"})
    assert response.status_code == 200


def test_samesite_none_is_rejected_unless_explicitly_allowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NETSIGHT_SESSION_SAME_SITE", "none")
    with pytest.raises(ValidationError, match="same_site"):
        SessionPolicy()
    monkeypatch.setenv("NETSIGHT_SESSION_ALLOW_SAME_SITE_NONE", "true")
    assert SessionPolicy().same_site == "none"


def test_samesite_none_even_when_allowed_requires_a_secure_cookie(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NETSIGHT_SESSION_SAME_SITE", "none")
    monkeypatch.setenv("NETSIGHT_SESSION_ALLOW_SAME_SITE_NONE", "true")
    monkeypatch.setenv("NETSIGHT_SESSION_SECURE_COOKIE", "false")
    with pytest.raises(ValidationError, match="secure"):
        SessionPolicy()


@pytest.mark.parametrize("value", ["lax", "strict"])
def test_samesite_lax_and_strict_need_no_opt_in(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv("NETSIGHT_SESSION_SAME_SITE", value)
    assert SessionPolicy().same_site == value


# --- 4. audit durability and logging configuration ---------------------------------------------


def _bare_request() -> Request:
    return Request({"type": "http", "method": "POST", "path": "/", "headers": [], "state": {}})


def test_the_success_audit_is_emitted_even_if_the_client_disconnects_mid_write(
    caplog: pytest.LogCaptureFixture,
) -> None:
    started, release = threading.Event(), threading.Event()

    class SlowStore(InMemoryIncidentRepository):
        def add_evidence(self, incident_id: str, **kwargs: Any) -> Any:
            started.set()
            assert release.wait(10)
            return super().add_evidence(incident_id, **kwargs)

    slow = SlowStore(clock=TickingClock())
    incident_id = seed(slow)
    actor = IncidentActor(Identity("microsoft:eng", frozenset({"administrator"})), True)
    caplog.set_level(logging.INFO, logger="netsight_api.audit")

    async def scenario() -> None:
        task = asyncio.ensure_future(
            _mutate(
                _bare_request(),
                slow,
                actor,
                action="incident.evidence",
                incident_id=incident_id,
                operation=lambda s: s.add_evidence(
                    incident_id, evidence_id="ev-1", actor_id="microsoft:eng"
                ),
            )
        )
        assert await asyncio.to_thread(started.wait, 10)
        task.cancel()  # the client went away while the committed write is in flight
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        # Let the (uncancellable) worker thread finish and flush its audit record.
        for _ in range(100):
            if audit_records(caplog):
                break
            await asyncio.sleep(0.05)

    asyncio.run(scenario())
    assert slow.get_incident(incident_id).evidence_ids == ["ev-1"]  # type: ignore[union-attr]
    [record] = audit_records(caplog)
    assert (record["action"], record["outcome"]) == ("incident.evidence", "success")


def test_the_failure_audit_is_also_emitted_if_the_client_disconnects(
    caplog: pytest.LogCaptureFixture,
) -> None:
    started, release, armed = threading.Event(), threading.Event(), threading.Event()

    class SlowFailing(InMemoryIncidentRepository):
        def transition_state(self, incident_id: str, **kwargs: Any) -> Any:
            if armed.is_set():  # only the request under test blocks, not the seeding
                started.set()
                assert release.wait(10)
            return super().transition_state(incident_id, **kwargs)

    slow = SlowFailing(clock=TickingClock())
    incident_id = seed(slow, state="closed")
    armed.set()
    actor = IncidentActor(Identity("microsoft:eng", frozenset({"administrator"})), True)
    caplog.set_level(logging.INFO, logger="netsight_api.audit")

    async def scenario() -> None:
        task = asyncio.ensure_future(
            _mutate(
                _bare_request(),
                slow,
                actor,
                action="incident.acknowledge",
                incident_id=incident_id,
                operation=lambda s: s.transition_state(
                    incident_id, to_state="acknowledged", actor_id="microsoft:eng"
                ),
            )
        )
        assert await asyncio.to_thread(started.wait, 10)
        task.cancel()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        for _ in range(100):
            if audit_records(caplog):
                break
            await asyncio.sleep(0.05)

    asyncio.run(scenario())
    [record] = audit_records(caplog)
    assert (record["outcome"], record["reason"]) == ("failure", "ILLEGAL_TRANSITION")


def test_a_failing_audit_sink_does_not_turn_a_committed_write_into_an_error(
    store: InMemoryIncidentRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    incident_id = seed(store)

    def broken(*_args: object, **_kwargs: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(audit._LOGGER, "log", broken)
    response = Caller("administrator").post(f"{API}/{incident_id}/comment", {"message": "x"})
    assert response.status_code == 201
    assert len(store.list_timeline(incident_id)) == 1


def test_audit_records_carry_a_utc_timestamp(
    store: InMemoryIncidentRepository, caplog: pytest.LogCaptureFixture
) -> None:
    incident_id = seed(store)
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    Caller("administrator").post(f"{API}/{incident_id}/comment", {"message": "x"})
    [record] = audit_records(caplog)
    assert record["ts"].endswith("+00:00") or record["ts"].endswith("Z")


def test_configured_audit_logging_emits_info_json_lines_to_stderr(
    audit_logger_state: logging.Logger, capsys: pytest.CaptureFixture[str]
) -> None:
    audit_logger_state.setLevel(logging.NOTSET)
    audit.configure_audit_logging({})
    assert audit_logger_state.isEnabledFor(logging.INFO)
    audit.record_audit("incident.comment", outcome="success", actor_id="u-1", correlation_id="c-1")
    lines = [line for line in capsys.readouterr().err.splitlines() if line.strip()]
    [line] = lines
    record = json.loads(line)
    assert (record["event"], record["action"], record["outcome"]) == (
        "audit",
        "incident.comment",
        "success",
    )


def test_unconfigured_python_logging_would_drop_info_audit_records(
    audit_logger_state: logging.Logger,
) -> None:
    """Documents why configuration is required: the default effective level is WARNING."""
    audit_logger_state.setLevel(logging.NOTSET)
    assert not logging.getLogger("netsight_api.audit").isEnabledFor(logging.INFO)


def test_audit_logging_can_write_to_a_file_and_is_idempotent(
    audit_logger_state: logging.Logger, tmp_path: Path
) -> None:
    target = tmp_path / "audit.jsonl"
    env = {"NETSIGHT_AUDIT_LOG_DESTINATION": "file", "NETSIGHT_AUDIT_LOG_FILE": str(target)}
    audit.configure_audit_logging(env)
    audit.configure_audit_logging(env)
    audit.record_audit("incident.assign", outcome="denied", actor_id="u-1", correlation_id="c-1")
    for handler in audit_logger_state.handlers:
        handler.flush()
    [line] = target.read_text(encoding="utf-8").splitlines()
    assert json.loads(line)["outcome"] == "denied"
    assert sum(getattr(h, "netsight_audit", False) for h in audit_logger_state.handlers) == 1


def test_audit_log_level_can_be_raised_to_warning(
    audit_logger_state: logging.Logger, capsys: pytest.CaptureFixture[str]
) -> None:
    audit.configure_audit_logging({"NETSIGHT_AUDIT_LOG_LEVEL": "WARNING"})
    audit.record_audit("a", outcome="success", actor_id="u", correlation_id="c")
    audit.record_audit("a", outcome="denied", actor_id="u", correlation_id="c")
    [line] = [x for x in capsys.readouterr().err.splitlines() if x.strip()]
    assert json.loads(line)["outcome"] == "denied"


@pytest.mark.parametrize(
    "env",
    [
        {"NETSIGHT_AUDIT_LOG_LEVEL": "ERROR"},  # would silently drop denied/failed audits
        {"NETSIGHT_AUDIT_LOG_LEVEL": "nonsense"},
        {"NETSIGHT_AUDIT_LOG_DESTINATION": "file"},  # file without a path
        {"NETSIGHT_AUDIT_LOG_DESTINATION": "syslog"},
    ],
)
def test_invalid_audit_logging_configuration_fails_at_startup(
    audit_logger_state: logging.Logger, env: dict[str, str]
) -> None:
    with pytest.raises(ValueError):
        audit.configure_audit_logging(env)


def test_application_startup_enables_info_audit_logging(
    audit_logger_state: logging.Logger,
) -> None:
    audit_logger_state.setLevel(logging.NOTSET)
    with TestClient(app):
        assert audit_logger_state.isEnabledFor(logging.INFO)
        assert any(getattr(h, "netsight_audit", False) for h in audit_logger_state.handlers)


# --- 5. audit hygiene ---------------------------------------------------------------------------


def test_a_refusal_targets_the_validated_id(
    store: InMemoryIncidentRepository, caplog: pytest.LogCaptureFixture
) -> None:
    incident_id = seed(store)
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    Caller("auditor").post(f"{API}/{incident_id}/comment", {"message": "x"})
    Caller("administrator").post(f"{API}/{incident_id}/comment", {"message": "x"}, csrf="bad")
    assert [r["target"] for r in audit_records(caplog)] == [incident_id, incident_id]


@pytest.mark.parametrize("hostile", ["x%0A{%22event%22:%22forged%22}", "..%2F..%2Fpasswd", "A" * 300])
def test_a_malformed_path_id_is_never_echoed_into_the_audit_log(
    store: InMemoryIncidentRepository, caplog: pytest.LogCaptureFixture, hostile: str
) -> None:
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    response = Caller("auditor").post(f"{API}/{hostile}/comment", {"message": "x"})
    assert response.status_code in (404, 422)
    assert "forged" not in caplog.text
    assert "passwd" not in caplog.text
    assert "AAAA" not in caplog.text


def test_free_form_values_are_logged_as_a_length_and_hash_never_verbatim(
    store: InMemoryIncidentRepository, caplog: pytest.LogCaptureFixture
) -> None:
    incident_id = seed(store)
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    caller = Caller("administrator")
    assert (
        caller.post(
            f"{API}/{incident_id}/assign", {"assignee_id": "microsoft:sub-secret-9"}
        ).status_code
        == 200
    )
    assert (
        caller.post(f"{API}/{incident_id}/evidence", {"evidence_id": "ev-secret-1"}).status_code
        == 200
    )
    assert "sub-secret-9" not in caplog.text
    assert "ev-secret-1" not in caplog.text
    assign, evidence = audit_records(caplog)
    assert assign["assignee_length"] == len("microsoft:sub-secret-9")
    assert assign["assignee_hash"] == hashlib.sha256(b"microsoft:sub-secret-9").hexdigest()[:16]
    assert evidence["evidence_length"] == len("ev-secret-1")
    assert evidence["evidence_hash"] == hashlib.sha256(b"ev-secret-1").hexdigest()[:16]
    assert "assignee_id" not in assign and "evidence_id" not in evidence


def test_unassigning_is_audited_without_a_hash(
    store: InMemoryIncidentRepository, caplog: pytest.LogCaptureFixture
) -> None:
    incident_id = seed(store, assignee="microsoft:sub-9")
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    Caller("administrator").post(f"{API}/{incident_id}/assign", {"assignee_id": None})
    [record] = audit_records(caplog)
    assert record["assignee_cleared"] is True
    assert "assignee_hash" not in record


def test_long_actor_ids_are_hashed_not_truncated_so_they_cannot_collide(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    shared = "a" * 200
    for suffix in ("1", "2"):
        audit.record_audit("x", outcome="success", actor_id=shared + suffix, correlation_id="c")
    exact = "b" * audit.MAX_FIELD_LENGTH
    audit.record_audit("x", outcome="success", actor_id=exact, correlation_id="c")
    first, second, kept = audit_records(caplog)
    assert first["actor_id"] != second["actor_id"]
    for record in (first, second):
        assert record["actor_id"].startswith("sha256:")
        assert len(record["actor_id"]) <= audit.MAX_FIELD_LENGTH
    assert first["actor_id"] == "sha256:" + hashlib.sha256((shared + "1").encode()).hexdigest()
    assert kept["actor_id"] == exact


def test_fingerprint_is_stable_and_short() -> None:
    assert audit.fingerprint("abc") == hashlib.sha256(b"abc").hexdigest()[:16]
    assert audit.fingerprint("é") == hashlib.sha256("é".encode()).hexdigest()[:16]


# --- 6. error mapping, resolution boundary, pagination ------------------------------------------


def _validation_error() -> ValidationError:
    try:
        IncidentResolutionInput.model_validate({})
    except ValidationError as error:
        return error
    raise AssertionError("expected a validation error")


@pytest.mark.parametrize(
    ("error", "status", "code"),
    [
        (_validation_error(), 422, "VALIDATION_ERROR"),
        (ValueError("hunter2 internal"), 500, "INTERNAL_ERROR"),
        (KeyError("hunter2"), 500, "INTERNAL_ERROR"),
        (StorageUnavailableError("hunter2"), 503, "STORE_UNAVAILABLE"),
    ],
    ids=["pydantic", "plain-valueerror", "keyerror", "unavailable"],
)
def test_only_known_errors_map_to_client_errors(
    error: Exception, status: int, code: str, caplog: pytest.LogCaptureFixture
) -> None:
    app.dependency_overrides[get_optional_incident_store] = lambda: ExplodingStore(error)
    caplog.set_level(logging.DEBUG)
    response = Caller("administrator").post(f"{API}/{MISSING_ID}/acknowledge")
    assert (response.status_code, response.json()["error"]["code"]) == (status, code)
    assert "hunter2" not in response.text
    assert "hunter2" not in caplog.text


def test_resolution_revalidation_failure_is_audited_and_a_422(
    store: InMemoryIncidentRepository,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    incident_id = seed(store, state="mitigated")

    def boom(_self: IncidentResolveRequest) -> IncidentResolutionInput:
        raise _validation_error()

    monkeypatch.setattr(IncidentResolveRequest, "to_resolution", boom)
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    response = Caller("administrator").post(f"{API}/{incident_id}/resolve", resolve_body())
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"
    [record] = audit_records(caplog)
    assert (record["action"], record["outcome"], record["reason"]) == (
        "incident.resolve",
        "failure",
        "VALIDATION_ERROR",
    )
    assert store.get_incident(incident_id).state == "mitigated"  # type: ignore[union-attr]


def test_a_full_final_page_still_offers_one_empty_trailing_page(
    store: InMemoryIncidentRepository,
) -> None:
    for n in range(4):
        seed(store, title=f"inc {n}")
    caller = Caller("auditor")
    second = caller.get(API, limit=2, offset=2).json()
    assert len(second["incidents"]) == 2
    assert second["next_offset"] == 4  # documented: a full final page yields one empty page
    trailing = caller.get(API, limit=2, offset=4).json()
    assert trailing["incidents"] == []
    assert trailing["next_offset"] is None


class FixedPageStore(InMemoryIncidentRepository):
    """Always returns a full page, so only the route's offset arithmetic is under test."""

    def __init__(self) -> None:
        super().__init__(clock=TickingClock())
        self.template = seed(self)

    def list_incidents(self, *, limit: int = 50, **_: Any) -> Any:
        found = self.get_incident(self.template)
        assert found is not None
        return [found] * limit


@pytest.mark.parametrize(
    ("offset", "limit", "expected"),
    [
        (0, 50, 50),
        (9_900, 50, 9_950),
        (9_950, 50, 10_000),  # the last reachable page is still offered
        (9_951, 50, None),  # the next offset would exceed the 10,000 cap
        (10_000, 50, None),
        (10_000, 1, None),
        (9_999, 1, 10_000),
    ],
)
def test_next_offset_never_exceeds_the_offset_cap(
    offset: int, limit: int, expected: int | None
) -> None:
    app.dependency_overrides[get_optional_incident_store] = lambda: FixedPageStore()
    body = Caller("auditor").get(API, limit=limit, offset=offset).json()
    assert body["state"] == "ok"
    assert body["next_offset"] == expected

