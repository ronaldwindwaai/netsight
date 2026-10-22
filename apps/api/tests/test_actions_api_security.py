"""Security of the controlled-action routes (Step 12): authz bypass, self-approval, replay and TOCTOU on
approval, step-up, CSRF and origin, the kill switch, rate limits, audit integrity and no generic path."""

from __future__ import annotations

import logging
import threading
from collections.abc import Iterator
from typing import Any

import pytest
from actions_api_support import (
    BASE,
    Clock,
    FindingStub,
    Person,
    clean_wiring,
    install_clock,
    install_findings,
    install_runtime,
    isolate_body,
    port_body,
)
from alerting_support import audit_records
from fastapi.testclient import TestClient

from netsight_api import actions_route_support as support
from netsight_api.actions.wiring import ActionRuntime
from netsight_api.auth.deps import get_current_identity
from netsight_api.auth.rate_limit import RateLimiter
from netsight_api.auth.settings import session_policy
from netsight_api.main import app
from netsight_api.rbac import Identity, PrincipalKind

READERS = ["administrator", "network_engineer", "security_analyst", "technician", "auditor"]
DENIED = ["management", "superuser"]
ID = "action-00000000-0000-4000-8000-000000000000"


@pytest.fixture(autouse=True)
def _wiring(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    yield from clean_wiring(monkeypatch)


@pytest.fixture
def clock() -> Clock:
    return install_clock()


@pytest.fixture
def findings() -> FindingStub:
    return install_findings()


@pytest.fixture
def runtime(clock: Clock, findings: FindingStub) -> ActionRuntime:
    return install_runtime(clock, findings)


def created(person: Person, body: dict[str, Any] | None = None) -> dict[str, Any]:
    response = person.create(body)
    assert response.status_code == 201, response.text
    return response.json()  # type: ignore[no-any-return]


# --- authentication and authorisation ----------------------------------------------------------------------------


@pytest.mark.parametrize("role", READERS)
def test_reader_roles_read(role: str, runtime: ActionRuntime) -> None:
    person = Person(role)
    assert person.get(f"{BASE}/status").status_code == 200
    assert person.get(BASE).status_code == 200


@pytest.mark.parametrize("role", DENIED)
def test_management_and_unknown_roles_are_denied_and_it_is_audited(
    role: str, runtime: ActionRuntime, caplog: pytest.LogCaptureFixture
) -> None:
    person = Person(role)
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        for path in (f"{BASE}/status", BASE, f"{BASE}/{ID}"):
            assert person.get(path).status_code == 403
        assert person.create().status_code == 403
    denied = [r for r in audit_records(caplog) if r["outcome"] == "denied"]
    assert len(denied) == 4 and all(r["reason"] == "permission" for r in denied)


@pytest.mark.parametrize("role", ["auditor", "management"])
def test_roles_without_propose_cannot_propose(role: str, runtime: ActionRuntime) -> None:
    assert Person(role).create().status_code == 403


def test_a_technician_may_propose_low_risk_but_not_high_risk(runtime: ActionRuntime) -> None:
    technician = Person("technician")
    low = technician.create(port_body("switch.port.enable"))
    assert low.status_code == 201 and low.json()["risk"] == "B"
    for body in (isolate_body(), port_body("switch.port.disable")):
        response = technician.create(body)
        assert response.status_code == 403, body
        assert response.json()["error"]["code"] == "FORBIDDEN"
    assert Person("auditor").get(BASE).json()["total"] == 1


@pytest.mark.parametrize(
    "role", ["network_engineer", "security_analyst", "technician", "auditor", "management"]
)
def test_only_the_administrator_may_approve_reject_or_execute(
    role: str, runtime: ActionRuntime
) -> None:
    request = created(Person("network_engineer"))
    person = Person(role)
    assert person.approve(request).status_code == 403
    assert person.decide(request, "reject", reason="Because I said so").status_code == 403
    assert person.execute(request).status_code == 403
    state = Person("auditor").show(request["id"]).json()["request"]
    assert state["state"] == "pending-approval" and state["approvals"] == []


@pytest.mark.parametrize("kind", [PrincipalKind.SERVICE, PrincipalKind.AI])
def test_a_service_or_ai_principal_never_approves_executes_or_stops(
    kind: PrincipalKind, runtime: ActionRuntime
) -> None:
    request = created(Person("network_engineer"))
    app.dependency_overrides[get_current_identity] = lambda: Identity(
        id="svc", roles=frozenset({"administrator"}), principal=kind
    )
    client = TestClient(app, raise_server_exceptions=False)
    body = {"expected_digest": request["digest"], "expected_version": request["version"]}
    assert client.post(f"{BASE}/{request['id']}/approve", json=body).status_code == 403
    assert (
        client.post(
            f"{BASE}/{request['id']}/reject", json={**body, "reason": "nope nope"}
        ).status_code
        == 403
    )
    assert (
        client.post(
            f"{BASE}/{request['id']}/execute", json=body, headers={"Idempotency-Key": "k" * 20}
        ).status_code
        == 403
    )
    assert (
        client.post(f"{BASE}/kill-switch", json={"engaged": True, "reason": "stop it"}).status_code
        == 403
    )


def test_an_ai_principal_may_propose_and_is_recorded_as_such(runtime: ActionRuntime) -> None:
    app.dependency_overrides[get_current_identity] = lambda: Identity(
        id="agent-1", roles=frozenset({"network_engineer"}), principal=PrincipalKind.AI
    )
    client = TestClient(app, raise_server_exceptions=False)
    response = client.post(
        BASE, json=isolate_body(), headers={"Idempotency-Key": "agent-key-0000000001"}
    )
    assert response.status_code == 201
    assert response.json()["requester"] == {"id": "agent-1", "kind": "ai"}
    assert response.json()["state"] == "pending-approval"  # a person still has to approve it


# --- self-approval, replay and TOCTOU -------------------------------------------------------------------------------


def test_a_requester_cannot_approve_their_own_request_even_as_administrator(
    runtime: ActionRuntime,
) -> None:
    admin = Person("administrator")
    request = created(admin)
    response = admin.approve(request)
    assert response.status_code == 409 and response.json()["error"]["code"] == "SELF_APPROVAL"
    assert admin.show(request["id"]).json()["request"]["approvals"] == []


def test_two_sessions_of_the_requester_are_still_the_requester(runtime: ActionRuntime) -> None:
    first = Person("administrator", "same-subject")
    request = created(first)
    second = Person("administrator", "same-subject")
    assert second.approve(request).json()["error"]["code"] == "SELF_APPROVAL"


def test_an_approval_of_what_was_not_seen_is_refused(runtime: ActionRuntime) -> None:
    request = created(Person("network_engineer"))
    admin = Person("administrator")
    wrong_digest = admin.post(
        f"{BASE}/{request['id']}/approve",
        {"expected_digest": "sha256:" + "0" * 64, "expected_version": request["version"]},
    )
    assert (
        wrong_digest.status_code == 409 and wrong_digest.json()["error"]["code"] == "STALE_REQUEST"
    )
    wrong_version = admin.post(
        f"{BASE}/{request['id']}/approve",
        {"expected_digest": request["digest"], "expected_version": request["version"] + 1},
    )
    assert wrong_version.status_code == 409
    assert Person("auditor").show(request["id"]).json()["request"]["state"] == "pending-approval"


def test_a_replayed_approval_cannot_authorise_a_later_state(runtime: ActionRuntime) -> None:
    engineer, admin, other = (
        Person("network_engineer"),
        Person("administrator"),
        Person("administrator", "other"),
    )
    request = created(engineer)
    assert admin.approve(request).status_code == 200
    replay = other.approve(request)  # the request they captured is now out of date
    assert replay.status_code == 409 and replay.json()["error"]["code"] == "STALE_REQUEST"
    assert len(Person("auditor").show(request["id"]).json()["request"]["approvals"]) == 1


def test_a_parallel_flood_of_approvals_records_exactly_one(runtime: ActionRuntime) -> None:
    request = created(Person("network_engineer"))
    admins = [Person("administrator", f"admin-{i}") for i in range(6)]
    results: list[int] = []
    barrier = threading.Barrier(len(admins))

    def worker(person: Person) -> None:
        barrier.wait()
        results.append(person.approve(request).status_code)

    threads = [threading.Thread(target=worker, args=(a,)) for a in admins]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results) == [200, 409, 409, 409, 409, 409]
    assert len(Person("auditor").show(request["id"]).json()["request"]["approvals"]) == 1


def test_an_approval_cannot_name_a_different_approver_in_the_body(runtime: ActionRuntime) -> None:
    request = created(Person("network_engineer"))
    response = Person("administrator").post(
        f"{BASE}/{request['id']}/approve",
        {
            "expected_digest": request["digest"],
            "expected_version": request["version"],
            "approver_id": "someone",
        },
    )
    assert response.status_code == 422


def test_a_cancel_by_a_stranger_is_refused_but_the_requester_and_an_administrator_may(
    runtime: ActionRuntime,
) -> None:
    owner, stranger, admin = (
        Person("network_engineer"),
        Person("security_analyst"),
        Person("administrator"),
    )
    request = created(owner)
    assert stranger.decide(request, "cancel", reason="not mine").status_code == 403
    assert Person("technician").decide(request, "cancel", reason="not mine").status_code == 403
    assert admin.decide(request, "cancel", reason="Stopping this one").status_code == 200


# --- step-up ----------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("mfa_age", [None, 100_000.0])
def test_approving_and_executing_need_a_recent_second_factor(
    mfa_age: float | None, runtime: ActionRuntime
) -> None:
    request = created(Person("network_engineer"))
    stale = Person("administrator", "stale", mfa_age=mfa_age)
    response = stale.approve(request)
    assert response.status_code == 403 and response.json()["error"]["code"] == "STEP_UP_REQUIRED"
    assert Person("auditor").show(request["id"]).json()["request"]["state"] == "pending-approval"
    approved = Person("administrator", "fresh").approve(request).json()
    again = stale.execute(approved)
    assert again.status_code == 403 and again.json()["error"]["code"] == "STEP_UP_REQUIRED"
    assert Person("auditor").show(request["id"]).json()["request"]["state"] == "approved"


def test_rejecting_and_proposing_do_not_need_step_up(runtime: ActionRuntime) -> None:
    engineer = Person("network_engineer", mfa_age=None)
    request = created(engineer)
    assert (
        Person("administrator", mfa_age=None)
        .decide(request, "reject", reason="Not justified")
        .status_code
        == 200
    )


# --- CSRF and origin ------------------------------------------------------------------------------------------------------


def write_calls(person: Person, request: dict[str, Any]) -> list[Any]:
    body = {"expected_digest": request["digest"], "expected_version": request["version"]}
    key = {"Idempotency-Key": "csrf-key-00000000001"}
    return [
        lambda **kw: person.post(BASE, isolate_body(), headers=key, **kw),
        lambda **kw: person.post(
            f"{BASE}/from-finding",
            {
                "finding_id": "unknown-device-aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                "expected_evidence_version": 3,
                "reason": "Seen again",
            },
            headers=key,
            **kw,
        ),
        lambda **kw: person.post(f"{BASE}/{request['id']}/approve", body, **kw),
        lambda **kw: person.post(
            f"{BASE}/{request['id']}/reject", {**body, "reason": "No thanks"}, **kw
        ),
        lambda **kw: person.post(
            f"{BASE}/{request['id']}/cancel", {**body, "reason": "No thanks"}, **kw
        ),
        lambda **kw: person.post(f"{BASE}/{request['id']}/execute", body, headers=key, **kw),
        lambda **kw: person.post(
            f"{BASE}/kill-switch", {"engaged": True, "reason": "stop it"}, **kw
        ),
    ]


@pytest.mark.parametrize("index", range(7))
@pytest.mark.parametrize("csrf", [None, "wrong-token"])
def test_every_write_needs_the_csrf_token(
    index: int, csrf: str | None, runtime: ActionRuntime
) -> None:
    request = created(Person("network_engineer"))
    admin = Person("administrator")
    response = write_calls(admin, request)[index](csrf=csrf)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "CSRF_VALIDATION_FAILED"
    assert Person("auditor").show(request["id"]).json()["request"]["state"] == "pending-approval"
    assert Person("auditor").get(f"{BASE}/status").json()["kill_switch"]["engaged"] is False


def test_a_foreign_origin_is_refused_even_with_a_valid_token(
    runtime: ActionRuntime, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NETSIGHT_PUBLIC_BASE_URL", "https://noc.example.test")
    session_policy.cache_clear()
    person = Person("network_engineer")
    evil = person.post(
        BASE,
        isolate_body(),
        headers={"Origin": "https://evil.example", "Idempotency-Key": "origin-key-0000000001"},
    )
    assert evil.status_code == 403 and evil.json()["error"]["code"] == "ORIGIN_NOT_ALLOWED"
    good = person.post(
        BASE,
        isolate_body(),
        headers={"Origin": "https://noc.example.test", "Idempotency-Key": "origin-key-0000000002"},
    )
    assert good.status_code == 201


def test_authorisation_is_decided_before_csrf(runtime: ActionRuntime) -> None:
    response = Person("auditor").post(
        BASE, isolate_body(), csrf=None, headers={"Idempotency-Key": "k" * 20}
    )
    assert response.status_code == 403 and response.json()["error"]["code"] == "FORBIDDEN"


# --- the kill switch --------------------------------------------------------------------------------------------------


def test_the_kill_switch_stops_proposals_approvals_and_runs_but_not_reads_or_cancels(
    runtime: ActionRuntime, caplog: pytest.LogCaptureFixture
) -> None:
    engineer, admin = Person("network_engineer"), Person("administrator")
    pending = created(engineer)
    approved = admin.approve(created(engineer)).json()
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        engaged = admin.post(
            f"{BASE}/kill-switch", {"engaged": True, "reason": "Suspected compromise"}
        )
    assert engaged.status_code == 200
    assert (
        engaged.json()["kill_switch"]["engaged"] is True
        and engaged.json()["kill_switch"]["source"] == "runtime"
    )
    assert any(
        r["action"] == "actions.kill-switch" and r["outcome"] == "success"
        for r in audit_records(caplog)
    )
    for response in (engineer.create(), admin.approve(pending), admin.execute(approved)):
        assert response.status_code == 503 and response.json()["error"]["code"] == "KILL_SWITCH"
    assert (
        admin.get(BASE).status_code == 200
        and admin.get(f"{BASE}/status").json()["kill_switch"]["engaged"] is True
    )
    assert engineer.decide(pending, "cancel", reason="Stand down").status_code == 200
    released = admin.post(f"{BASE}/kill-switch", {"engaged": False, "reason": "All clear"})
    assert released.status_code == 200 and released.json()["kill_switch"]["engaged"] is False
    assert admin.execute(approved).status_code == 200


def test_releasing_the_kill_switch_needs_step_up_but_engaging_does_not(
    runtime: ActionRuntime,
) -> None:
    stale = Person("administrator", "stale", mfa_age=None)
    assert (
        stale.post(f"{BASE}/kill-switch", {"engaged": True, "reason": "Stop now"}).status_code
        == 200
    )
    release = stale.post(f"{BASE}/kill-switch", {"engaged": False, "reason": "All clear"})
    assert release.status_code == 403 and release.json()["error"]["code"] == "STEP_UP_REQUIRED"


def test_the_environment_kill_switch_cannot_be_released_through_the_api(
    clock: Clock, findings: FindingStub
) -> None:
    from netsight_api.actions.wiring import build_runtime

    built = build_runtime(
        {"NETSIGHT_ACTIONS_ENABLED": "true", "NETSIGHT_ACTIONS_KILL_SWITCH": "true"},
        clock=clock,
        findings=lambda: findings,
    )
    app.dependency_overrides[support.get_runtime] = lambda: built
    admin = Person("administrator")
    status = admin.get(f"{BASE}/status").json()["kill_switch"]
    assert status["engaged"] is True and status["source"] == "environment"
    assert admin.create().status_code == 503
    released = admin.post(f"{BASE}/kill-switch", {"engaged": False, "reason": "Try to undo it"})
    assert released.status_code == 409 and released.json()["error"]["code"] == "KILL_SWITCH_LOCKED"
    assert admin.get(f"{BASE}/status").json()["kill_switch"]["engaged"] is True


# --- rate limits ---------------------------------------------------------------------------------------------------------


def test_writes_are_rate_limited_per_identity_with_retry_after(
    runtime: ActionRuntime, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(support, "_write_limiter", RateLimiter())
    monkeypatch.setattr(support, "WRITE_LIMIT_PER_MINUTE", 3)
    engineer = Person("network_engineer")
    statuses = [engineer.create().status_code for _ in range(5)]
    assert statuses == [201, 201, 201, 429, 429]
    limited = engineer.create()
    assert limited.headers["retry-after"] and limited.json()["error"]["code"] == "RATE_LIMITED"
    assert (
        Person("security_analyst").create().status_code == 201
    )  # another identity has its own budget


def test_execution_and_the_kill_switch_have_their_own_smaller_budgets(
    runtime: ActionRuntime, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(support, "_execute_limiter", RateLimiter())
    monkeypatch.setattr(support, "EXECUTE_LIMIT_PER_MINUTE", 1)
    admin = Person("administrator")
    request = created(Person("network_engineer"))
    approved = admin.approve(request).json()
    assert admin.execute(approved).status_code == 200
    assert admin.execute(approved).status_code == 429


def test_reads_are_rate_limited(runtime: ActionRuntime, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(support, "READ_LIMIT_PER_MINUTE", 2)
    person = Person("auditor")
    assert [person.get(BASE).status_code for _ in range(3)] == [200, 200, 429]


# --- audit integrity -----------------------------------------------------------------------------------------------------


def test_the_audit_names_actor_action_and_target_but_never_the_reason_or_parameters(
    runtime: ActionRuntime, caplog: pytest.LogCaptureFixture
) -> None:
    secret_reason = "contains-unique-reason-marker-QQQ"
    engineer, admin = Person("network_engineer"), Person("administrator")
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        request = created(engineer, isolate_body(reason=secret_reason))
        admin.approve(request)
        admin.decide(
            request, "reject", reason="rejection-marker-ZZZ"
        )  # stale: refused, still audited
    text = " ".join(r.getMessage() for r in caplog.records if r.name == "netsight_api.audit")
    assert secret_reason not in text and "rejection-marker-ZZZ" not in text
    assert request["target_id"] not in text and "duration_minutes" not in text
    records = audit_records(caplog)
    create = next(r for r in records if r["action"] == "actions.create")
    assert create["actor_id"] == engineer.identity_id and create["outcome"] == "success"
    assert create["target"] == request["id"] and create["risk"] == "C"
    assert create["reason_length"] == len(secret_reason)
    approve = next(r for r in records if r["action"] == "actions.approve")
    assert approve["actor_id"] == admin.identity_id and approve["target"] == request["id"]
    assert any(r["action"] == "actions.reject" and r["outcome"] == "failure" for r in records)
    assert all(r["correlation_id"] for r in records)


def test_every_refusal_is_audited_with_a_static_reason(
    runtime: ActionRuntime, caplog: pytest.LogCaptureFixture
) -> None:
    engineer = Person("network_engineer")
    request = created(engineer)
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        Person("administrator", mfa_age=None).approve(request)
        Person("auditor").approve(request)
        engineer.approve(request)
        Person("administrator").approve({**request, "digest": "sha256:" + "1" * 64})
    reasons = {r["reason"] for r in audit_records(caplog) if r["outcome"] in ("denied", "failure")}
    assert {"step-up", "permission", "STALE_REQUEST"} <= reasons


def test_the_history_hash_chain_detects_a_tampered_store(runtime: ActionRuntime) -> None:
    request = created(Person("network_engineer"))
    admin = Person("administrator")
    assert admin.show(request["id"]).json()["chain_intact"] is True
    record = runtime.store._records[request["id"]]  # type: ignore[attr-defined]
    record.history[1] = record.history[1].model_copy(update={"actor_id": "mallory"})
    detail = admin.show(request["id"]).json()
    assert detail["chain_intact"] is False


# --- there is no generic path ------------------------------------------------------------------------------------------


def test_the_action_routes_are_exactly_these_and_none_takes_a_command() -> None:
    schema = app.openapi()
    paths = {
        path.removeprefix("/api/v1"): sorted(m.upper() for m in operations)
        for path, operations in schema["paths"].items()
        if path.startswith("/api/v1/actions")
    }
    assert paths == {
        "/actions/status": ["GET"],
        "/actions": ["GET", "POST"],
        "/actions/from-finding": ["POST"],
        "/actions/kill-switch": ["POST"],
        "/actions/{action_id}": ["GET"],
        "/actions/{action_id}/approve": ["POST"],
        "/actions/{action_id}/reject": ["POST"],
        "/actions/{action_id}/cancel": ["POST"],
        "/actions/{action_id}/execute": ["POST"],
    }
    for path, operations in schema["paths"].items():
        if path.startswith("/api/v1/actions"):
            for operation in operations.values():
                names = {p["name"] for p in operation.get("parameters", [])}
                assert not {"command", "cmd", "script", "shell", "argv"} & names


def test_every_action_response_is_not_cacheable(runtime: ActionRuntime) -> None:
    admin = Person("administrator")
    request = created(Person("network_engineer"))
    for response in (
        admin.get(BASE),
        admin.get(f"{BASE}/status"),
        admin.show(request["id"]),
        admin.approve(request),
        admin.get(f"{BASE}/action-00000000-0000-4000-8000-000000000001"),
    ):
        assert response.headers["cache-control"] == "no-store"


def test_the_sign_in_return_allow_lists_of_the_api_and_the_web_agree_and_include_actions() -> None:
    import re
    from pathlib import Path

    from netsight_api.auth.redirects import UI_AREAS

    web = Path(__file__).resolve().parents[2] / "web" / "src" / "lib" / "sign-in-redirect.ts"
    block = re.search(r"const UI_AREAS = \[(.*?)\];", web.read_text("utf-8"), re.DOTALL)
    assert block is not None
    areas = set(re.findall(r"'([a-z-]+)'", block.group(1)))
    assert "actions" in UI_AREAS and areas == set(UI_AREAS)
