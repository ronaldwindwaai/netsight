"""The controlled-action routes over HTTP (Step 12): the lifecycle end to end, honest states, contracts.

Hermetic: the store is the in-memory store, the only executor is the dry-run executor and the real
session, CSRF, origin, step-up, RBAC and rate-limit stack runs through ``Person``.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from datetime import timedelta
from typing import Any

import pytest
from actions_api_support import (
    BASE,
    Clock,
    FindingStub,
    Person,
    clean_wiring,
    disabled,
    install_clock,
    install_findings,
    install_runtime,
    isolate_body,
    port_body,
)
from actions_support import FINDING, make_finding
from alerting_support import audit_records
from fastapi.testclient import TestClient

from netsight_api.actions.catalog import CATALOG
from netsight_api.actions.wiring import ActionRuntime
from netsight_api.contracts import validate
from netsight_api.main import app


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
    validate("action_request", response.json())
    return response.json()  # type: ignore[no-any-return]


# --- status and the disabled state -----------------------------------------------------------------------------


def test_unauthenticated_callers_get_401_everywhere(runtime: ActionRuntime) -> None:
    client = TestClient(app, raise_server_exceptions=False)
    for path in (f"{BASE}/status", BASE, f"{BASE}/action-00000000-0000-4000-8000-000000000000"):
        assert client.get(path).status_code == 401
    assert client.post(BASE, json={}).status_code == 401
    assert client.post(f"{BASE}/kill-switch", json={}).status_code == 401


def test_status_says_dry_run_only_and_lists_exactly_the_catalogue(runtime: ActionRuntime) -> None:
    response = Person("auditor").get(f"{BASE}/status")
    assert response.status_code == 200
    body = response.json()
    validate("action_status", body)
    assert response.headers["cache-control"] == "no-store"
    assert body["state"] == "ok" and body["dry_run_only"] is True
    assert body["store"] == {"kind": "memory", "durable": False}
    assert body["kill_switch"] == {"engaged": False, "source": "none", "since": None}
    assert {e["id"]: e["state"] for e in body["executors"]} == {"dry-run": "ok", "live": "disabled"}
    assert sorted(d["action_type"] for d in body["definitions"]) == sorted(CATALOG)
    assert all(d["step_up_required"] is True for d in body["definitions"])


def test_enabling_live_execution_still_reports_it_not_connected() -> None:
    from netsight_api.actions.wiring import build_runtime

    built = build_runtime(
        {"NETSIGHT_ACTIONS_ENABLED": "true", "NETSIGHT_ACTIONS_LIVE_EXECUTION": "true"}
    )
    assert built is not None
    assert {x.id: x.status().state for x in built.executors} == {
        "dry-run": "ok",
        "live": "not-connected",
    }


def test_a_disabled_engine_is_not_connected_never_an_empty_success() -> None:
    disabled()
    person = Person("network_engineer")
    status = person.get(f"{BASE}/status")
    assert status.status_code == 200
    validate("action_status", status.json())
    assert status.json()["state"] == "not-connected" and status.json()["definitions"] == []
    listing = person.get(BASE)
    assert listing.status_code == 200
    validate("action_list", listing.json())
    assert listing.json()["state"] == "not-connected" and listing.json()["items"] == []
    refused = person.create()
    assert refused.status_code == 503 and refused.json()["error"]["code"] == "ACTIONS_NOT_ENABLED"
    detail = person.get(f"{BASE}/action-00000000-0000-4000-8000-000000000000")
    assert detail.status_code == 503 and detail.json()["error"]["code"] == "ACTIONS_NOT_ENABLED"


# --- proposing ---------------------------------------------------------------------------------------------------


def test_a_proposal_is_pending_approval_and_nothing_runs(runtime: ActionRuntime) -> None:
    request = created(Person("network_engineer"))
    assert request["state"] == "pending-approval"
    assert request["requester"] == {"id": Person("network_engineer").identity_id, "kind": "human"}
    assert request["execution"] is None and request["approvals"] == []
    assert request["risk"] == "C" and request["approvals_required"] == 1
    assert {c["name"]: c["state"] for c in request["policy_checks"]}["target-exists"] == "unknown"


def test_the_same_idempotency_key_and_body_returns_the_first_request(
    runtime: ActionRuntime,
) -> None:
    person = Person("network_engineer")
    body = isolate_body()
    first = person.create(body, key="fixed-key-0000000001")
    again = person.create(body, key="fixed-key-0000000001")
    assert first.status_code == again.status_code == 201
    assert again.json()["id"] == first.json()["id"]
    assert again.headers["idempotent-replay"] == "true" and "idempotent-replay" not in first.headers
    assert person.get(BASE).json()["total"] == 1


def test_the_same_key_with_a_different_body_is_a_conflict(runtime: ActionRuntime) -> None:
    person = Person("network_engineer")
    person.create(isolate_body(), key="fixed-key-0000000002")
    response = person.create(isolate_body(), key="fixed-key-0000000002")
    assert (
        response.status_code == 409 and response.json()["error"]["code"] == "IDEMPOTENCY_CONFLICT"
    )


@pytest.mark.parametrize(
    "key", ["short", "has spaces in it 1234", "x" * 65, "bad/slash/0123456789"]
)
def test_a_bad_or_missing_idempotency_key_is_422(runtime: ActionRuntime, key: str) -> None:
    person = Person("network_engineer")
    assert person.create(key=key).status_code == 422
    assert person.post(BASE, isolate_body()).status_code == 422  # header absent


HOSTILE = "<script>alert('x')</script> \"; DROP TABLE actions; -- {{7*7}} $(reboot)"


def test_a_hostile_reason_is_stored_and_returned_verbatim_as_data(runtime: ActionRuntime) -> None:
    person = Person("network_engineer")
    request = created(person, isolate_body(reason=HOSTILE))
    assert request["reason"] == HOSTILE
    assert person.show(request["id"]).json()["request"]["reason"] == HOSTILE


@pytest.mark.parametrize(
    "overrides",
    [
        {"action_type": "shell.exec"},
        {"action_type": "service.restart"},
        {"params": {"duration_minutes": "60; reboot"}},
        {"params": {"duration_minutes": 60, "command": "reload"}},
        {"params": {"duration_minutes": [60]}},
        {"params": {"duration_minutes": True}},
        {"params": {"duration_minutes": 10**30}},
        {"params": {"Bad Name": 1}},
        {"params": {}},
        {"target_id": "interface:sw1-gi0-1"},
        {"target_id": "endpoint:a;reboot"},
        {"reason": "ab"},
        {"reason": "x" * 501},
        {"reason": "line one\nline two"},
        {"reason": "evil" + chr(0x202E) + "text"},
        {"command": "reload"},
    ],
)
def test_an_unacceptable_proposal_is_422_and_nothing_is_echoed(
    runtime: ActionRuntime, overrides: dict[str, Any]
) -> None:
    response = Person("network_engineer").create(isolate_body(**overrides))
    assert response.status_code == 422
    text = response.text
    for echoed in ("reboot", "reload", "evil", "shell.exec", "Bad Name", "sw1-gi0-1"):
        assert echoed not in text
    assert Person("network_engineer").get(BASE).json()["total"] == 0


def test_surrounding_whitespace_is_stripped_not_carried_into_the_target(
    runtime: ActionRuntime,
) -> None:
    request = created(Person("network_engineer"), isolate_body(target_id="endpoint:padded\n"))
    assert request["target_id"] == "endpoint:padded"


def test_a_non_json_body_is_422(runtime: ActionRuntime) -> None:
    person = Person("network_engineer")
    response = person.http.post(
        BASE,
        content=b"not json",
        headers={
            "X-CSRF-Token": person.session.csrf_token,
            "Idempotency-Key": "fixed-key-0000000003",
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 422


# --- the whole lifecycle --------------------------------------------------------------------------------------


def test_propose_approve_execute_as_dry_run_end_to_end(
    runtime: ActionRuntime, caplog: pytest.LogCaptureFixture
) -> None:
    engineer, admin = Person("network_engineer"), Person("administrator")
    request = created(engineer)
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        approved = admin.approve(request)
        assert approved.status_code == 200, approved.text
        approved_body = approved.json()
        validate("action_request", approved_body)
        assert approved_body["state"] == "approved"
        assert approved_body["approvals"][0]["approver_id"] == admin.identity_id
        assert approved_body["execute_by"] is not None
        done = admin.execute(approved_body)
    assert done.status_code == 200, done.text
    body = done.json()
    validate("action_request", body)
    assert body["state"] == "succeeded"
    assert body["execution"]["mode"] == "dry-run" and body["execution"]["effect"] == "none"
    assert body["execution"]["verification"]["state"] == "not-applicable"
    assert any("Would" in step for step in body["execution"]["planned_steps"])
    detail = admin.show(request["id"]).json()
    validate("action_detail", detail)
    assert detail["chain_intact"] is True
    assert [e["type"] for e in detail["history"]][:4] == [
        "proposed",
        "policy-checked",
        "submitted",
        "approved",
    ]
    assert detail["history"][-1]["type"] == "executed"
    executed = [r for r in audit_records(caplog) if r["action"] == "actions.execute"]
    assert executed and executed[0]["outcome"] == "success"
    assert executed[0]["mode"] == "dry-run" and executed[0]["target"] == request["id"]


def test_a_risk_d_request_needs_two_different_administrators(runtime: ActionRuntime) -> None:
    engineer = Person("network_engineer")
    first, second = Person("administrator", "admin-one"), Person("administrator", "admin-two")
    request = created(engineer, port_body())
    assert request["risk"] == "D" and request["approvals_required"] == 2
    once = first.approve(request)
    assert once.status_code == 200 and once.json()["state"] == "pending-approval"
    again = first.approve(once.json())
    assert again.status_code == 409 and again.json()["error"]["code"] == "ALREADY_APPROVED"
    unready = first.execute(once.json())
    assert unready.status_code == 409  # not approved yet
    twice = second.approve(once.json())
    assert twice.status_code == 200 and twice.json()["state"] == "approved"
    assert second.execute(twice.json()).json()["state"] == "succeeded"


def test_an_unapproved_request_cannot_be_executed(runtime: ActionRuntime) -> None:
    request = created(Person("network_engineer"))
    response = Person("administrator").execute(request)
    assert response.status_code == 409 and response.json()["error"]["code"] == "ILLEGAL_STATE"


def test_executing_twice_with_one_key_runs_once_and_a_second_key_is_refused(
    runtime: ActionRuntime,
) -> None:
    admin = Person("administrator")
    approved = admin.approve(created(Person("network_engineer"))).json()
    first = admin.execute(approved, key="exec-key-000000000001")
    again = admin.execute(approved, key="exec-key-000000000001")
    assert first.status_code == again.status_code == 200
    assert again.json()["state"] == "succeeded"
    other = admin.execute(first.json(), key="exec-key-000000000002")
    assert other.status_code == 409
    history = admin.show(approved["id"]).json()["history"]
    assert [e["type"] for e in history].count("execution-started") == 1


def test_reject_and_cancel_record_the_note_and_are_final(runtime: ActionRuntime) -> None:
    engineer, admin = Person("network_engineer"), Person("administrator")
    rejected = admin.decide(created(engineer), "reject", reason="Not justified by the evidence")
    assert rejected.status_code == 200 and rejected.json()["state"] == "rejected"
    history = admin.show(rejected.json()["id"]).json()["history"]
    assert history[-1]["note"] == "Not justified by the evidence"
    again = admin.decide(rejected.json(), "reject", reason="Still not justified")
    assert again.status_code == 409
    mine = created(engineer)
    cancelled = engineer.decide(mine, "cancel", reason="Raised in error")
    assert cancelled.status_code == 200 and cancelled.json()["state"] == "cancelled"
    assert admin.approve(cancelled.json()).status_code == 409


def test_a_request_that_is_not_approved_in_time_expires(
    runtime: ActionRuntime, clock: Clock
) -> None:
    engineer, admin = Person("network_engineer"), Person("administrator")
    request = created(engineer)
    clock.advance(hours=25)
    response = admin.approve(request)
    assert response.status_code == 409 and response.json()["error"]["code"] == "EXPIRED"
    assert admin.show(request["id"]).json()["request"]["state"] == "expired"
    assert admin.get(BASE, state="expired").json()["total"] == 1


def test_an_approved_request_not_run_in_time_expires(runtime: ActionRuntime, clock: Clock) -> None:
    admin = Person("administrator")
    approved = admin.approve(created(Person("network_engineer"))).json()
    clock.advance(hours=2)
    response = admin.execute(approved)
    assert response.status_code == 409 and response.json()["error"]["code"] == "EXPIRED"


# --- listing and detail -----------------------------------------------------------------------------------------


def test_listing_is_newest_first_filtered_and_bounded(runtime: ActionRuntime, clock: Clock) -> None:
    engineer = Person("network_engineer")
    ids = []
    for _ in range(3):
        ids.append(created(engineer)["id"])
        clock.advance(seconds=5)
    listing = Person("auditor").get(BASE, page_size=2)
    body = listing.json()
    validate("action_list", body)
    assert [i["id"] for i in body["items"]] == [ids[2], ids[1]] and body["total"] == 3
    assert Person("auditor").get(BASE, page=2, page_size=2).json()["items"][0]["id"] == ids[0]
    assert Person("auditor").get(BASE, state="approved").json()["total"] == 0
    for bad in (
        {"page_size": 51},
        {"page": 0},
        {"state": "bogus"},
        {"unknown": "x"},
        {"page": 1001},
    ):
        assert Person("auditor").get(BASE, **bad).status_code == 422, bad


def test_detail_of_an_unknown_or_malformed_id(runtime: ActionRuntime) -> None:
    auditor = Person("auditor")
    assert auditor.show("action-00000000-0000-4000-8000-000000000000").status_code == 404
    assert auditor.show("not-an-id").status_code == 422
    assert auditor.show("../../etc/passwd").status_code in (404, 422)


def test_a_finished_dry_run_is_never_labelled_applied(runtime: ActionRuntime) -> None:
    admin = Person("administrator")
    approved = admin.approve(created(Person("network_engineer"))).json()
    done = admin.execute(approved).json()
    assert done["execution"]["effect"] == "none"
    status = admin.get(f"{BASE}/status").json()
    assert status["dry_run_only"] is True


# --- a Step 8 quarantine proposal -------------------------------------------------------------------------------


def from_finding(person: Person, **overrides: Any) -> Any:
    body = {
        "finding_id": FINDING,
        "expected_evidence_version": 3,
        "reason": "Seen on the finance VLAN",
    }
    body.update(overrides)
    return person.post(
        f"{BASE}/from-finding",
        body,
        headers={"Idempotency-Key": f"finding-key-{len(str(body)):04d}0000"},
    )


def test_a_quarantine_proposal_becomes_a_request_that_is_still_only_a_proposal(
    runtime: ActionRuntime, findings: FindingStub
) -> None:
    response = from_finding(Person("security_analyst"))
    assert response.status_code == 201, response.text
    body = response.json()
    validate("action_request", body)
    assert body["action_type"] == "endpoint.isolate" and body["state"] == "pending-approval"
    assert body["target_id"] == FINDING
    assert body["source"] == {
        "kind": "unknown-device-finding",
        "id": FINDING,
        "evidence_version": 3,
    }
    assert body["execution"] is None
    assert (
        "aa:bb:cc" not in response.text and "10.0.5.9" not in response.text
    )  # no endpoint data copied
    assert findings.finding.proposed_action.executable is False  # type: ignore[union-attr]


@pytest.mark.parametrize(
    ("finding", "version", "status", "code"),
    [
        (make_finding(proposed_action=None), 3, 409, "NO_PROPOSAL"),
        (make_finding(state="resolved"), 3, 409, "FINDING_CLOSED"),
        (make_finding(), 2, 409, "STALE_EVIDENCE"),
        (None, 3, 404, "NOT_FOUND"),
    ],
)
def test_a_finding_that_cannot_back_a_request_is_refused(
    runtime: ActionRuntime,
    findings: FindingStub,
    finding: Any,
    version: int,
    status: int,
    code: str,
) -> None:
    findings.finding = finding
    response = from_finding(Person("security_analyst"), expected_evidence_version=version)
    assert response.status_code == status and response.json()["error"]["code"] == code


def test_findings_that_are_not_connected_refuse_with_503(runtime: ActionRuntime) -> None:
    from netsight_api import actions_route_support as support

    app.dependency_overrides[support.get_finding_reader] = lambda: None
    response = from_finding(Person("security_analyst"))
    assert (
        response.status_code == 503 and response.json()["error"]["code"] == "FINDINGS_NOT_CONNECTED"
    )


def test_an_execution_stops_when_the_finding_changed_since_the_proposal(
    runtime: ActionRuntime, findings: FindingStub
) -> None:
    admin = Person("administrator")
    request = from_finding(Person("security_analyst")).json()
    approved = admin.approve(request).json()
    findings.finding = make_finding(evidence_version=4)  # the evidence moved after the approval
    done = admin.execute(approved).json()
    assert done["state"] == "failed"
    assert done["execution"]["failure"] == "pre-check-failed"
    assert [c["detail"] for c in done["pre_checks"]] == ["evidence-changed"]
    assert done["execution"]["effect"] == "none"


def test_the_response_timestamps_are_the_injected_clock(
    runtime: ActionRuntime, clock: Clock
) -> None:
    request = created(Person("network_engineer"))
    assert request["created_at"].startswith("2026-10-18T12:00:00")
    assert request["approve_by"].startswith("2026-10-19T12:00:00")
    assert timedelta(hours=24) == timedelta(
        seconds=CATALOG["endpoint.isolate"].approve_within_seconds
    )


# --- review fixes -----------------------------------------------------------------------------------------------------


def test_a_retried_execution_is_marked_as_a_replay_and_audited_as_one(
    runtime: ActionRuntime, caplog: pytest.LogCaptureFixture
) -> None:
    admin = Person("administrator")
    approved = admin.approve(created(Person("network_engineer"))).json()
    first = admin.execute(approved, key="exec-key-000000000001")
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        again = admin.execute(approved, key="exec-key-000000000001")
    assert "idempotent-replay" not in first.headers
    assert again.headers["idempotent-replay"] == "true"
    replays = [r for r in audit_records(caplog) if r["action"] == "actions.execute"]
    assert replays and replays[0]["replayed"] is True


def test_another_administrator_cannot_use_someone_elses_execution_key(
    runtime: ActionRuntime,
) -> None:
    approved = Person("administrator", "first").approve(created(Person("network_engineer"))).json()
    Person("administrator", "first").execute(approved, key="exec-key-000000000001")
    other = Person("administrator", "second").execute(approved, key="exec-key-000000000001")
    assert other.status_code == 409 and other.json()["error"]["code"] == "IDEMPOTENCY_CONFLICT"


def test_a_request_moved_by_the_clock_is_audited_as_a_system_change(
    runtime: ActionRuntime, clock: Clock, caplog: pytest.LogCaptureFixture
) -> None:
    request = created(Person("network_engineer"))
    clock.advance(hours=25)
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        Person("auditor").get(BASE)
    system = [r for r in audit_records(caplog) if r["action"] == "actions.system-transition"]
    assert len(system) == 1
    assert system[0]["actor_id"] == "system:actions" and system[0]["target"] == request["id"]
    assert system[0]["state"] == "expired" and system[0]["code"] == "approval-window-closed"
