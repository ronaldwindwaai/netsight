"""Separation of duties at execution (Step 12 follow-up): the requester does not run their own request.

Approval already refuses the requester. Execution refuses them too, unless an operator opts in with
``NETSIGHT_ACTIONS_ALLOW_SELF_EXECUTE``; the default is off. The identity compared is the stable
``Identity.id`` (provider and subject), never an email address or display name.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from actions_api_support import (
    ENV_ON,
    Clock,
    FindingStub,
    Person,
    clean_wiring,
    install_clock,
    install_findings,
)
from actions_support import ALICE, BOB, NOW, new_action, new_store

from netsight_api import actions_route_support as support
from netsight_api.actions import errors as e
from netsight_api.actions.wiring import build_runtime, validate_environment
from netsight_api.main import app

ALLOW = "NETSIGHT_ACTIONS_ALLOW_SELF_EXECUTE"


@pytest.fixture(autouse=True)
def _wiring(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    yield from clean_wiring(monkeypatch)


def _begin(store: Any, request: Any, actor: Any) -> Any:
    return store.begin_execution(
        request.id,
        actor=actor,
        expected_digest=request.digest,
        expected_version=request.version,
        idempotency_key="exec-key-000000001",
        executor_id="dry-run",
        mode="dry-run",
        steps=["Would do the thing"],
        now=NOW,
    )


def _approved(store: Any) -> Any:
    request = store.create(new_action(), idempotency_key="create-key-0000001", now=NOW).request
    return store.approve(
        request.id,
        approver=BOB,
        expected_digest=request.digest,
        expected_version=request.version,
        now=NOW,
    )


def test_the_requester_cannot_execute_their_own_approved_request_by_default() -> None:
    store = new_store()
    request = _approved(store)
    with pytest.raises(e.SelfExecution):
        _begin(store, request, ALICE)
    assert store.get(request.id).state == "approved"  # nothing started


def test_a_different_person_can_execute_it() -> None:
    store = new_store()
    request = _approved(store)
    assert _begin(store, request, BOB).request.state == "executing"


def test_the_policy_flag_allows_the_requester_to_execute() -> None:
    store = new_store(allow_self_execute=True)
    request = _approved(store)
    assert _begin(store, request, ALICE).request.state == "executing"


def test_the_flag_is_off_unless_set_and_a_garbled_value_stops_start_up() -> None:
    runtime = build_runtime(ENV_ON)
    assert runtime is not None and runtime.store.allow_self_execute is False
    allowed = build_runtime({**ENV_ON, ALLOW: "true"})
    assert allowed is not None and allowed.store.allow_self_execute is True
    with pytest.raises(ValueError):
        validate_environment({**ENV_ON, ALLOW: "maybe"})


def test_the_status_contract_carries_the_policy_so_the_ui_can_explain_it_beforehand() -> None:
    from netsight_api.actions_read_routes import status_body

    off = build_runtime(ENV_ON)
    on = build_runtime({**ENV_ON, ALLOW: "true"})
    assert off is not None and on is not None
    assert status_body(off, lambda: NOW).policy.self_execute_allowed is False
    assert status_body(on, lambda: NOW).policy.self_execute_allowed is True
    assert status_body(None, lambda: NOW).policy.self_execute_allowed is False


def test_the_status_endpoint_reports_the_policy(clock: Clock, findings: FindingStub) -> None:
    runtime = build_runtime({**ENV_ON, ALLOW: "true"}, clock=clock, findings=lambda: findings)
    assert runtime is not None
    app.dependency_overrides[support.get_runtime] = lambda: runtime
    body = Person("auditor").get("/api/v1/actions/status").json()
    assert body["policy"] == {"self_execute_allowed": True}


def test_the_api_refuses_self_execution(clock: Clock, findings: FindingStub) -> None:
    runtime = build_runtime(ENV_ON, clock=clock, findings=lambda: findings)
    assert runtime is not None
    app.dependency_overrides[support.get_runtime] = lambda: runtime
    requester = Person("administrator", "requester-sub")
    created = requester.create().json()
    approver = Person("administrator", "approver-sub")
    approved = approver.approve(created).json()
    own = requester.execute(approved)
    assert own.status_code == 409 and own.json()["error"]["code"] == "SELF_EXECUTION"
    assert approver.execute(approved).status_code == 200


def test_the_same_subject_in_a_second_session_is_still_the_requester(
    clock: Clock, findings: FindingStub
) -> None:
    runtime = build_runtime(ENV_ON, clock=clock, findings=lambda: findings)
    assert runtime is not None
    app.dependency_overrides[support.get_runtime] = lambda: runtime
    first = Person("administrator", "same-subject")
    created = first.create().json()
    approved = Person("administrator", "other-subject").approve(created).json()
    again = Person("administrator", "same-subject")
    assert again.execute(approved).json()["error"]["code"] == "SELF_EXECUTION"


def test_the_actor_recorded_is_the_stable_identity_id_not_a_display_name() -> None:
    from netsight_api.rbac import Identity, PrincipalKind

    identity = Identity("oidc:subject-123", frozenset({"administrator"}), PrincipalKind.HUMAN)
    actor = support.actor_of(identity)
    assert actor.id == "oidc:subject-123" and actor.kind == "human"


@pytest.fixture
def clock() -> Clock:
    return install_clock()


@pytest.fixture
def findings() -> FindingStub:
    return install_findings()
