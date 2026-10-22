"""RBAC for controlled actions (Step 12): who may read, propose, approve, execute and stop them."""

from __future__ import annotations

import pytest

from netsight_api.rbac import (
    HUMAN_ONLY_PERMISSIONS,
    ROLE_PERMISSIONS,
    Identity,
    Permission,
    PrincipalKind,
    Role,
    is_allowed,
)

ACTION_PERMISSIONS = {
    "actions:read",
    "actions:propose",
    "actions:propose-high",
    "actions:approve",
    "actions:execute",
    "actions:kill-switch",
}


def human(role: str) -> Identity:
    return Identity(id="u", roles=frozenset({role}), principal=PrincipalKind.HUMAN)


def test_the_action_permissions_are_exactly_these() -> None:
    assert {p.value for p in Permission if p.value.startswith("actions:")} == ACTION_PERMISSIONS


@pytest.mark.parametrize(
    ("role", "granted"),
    [
        ("administrator", ACTION_PERMISSIONS),
        ("network_engineer", {"actions:read", "actions:propose", "actions:propose-high"}),
        ("security_analyst", {"actions:read", "actions:propose", "actions:propose-high"}),
        ("technician", {"actions:read", "actions:propose"}),
        ("management", set()),
        ("auditor", {"actions:read"}),
    ],
)
def test_the_role_matrix(role: str, granted: set[str]) -> None:
    held = {p for p in ACTION_PERMISSIONS if is_allowed(human(role), p)}
    assert held == granted


def test_only_the_administrator_approves_executes_or_stops_actions() -> None:
    for role in Role:
        for permission in ("actions:approve", "actions:execute", "actions:kill-switch"):
            assert is_allowed(human(role.value), permission) is (role is Role.ADMINISTRATOR)


@pytest.mark.parametrize("principal", [PrincipalKind.SERVICE, PrincipalKind.AI])
@pytest.mark.parametrize(
    "permission", ["actions:approve", "actions:execute", "actions:kill-switch"]
)
def test_no_service_or_ai_principal_approves_executes_or_stops_whatever_its_role(
    principal: PrincipalKind, permission: str
) -> None:
    identity = Identity(id="svc", roles=frozenset({"administrator"}), principal=principal)
    assert not is_allowed(identity, permission)
    assert Permission(permission) in HUMAN_ONLY_PERMISSIONS


def test_an_ai_principal_may_propose_but_the_proposal_still_needs_a_person() -> None:
    identity = Identity(
        id="agent", roles=frozenset({"network_engineer"}), principal=PrincipalKind.AI
    )
    assert is_allowed(identity, "actions:propose")
    assert not is_allowed(identity, "actions:approve")


def test_unknown_roles_and_permissions_are_denied() -> None:
    assert not is_allowed(human("superuser"), "actions:read")
    assert not is_allowed(human("administrator"), "actions:run-anything")
    assert not is_allowed(None, "actions:read")


def test_proposing_high_risk_implies_proposing() -> None:
    for role, permissions in ROLE_PERMISSIONS.items():
        if Permission.ACTIONS_PROPOSE_HIGH in permissions:
            assert Permission.ACTIONS_PROPOSE in permissions, role
        if Permission.ACTIONS_PROPOSE in permissions:
            assert Permission.ACTIONS_READ in permissions, role
