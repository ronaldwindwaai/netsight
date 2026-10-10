"""RBAC for the incident surface (docs/02-security/RBAC-MATRIX.md, 'Incidents' row).

Admin / Network Engineer / Security Analyst: Full. Technician: Assigned (acts only on
incidents assigned to them). Management: Summary (a reduced, personal-data-free view under
``incidents:read-summary``, human decision 2026-10-10) and Auditor: Read (read only).
Resolve and reopen additionally require a human principal: a root cause is never
recorded by an AI or service identity (INCIDENT-ENGINE.md, 'Resolution').
"""

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

FULL_WRITE = [
    Permission.INCIDENTS_TRANSITION,
    Permission.INCIDENTS_ASSIGN,
    Permission.INCIDENTS_COMMENT,
    Permission.INCIDENTS_RESOLVE,
    Permission.INCIDENTS_REOPEN,
]


def person(role: str) -> Identity:
    return Identity("oidc:p1", frozenset({role}), PrincipalKind.HUMAN)


@pytest.mark.parametrize("role", ["administrator", "network_engineer", "security_analyst"])
@pytest.mark.parametrize("permission", FULL_WRITE)
def test_full_roles_hold_every_incident_write_permission(role: str, permission: Permission) -> None:
    assert is_allowed(person(role), permission.value)


@pytest.mark.parametrize("role", ["management", "auditor"])
def test_read_only_roles_hold_no_incident_write_permission(role: str) -> None:
    assert is_allowed(person(role), Permission.INCIDENTS_READ_SUMMARY.value)
    for permission in [*FULL_WRITE, Permission.INCIDENTS_WRITE_ASSIGNED]:
        assert not is_allowed(person(role), permission.value)


def test_management_holds_the_summary_view_and_not_the_full_read() -> None:
    manager = person("management")
    assert is_allowed(manager, Permission.INCIDENTS_READ_SUMMARY.value)
    assert not is_allowed(manager, Permission.INCIDENTS_READ.value)


@pytest.mark.parametrize(
    "role", ["administrator", "network_engineer", "security_analyst", "technician", "auditor"]
)
def test_every_full_reader_can_also_see_the_summary(role: str) -> None:
    assert is_allowed(person(role), Permission.INCIDENTS_READ.value)
    assert is_allowed(person(role), Permission.INCIDENTS_READ_SUMMARY.value)


@pytest.mark.parametrize("kind", [PrincipalKind.SERVICE, PrincipalKind.AI])
def test_summary_is_not_a_human_only_permission(kind: PrincipalKind) -> None:
    # Reading is not a human judgement; only writes that record one are human-only.
    assert Permission.INCIDENTS_READ_SUMMARY not in HUMAN_ONLY_PERMISSIONS
    robot = Identity("svc:x", frozenset({"management"}), kind)
    assert is_allowed(robot, Permission.INCIDENTS_READ_SUMMARY.value)


def test_technician_is_limited_to_assigned_incident_work() -> None:
    tech = person("technician")
    assert is_allowed(tech, Permission.INCIDENTS_READ.value)
    assert is_allowed(tech, Permission.INCIDENTS_WRITE_ASSIGNED.value)
    for permission in FULL_WRITE:
        assert not is_allowed(tech, permission.value), permission


def test_unknown_roles_and_anonymous_hold_nothing() -> None:
    nobody = Identity("x", frozenset({"incident_admin"}), PrincipalKind.HUMAN)
    for permission in [Permission.INCIDENTS_READ, *FULL_WRITE]:
        assert not is_allowed(nobody, permission.value)
        assert not is_allowed(None, permission.value)


def test_legacy_coarse_write_permission_is_gone() -> None:
    assert "incidents:write" not in {p.value for p in Permission}
    assert not is_allowed(person("administrator"), "incidents:write")


def test_resolve_and_reopen_are_human_only_permissions() -> None:
    # S6-3 added the alert-rule and maintenance writes (test_rbac_alerting.py pins those).
    assert {Permission.INCIDENTS_RESOLVE, Permission.INCIDENTS_REOPEN} <= HUMAN_ONLY_PERMISSIONS
    incident_permissions = {p for p in Permission if p.value.startswith("incidents:")}
    assert HUMAN_ONLY_PERMISSIONS & incident_permissions == {
        Permission.INCIDENTS_RESOLVE,
        Permission.INCIDENTS_REOPEN,
    }


@pytest.mark.parametrize("kind", [PrincipalKind.SERVICE, PrincipalKind.AI])
@pytest.mark.parametrize("permission", [Permission.INCIDENTS_RESOLVE, Permission.INCIDENTS_REOPEN])
def test_non_human_principals_can_never_resolve_or_reopen(
    kind: PrincipalKind, permission: Permission
) -> None:
    # Even holding the administrator role (all permissions) a non-human principal is denied.
    robot = Identity("svc:copilot", frozenset({"administrator"}), kind)
    assert not is_allowed(robot, permission.value)
    # ...while still able to do the non-root-cause work its role allows.
    assert is_allowed(robot, Permission.INCIDENTS_COMMENT.value)


def test_principal_kind_defaults_to_not_human() -> None:
    """An identity built without an explicit human proof must not close incidents."""
    unspecified = Identity("u", frozenset({"administrator"}))
    assert unspecified.principal is not PrincipalKind.HUMAN
    assert not is_allowed(unspecified, Permission.INCIDENTS_RESOLVE.value)
    assert not is_allowed(unspecified, Permission.INCIDENTS_REOPEN.value)
    assert is_allowed(unspecified, Permission.INCIDENTS_READ.value)


def test_every_role_maps_only_to_known_permissions() -> None:
    for role in Role:
        assert ROLE_PERMISSIONS[role] <= frozenset(Permission)
