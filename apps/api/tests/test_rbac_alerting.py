"""RBAC for alert rules and maintenance windows (RBAC-MATRIX.md, 'Alert rules' row).

Admin: Full. Network Engineer / Security Analyst: Scoped (site scoping is not implemented,
so they author and disable but never approve). Technician and Management: No. Auditor: Read.
Every write permission is human-only: a service or AI principal never changes monitoring
configuration (AGENTS.md), whatever role it carries.
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

RULE_READ = Permission.ALERT_RULES_READ
RULE_WRITES = [
    Permission.ALERT_RULES_WRITE,
    Permission.ALERT_RULES_APPROVE,
    Permission.ALERT_RULES_DISABLE,
]
MAINT_WRITES = [Permission.MAINTENANCE_WRITE, Permission.MAINTENANCE_WRITE_ORGANISATION]
ALL_NEW = [RULE_READ, Permission.MAINTENANCE_READ, *RULE_WRITES, *MAINT_WRITES]


def person(role: str) -> Identity:
    return Identity("oidc:p1", frozenset({role}), PrincipalKind.HUMAN)


def test_administrator_holds_every_alerting_permission() -> None:
    for permission in ALL_NEW:
        assert is_allowed(person("administrator"), permission.value), permission


@pytest.mark.parametrize("role", ["network_engineer", "security_analyst"])
def test_scoped_roles_author_and_disable_but_never_approve(role: str) -> None:
    who = person(role)
    for allowed in (
        RULE_READ,
        Permission.MAINTENANCE_READ,
        Permission.ALERT_RULES_WRITE,
        Permission.ALERT_RULES_DISABLE,
        Permission.MAINTENANCE_WRITE,
    ):
        assert is_allowed(who, allowed.value), allowed
    # Approval activates notifications; organisation-wide windows silence everything, and so
    # does `evaluation: disable` at any scope — both need maintenance:write-organisation.
    assert not is_allowed(who, Permission.ALERT_RULES_APPROVE.value)
    assert not is_allowed(who, Permission.MAINTENANCE_WRITE_ORGANISATION.value)


def test_auditor_reads_but_cannot_change_anything() -> None:
    who = person("auditor")
    assert is_allowed(who, RULE_READ.value)
    assert is_allowed(who, Permission.MAINTENANCE_READ.value)
    for permission in [*RULE_WRITES, *MAINT_WRITES]:
        assert not is_allowed(who, permission.value), permission


@pytest.mark.parametrize("role", ["technician", "management"])
def test_technician_and_management_hold_no_alerting_permission(role: str) -> None:
    # RBAC-MATRIX 'Alert rules': No. Management keeps the S6-2 full incidents:read (open decision).
    for permission in ALL_NEW:
        assert not is_allowed(person(role), permission.value), permission
    assert is_allowed(person(role), Permission.INCIDENTS_READ.value)


def test_unknown_roles_anonymous_and_unknown_permissions_are_denied() -> None:
    nobody = Identity("x", frozenset({"rule_admin"}), PrincipalKind.HUMAN)
    for permission in ALL_NEW:
        assert not is_allowed(nobody, permission.value)
        assert not is_allowed(None, permission.value)
    assert not is_allowed(person("administrator"), "alert-rules:delete")


def test_every_write_permission_is_human_only() -> None:
    assert {*RULE_WRITES, *MAINT_WRITES} <= HUMAN_ONLY_PERMISSIONS
    assert RULE_READ not in HUMAN_ONLY_PERMISSIONS


@pytest.mark.parametrize("kind", [PrincipalKind.SERVICE, PrincipalKind.AI])
def test_non_human_principals_can_read_but_never_change_monitoring_configuration(
    kind: PrincipalKind,
) -> None:
    robot = Identity("svc:copilot", frozenset({"administrator"}), kind)
    assert is_allowed(robot, RULE_READ.value)
    for permission in [*RULE_WRITES, *MAINT_WRITES]:
        assert not is_allowed(robot, permission.value), permission


def test_new_permissions_are_known_to_the_role_table() -> None:
    for role in Role:
        assert ROLE_PERMISSIONS[role] <= frozenset(Permission)
