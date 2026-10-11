"""RBAC for per-user identity data (docs/02-security/RBAC-MATRIX.md, "Users and identity"; PRD 92).

The matrix has no Users row; this is the privacy-first reading (a human decision is recorded in the
matrix and listed as open). Three permissions form a strict-subset ladder:

* ``users:read``: browse people, read one person, resolve an address to a person (Admin, Network
  Engineer, Security Analyst);
* ``users:read-limited``: resolve an address to its endpoint (device, MAC, port, VLAN) but never to a
  person (Technician, and everyone above);
* ``users:read-summary``: aggregate counts only, no names and no identifiers (Management, and
  everyone above).

The two per-user permissions are human-only: a service or AI principal may not browse people.
Auditor holds none (an open decision). Unknown roles, no identity and unknown names are denied.
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
    permissions_for,
)

FULL = ["administrator", "network_engineer", "security_analyst"]
LIMITED_ONLY = ["technician"]
SUMMARY_ONLY = ["management"]
NONE = ["auditor"]
ALL_ROLES = [role.value for role in Role]


def person(role: str, kind: PrincipalKind = PrincipalKind.HUMAN) -> Identity:
    return Identity("oidc:p1", frozenset({role}), kind)


@pytest.mark.parametrize("role", FULL)
def test_the_full_roles_hold_the_whole_ladder(role: str) -> None:
    for name in ("users:read", "users:read-limited", "users:read-summary"):
        assert is_allowed(person(role), name), (role, name)


@pytest.mark.parametrize("role", LIMITED_ONLY)
def test_technician_resolves_endpoints_but_cannot_browse_or_name_people(role: str) -> None:
    assert is_allowed(person(role), "users:read-limited")
    assert is_allowed(person(role), "users:read-summary")
    assert not is_allowed(person(role), "users:read")


@pytest.mark.parametrize("role", SUMMARY_ONLY)
def test_management_gets_aggregates_only(role: str) -> None:
    assert is_allowed(person(role), "users:read-summary")
    assert not is_allowed(person(role), "users:read-limited")
    assert not is_allowed(person(role), "users:read")


@pytest.mark.parametrize("role", NONE)
def test_auditor_holds_no_users_permission_pending_a_human_decision(role: str) -> None:
    for name in ("users:read", "users:read-limited", "users:read-summary"):
        assert not is_allowed(person(role), name)


def test_the_ladder_is_a_strict_subset_chain_for_every_role() -> None:
    for role, held in ROLE_PERMISSIONS.items():
        if Permission.USERS_READ in held:
            assert {Permission.USERS_READ_LIMITED, Permission.USERS_READ_SUMMARY} <= held, role
        if Permission.USERS_READ_LIMITED in held:
            assert Permission.USERS_READ_SUMMARY in held, role


def test_the_role_lists_cover_every_role_exactly_once() -> None:
    assert sorted([*FULL, *LIMITED_ONLY, *SUMMARY_ONLY, *NONE]) == sorted(ALL_ROLES)


def test_per_user_permissions_are_human_only_and_the_aggregate_is_not() -> None:
    assert Permission.USERS_READ in HUMAN_ONLY_PERMISSIONS
    assert Permission.USERS_READ_LIMITED in HUMAN_ONLY_PERMISSIONS
    assert Permission.USERS_READ_SUMMARY not in HUMAN_ONLY_PERMISSIONS


@pytest.mark.parametrize("kind", [PrincipalKind.SERVICE, PrincipalKind.AI])
def test_a_service_or_ai_principal_cannot_read_people_whatever_role_it_carries(
    kind: PrincipalKind,
) -> None:
    for role in ALL_ROLES:
        principal = person(role, kind)
        assert not is_allowed(principal, "users:read")
        assert not is_allowed(principal, "users:read-limited")
    assert is_allowed(person("management", PrincipalKind.SERVICE), "users:read-summary")


def test_fail_closed_for_unknown_roles_no_identity_and_unknown_names() -> None:
    assert not is_allowed(person("intern"), "users:read")
    assert not is_allowed(None, "users:read-summary")
    assert not is_allowed(person("administrator"), "users:read-everything")
    assert not is_allowed(Identity("x", frozenset()), "users:read-summary")


def test_the_session_lists_the_users_permissions_it_holds() -> None:
    assert {"users:read", "users:read-limited", "users:read-summary"} <= set(
        permissions_for(person("security_analyst"))
    )
    assert permissions_for(person("management")).count("users:read-summary") == 1
    assert "users:read" not in permissions_for(person("technician"))
