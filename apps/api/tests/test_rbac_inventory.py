"""RBAC for Inventory, IPAM and unknown-device findings (Step 8; docs/02-security/RBAC-MATRIX.md).

Each surface has a strict-subset ladder: ``*:read`` (rows, per-asset detail) implies
``*:read-summary`` (counts only), so a role can never see rows without the counts. Management holds
the summary rung only. Every write on a finding is human-only: no service or AI principal may
acknowledge, assign, comment on, resolve or scan, whatever role it carries. Unknown roles, no
identity and unknown permission names are denied (fail closed).
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

ALL_ROLES = [role.value for role in Role]
INVENTORY_READERS = [
    "administrator",
    "network_engineer",
    "security_analyst",
    "technician",
    "auditor",
]
IPAM_READERS = INVENTORY_READERS
FINDING_READERS = ["administrator", "network_engineer", "security_analyst", "auditor"]
FINDING_SUMMARY_ONLY = ["technician", "management"]
FINDING_WRITERS = ["administrator", "network_engineer", "security_analyst"]
WRITE_PERMISSIONS = [
    "unknown-devices:acknowledge",
    "unknown-devices:assign",
    "unknown-devices:comment",
    "unknown-devices:resolve",
    "unknown-devices:scan",
]
LADDERS = [
    ("inventory:read", "inventory:read-summary"),
    ("ipam:read", "ipam:read-summary"),
    ("unknown-devices:read", "unknown-devices:read-summary"),
]


def person(role: str) -> Identity:
    return Identity("oidc:p1", frozenset({role}), PrincipalKind.HUMAN)


def holders(permission: str) -> set[str]:
    return {r.value for r, perms in ROLE_PERMISSIONS.items() if Permission(permission) in perms}


@pytest.mark.parametrize("role", ALL_ROLES)
def test_every_role_holds_a_summary_rung_of_each_surface(role: str) -> None:
    for _, summary in LADDERS:
        assert is_allowed(person(role), summary), (role, summary)


def test_inventory_and_ipam_rows_are_for_the_device_readers() -> None:
    assert holders("inventory:read") == set(INVENTORY_READERS)
    assert holders("ipam:read") == set(IPAM_READERS)


def test_management_gets_counts_only_on_every_surface() -> None:
    for read, summary in LADDERS:
        assert not is_allowed(person("management"), read)
        assert is_allowed(person("management"), summary)


def test_finding_rows_are_for_the_security_and_network_roles_and_the_auditor() -> None:
    assert holders("unknown-devices:read") == set(FINDING_READERS)
    for role in FINDING_SUMMARY_ONLY:
        assert not is_allowed(person(role), "unknown-devices:read")


@pytest.mark.parametrize(("read", "summary"), LADDERS)
def test_the_read_rung_implies_the_summary_rung(read: str, summary: str) -> None:
    for role, perms in ROLE_PERMISSIONS.items():
        if Permission(read) in perms:
            assert Permission(summary) in perms, role


@pytest.mark.parametrize("permission", WRITE_PERMISSIONS)
def test_only_the_operating_roles_may_change_findings(permission: str) -> None:
    assert holders(permission) == set(FINDING_WRITERS)


@pytest.mark.parametrize("permission", WRITE_PERMISSIONS)
def test_every_finding_write_is_human_only(permission: str) -> None:
    assert Permission(permission) in HUMAN_ONLY_PERMISSIONS
    for kind in (PrincipalKind.SERVICE, PrincipalKind.AI):
        identity = Identity("svc", frozenset({"administrator"}), kind)
        assert not is_allowed(identity, permission)
    assert is_allowed(person("administrator"), permission)


def test_a_writer_can_always_read_the_findings_it_changes() -> None:
    for role, perms in ROLE_PERMISSIONS.items():
        if Permission.UNKNOWN_DEVICES_ACKNOWLEDGE in perms:
            assert Permission.UNKNOWN_DEVICES_READ in perms, role


def test_reads_are_not_human_only() -> None:
    for read, summary in LADDERS:
        assert Permission(read) not in HUMAN_ONLY_PERMISSIONS
        assert Permission(summary) not in HUMAN_ONLY_PERMISSIONS


@pytest.mark.parametrize(
    "permission", [p for ladder in LADDERS for p in ladder] + WRITE_PERMISSIONS
)
def test_unknown_roles_no_identity_and_the_empty_role_set_are_denied(permission: str) -> None:
    assert not is_allowed(None, permission)
    assert not is_allowed(Identity("x", frozenset({"superuser"}), PrincipalKind.HUMAN), permission)
    assert not is_allowed(Identity("x", frozenset(), PrincipalKind.HUMAN), permission)
    assert not is_allowed(
        Identity("x", frozenset({"Administrator"}), PrincipalKind.HUMAN), permission
    )


def test_the_session_permission_list_names_the_new_permissions_for_the_ui() -> None:
    held = permissions_for(person("management"))
    assert "inventory:read-summary" in held
    assert "inventory:read" not in held
    assert "unknown-devices:resolve" not in held
    assert "unknown-devices:resolve" in permissions_for(person("security_analyst"))
