"""RBAC for the Internet/WAN surface (docs/02-security/RBAC-MATRIX.md, "Internet / WAN").

The WAN card is an Overview widget (PRD 6) and the matrix gives Overview to every role (Full,
Summary or Read), so every role holds ``internet:read``. The evidence export for ISP disputes is
narrower: ``internet:export`` is held by Admin, Network Engineer and Auditor only. Unknown roles,
no identity and unknown permission names are denied (fail closed).
"""

from __future__ import annotations

import pytest

from netsight_api.rbac import (
    ROLE_PERMISSIONS,
    Identity,
    Permission,
    PrincipalKind,
    Role,
    is_allowed,
    permissions_for,
)

READERS = [role.value for role in Role]
EXPORTERS = ["administrator", "network_engineer", "auditor"]
NON_EXPORTERS = ["security_analyst", "technician", "management"]
# internet:read_detail (public IP, gateway, ISP name, per-link throughput): the roles that operate
# or defend the network. Management, Technician and Auditor get status and the SLA summary only.
DETAIL_READERS = ["administrator", "network_engineer", "security_analyst"]
SUMMARY_ONLY = ["technician", "management", "auditor"]


def person(role: str) -> Identity:
    return Identity("oidc:p1", frozenset({role}), PrincipalKind.HUMAN)


@pytest.mark.parametrize("role", READERS)
def test_every_defined_role_may_read_the_internet_surface(role: str) -> None:
    assert is_allowed(person(role), "internet:read")


@pytest.mark.parametrize("role", EXPORTERS)
def test_only_the_evidence_roles_may_export(role: str) -> None:
    assert is_allowed(person(role), "internet:export")


@pytest.mark.parametrize("role", NON_EXPORTERS)
def test_other_roles_may_not_export(role: str) -> None:
    assert not is_allowed(person(role), "internet:export")


def test_the_two_export_lists_cover_every_role_exactly_once() -> None:
    assert sorted([*EXPORTERS, *NON_EXPORTERS]) == sorted(READERS)


def test_the_permission_table_agrees_with_the_helpers() -> None:
    exporters = {
        r.value for r, perms in ROLE_PERMISSIONS.items() if Permission.INTERNET_EXPORT in perms
    }
    readers = {
        r.value for r, perms in ROLE_PERMISSIONS.items() if Permission.INTERNET_READ in perms
    }
    assert exporters == set(EXPORTERS)
    assert readers == set(READERS)


def test_export_implies_read_so_no_role_can_export_what_it_cannot_view() -> None:
    for role, perms in ROLE_PERMISSIONS.items():
        if Permission.INTERNET_EXPORT in perms:
            assert Permission.INTERNET_READ in perms, role


@pytest.mark.parametrize("permission", ["internet:read", "internet:export", "internet:read_detail"])
def test_unknown_roles_no_identity_and_the_empty_role_set_are_denied(permission: str) -> None:
    assert not is_allowed(None, permission)
    assert not is_allowed(Identity("x", frozenset({"superuser"}), PrincipalKind.HUMAN), permission)
    assert not is_allowed(Identity("x", frozenset(), PrincipalKind.HUMAN), permission)
    assert not is_allowed(
        Identity("x", frozenset({"Administrator"}), PrincipalKind.HUMAN), permission
    )


@pytest.mark.parametrize("role", DETAIL_READERS)
def test_operating_and_defending_roles_read_the_detail(role: str) -> None:
    assert is_allowed(person(role), "internet:read_detail")


@pytest.mark.parametrize("role", SUMMARY_ONLY)
def test_summary_roles_do_not_read_the_detail(role: str) -> None:
    assert not is_allowed(person(role), "internet:read_detail")
    assert is_allowed(person(role), "internet:read")


def test_the_detail_lists_cover_every_role_exactly_once() -> None:
    assert sorted([*DETAIL_READERS, *SUMMARY_ONLY]) == sorted(READERS)
    holders = {
        r.value for r, perms in ROLE_PERMISSIONS.items() if Permission.INTERNET_READ_DETAIL in perms
    }
    assert holders == set(DETAIL_READERS)


def test_detail_implies_read_so_no_role_holds_detail_without_the_surface() -> None:
    for role, perms in ROLE_PERMISSIONS.items():
        if Permission.INTERNET_READ_DETAIL in perms:
            assert Permission.INTERNET_READ in perms, role


def test_the_detail_permission_is_not_human_only_and_services_get_none_by_role() -> None:
    service = Identity("svc", frozenset({"management"}), PrincipalKind.SERVICE)
    assert not is_allowed(service, "internet:read_detail")


def test_there_is_no_internet_write_permission() -> None:
    names = {p.value for p in Permission if p.value.startswith("internet:")}
    assert names == {"internet:read", "internet:export", "internet:read_detail"}


def test_the_session_reports_the_new_permissions_for_the_ui() -> None:
    assert {"internet:read", "internet:export"} <= set(permissions_for(person("network_engineer")))
    assert "internet:export" not in permissions_for(person("management"))
    assert "internet:read" in permissions_for(person("management"))
    assert "internet:read_detail" in permissions_for(person("security_analyst"))
    assert "internet:read_detail" not in permissions_for(person("auditor"))
