"""RBAC for diagnostics (docs/02-security/RBAC-MATRIX.md, 'Diagnostics' row).

Admin / Network Engineer: Full. Security Analyst: "Security scope" (no scoping exists, so the same
surface). Technician: "Basic" (the same read-only run and session reads). Management and Auditor:
No. A diagnostic session names targets, devices and (as references) incidents, so a role without
the row must not read or start one, even though it can read other things.
"""

from __future__ import annotations

import pytest
from diagnostic_support import DIAGNOSTIC_ROLES, NO_DIAGNOSTIC_ROLES

from netsight_api.rbac import (
    ROLE_PERMISSIONS,
    Identity,
    Permission,
    PrincipalKind,
    Role,
    is_allowed,
)


def person(role: str) -> Identity:
    return Identity("oidc:p1", frozenset({role}), PrincipalKind.HUMAN)


@pytest.mark.parametrize("role", DIAGNOSTIC_ROLES)
def test_roles_with_a_diagnostics_row_hold_the_permission(role: str) -> None:
    assert is_allowed(person(role), Permission.DIAGNOSTICS_READ.value)


@pytest.mark.parametrize("role", NO_DIAGNOSTIC_ROLES)
def test_management_and_auditor_hold_no_diagnostics_permission(role: str) -> None:
    assert not is_allowed(person(role), Permission.DIAGNOSTICS_READ.value)


def test_the_two_lists_cover_every_role_exactly_once() -> None:
    assert sorted([*DIAGNOSTIC_ROLES, *NO_DIAGNOSTIC_ROLES]) == sorted(r.value for r in Role)


def test_the_permission_table_agrees_with_the_helper() -> None:
    holders = {
        r.value for r, perms in ROLE_PERMISSIONS.items() if Permission.DIAGNOSTICS_READ in perms
    }
    assert holders == set(DIAGNOSTIC_ROLES)


def test_no_role_that_runs_diagnostics_lacks_the_incident_read_for_titles() -> None:
    # Defence in depth for the read-time title join: every diagnostics role also holds
    # incidents:read today, but the join checks it on its own and does not rely on this.
    for role in DIAGNOSTIC_ROLES:
        assert is_allowed(person(role), Permission.INCIDENTS_READ.value)
