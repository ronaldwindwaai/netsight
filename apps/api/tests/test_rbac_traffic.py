"""RBAC for the traffic surface (docs/02-security/RBAC-MATRIX.md, "Traffic permissions (Step 7)").

Two rungs, a strict subset ladder: ``traffic:read-detail`` (flow rows and top talkers, which name
endpoints) implies ``traffic:read`` (aggregates only: volumes, application mix, destinations,
baselines). Management is "Summary" in the matrix, so it holds the aggregate rung only. Technician
holds neither (unchanged: a human decision is needed before "Limited" gives it any traffic).
Unknown roles, no identity and unknown permission names are denied (fail closed).
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

DETAIL = ["administrator", "network_engineer", "security_analyst", "auditor"]
AGGREGATE_ONLY = ["management"]
NONE = ["technician"]


def person(role: str) -> Identity:
    return Identity("oidc:p1", frozenset({role}), PrincipalKind.HUMAN)


@pytest.mark.parametrize("role", DETAIL)
def test_detail_roles_hold_both_rungs(role: str) -> None:
    assert is_allowed(person(role), "traffic:read")
    assert is_allowed(person(role), "traffic:read-detail")


@pytest.mark.parametrize("role", AGGREGATE_ONLY)
def test_management_holds_the_aggregate_rung_only(role: str) -> None:
    assert is_allowed(person(role), "traffic:read")
    assert not is_allowed(person(role), "traffic:read-detail")


@pytest.mark.parametrize("role", NONE)
def test_technician_holds_no_traffic_permission(role: str) -> None:
    assert not is_allowed(person(role), "traffic:read")
    assert not is_allowed(person(role), "traffic:read-detail")


def test_the_three_lists_cover_every_role_exactly_once() -> None:
    assert sorted([*DETAIL, *AGGREGATE_ONLY, *NONE]) == sorted(role.value for role in Role)


def test_detail_implies_aggregate_so_no_role_sees_rows_it_cannot_total() -> None:
    for role, perms in ROLE_PERMISSIONS.items():
        if Permission.TRAFFIC_READ_DETAIL in perms:
            assert Permission.TRAFFIC_READ in perms, role


def test_the_permission_table_agrees_with_the_lists() -> None:
    detail = {
        r.value for r, perms in ROLE_PERMISSIONS.items() if Permission.TRAFFIC_READ_DETAIL in perms
    }
    assert detail == set(DETAIL)


def test_detail_is_not_human_only_because_attribution_is_gated_separately() -> None:
    # Endpoint rows may be read by a service principal; naming the person needs users:read, which
    # is human-only. The two controls are independent.
    assert Permission.TRAFFIC_READ_DETAIL not in HUMAN_ONLY_PERMISSIONS
    assert Permission.USERS_READ in HUMAN_ONLY_PERMISSIONS


def test_the_session_lists_the_new_permission_for_the_ui() -> None:
    assert "traffic:read-detail" in permissions_for(person("security_analyst"))
    assert "traffic:read-detail" not in permissions_for(person("management"))


@pytest.mark.parametrize("permission", ["traffic:read", "traffic:read-detail"])
def test_unknown_roles_no_identity_and_the_empty_role_set_are_denied(permission: str) -> None:
    assert not is_allowed(None, permission)
    assert not is_allowed(Identity("x", frozenset({"superuser"}), PrincipalKind.HUMAN), permission)
    assert not is_allowed(Identity("x", frozenset(), PrincipalKind.HUMAN), permission)
    assert not is_allowed(
        Identity("x", frozenset({"Administrator"}), PrincipalKind.HUMAN), permission
    )
