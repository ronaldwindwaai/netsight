"""RBAC for the AI copilot (Step 10): who may ask, and that no service or AI principal can."""

from __future__ import annotations

import pytest

from netsight_api.rbac import (
    HUMAN_ONLY_PERMISSIONS,
    Identity,
    Permission,
    PrincipalKind,
    is_allowed,
    permissions_for,
)

ROLES_WITH = ["administrator", "network_engineer", "security_analyst", "technician", "auditor"]


@pytest.mark.parametrize("role", ROLES_WITH)
def test_operational_roles_may_ask(role: str) -> None:
    identity = Identity(id="u", roles=frozenset({role}), principal=PrincipalKind.HUMAN)
    assert is_allowed(identity, "copilot:ask")
    assert "copilot:ask" in permissions_for(identity)


@pytest.mark.parametrize("role", ["management", "superuser", ""])
def test_management_and_unknown_roles_may_not(role: str) -> None:
    identity = Identity(id="u", roles=frozenset({role}), principal=PrincipalKind.HUMAN)
    assert not is_allowed(identity, "copilot:ask")


@pytest.mark.parametrize("principal", [PrincipalKind.SERVICE, PrincipalKind.AI])
def test_no_service_or_ai_principal_may_ask_whatever_its_role(principal: PrincipalKind) -> None:
    identity = Identity(id="svc", roles=frozenset({"administrator"}), principal=principal)
    assert not is_allowed(identity, "copilot:ask")
    assert Permission.COPILOT_ASK in HUMAN_ONLY_PERMISSIONS


def test_there_is_no_copilot_write_or_execute_permission() -> None:
    assert [p.value for p in Permission if p.value.startswith("copilot:")] == ["copilot:ask"]
