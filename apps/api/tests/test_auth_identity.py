"""OIDC claim-to-role mapping tests."""

from __future__ import annotations

import pytest

from netsight_api.auth.identity import resolve_roles
from netsight_api.auth.settings import AuthSettings


def test_unmapped_identity_has_no_roles_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NETSIGHT_DEFAULT_ROLE", raising=False)
    monkeypatch.delenv("NETSIGHT_ROLE_MAPPING", raising=False)

    settings = AuthSettings()

    assert settings.default_role == ""
    assert resolve_roles({"roles": ["unmapped-group"]}, settings) == frozenset()


def test_unmapped_identity_gets_explicit_valid_default_role(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NETSIGHT_DEFAULT_ROLE", "technician")
    monkeypatch.delenv("NETSIGHT_ROLE_MAPPING", raising=False)

    settings = AuthSettings()

    assert resolve_roles({"roles": ["unmapped-group"]}, settings) == frozenset(
        {"technician"}
    )


def test_mapped_role_takes_precedence_over_explicit_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NETSIGHT_DEFAULT_ROLE", "management")
    monkeypatch.setenv("NETSIGHT_ROLE_MAPPING", "network-team:network_engineer")

    settings = AuthSettings()

    assert resolve_roles({"roles": ["network-team"]}, settings) == frozenset(
        {"network_engineer"}
    )
