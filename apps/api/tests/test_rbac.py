import pytest

from netsight_api.rbac import Identity, is_allowed, require


def test_unknown_permission_denied() -> None:
    admin = Identity("u1", frozenset({"administrator"}))
    assert is_allowed(admin, "devices:delete") is False


def test_unknown_role_denied() -> None:
    user = Identity("u1", frozenset({"superuser"}))
    assert is_allowed(user, "devices:read") is False


def test_anonymous_denied() -> None:
    assert is_allowed(None, "devices:read") is False


def test_technician_cannot_approve() -> None:
    tech = Identity("u2", frozenset({"technician"}))
    assert is_allowed(tech, "actions:propose") is True
    assert is_allowed(tech, "actions:approve") is False


def test_auditor_read_only() -> None:
    auditor = Identity("u3", frozenset({"auditor"}))
    assert is_allowed(auditor, "incidents:read") is True
    assert is_allowed(auditor, "audit:read") is True
    assert is_allowed(auditor, "incidents:write") is False


def test_administrator_has_all() -> None:
    admin = Identity("u4", frozenset({"administrator"}))
    assert is_allowed(admin, "admin:config") is True
    assert is_allowed(admin, "actions:approve") is True


def test_require_raises() -> None:
    with pytest.raises(PermissionError):
        require(Identity("u5", frozenset({"auditor"})), "admin:config")
