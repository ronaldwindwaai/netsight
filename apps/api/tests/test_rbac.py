import pytest

from netsight_api.rbac import Identity, Permission, PrincipalKind, is_allowed, require


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
    # Every real mutating permission is denied (an unknown name such as "incidents:write"
    # would be denied for any role, so it proves nothing).
    for permission in (
        Permission.INCIDENTS_TRANSITION,
        Permission.INCIDENTS_ASSIGN,
        Permission.INCIDENTS_COMMENT,
        Permission.INCIDENTS_RESOLVE,
        Permission.INCIDENTS_REOPEN,
        Permission.INCIDENTS_WRITE_ASSIGNED,
        Permission.ACTIONS_PROPOSE,
        Permission.ACTIONS_APPROVE,
        Permission.ADMIN_CONFIG,
    ):
        assert is_allowed(auditor, permission.value) is False, permission
    assert is_allowed(auditor, "incidents:write") is False  # not a permission at all
    assert "incidents:write" not in {p.value for p in Permission}


def test_granular_incident_permissions_per_role() -> None:
    engineer = Identity("u6", frozenset({"network_engineer"}), PrincipalKind.HUMAN)
    technician = Identity("u7", frozenset({"technician"}), PrincipalKind.HUMAN)
    for permission in (
        Permission.INCIDENTS_TRANSITION,
        Permission.INCIDENTS_ASSIGN,
        Permission.INCIDENTS_COMMENT,
        Permission.INCIDENTS_RESOLVE,
        Permission.INCIDENTS_REOPEN,
    ):
        assert is_allowed(engineer, permission.value) is True, permission
        assert is_allowed(technician, permission.value) is False, permission
    assert is_allowed(technician, Permission.INCIDENTS_WRITE_ASSIGNED.value) is True
    assert is_allowed(engineer, Permission.INCIDENTS_WRITE_ASSIGNED.value) is False


def test_administrator_has_all() -> None:
    admin = Identity("u4", frozenset({"administrator"}))
    assert is_allowed(admin, "admin:config") is True
    assert is_allowed(admin, "actions:approve") is True


def test_require_raises() -> None:
    with pytest.raises(PermissionError):
        require(Identity("u5", frozenset({"auditor"})), "admin:config")
