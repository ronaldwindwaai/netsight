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
    admin = Identity("u4", frozenset({"administrator"}), PrincipalKind.HUMAN)
    assert is_allowed(admin, "admin:config") is True
    # Approving a remote action is human-only (Step 12): a service principal with the same role is refused.
    assert is_allowed(admin, "actions:approve") is True
    assert is_allowed(Identity("u4", frozenset({"administrator"})), "actions:approve") is False


def test_require_raises() -> None:
    with pytest.raises(PermissionError):
        require(Identity("u5", frozenset({"auditor"})), "admin:config")


def test_permissions_for_lists_exactly_what_is_allowed_sorted() -> None:
    from netsight_api.rbac import Permission, permissions_for

    human = Identity("a", frozenset({"technician"}), PrincipalKind.HUMAN)
    listed = permissions_for(human)
    assert listed == sorted(listed)
    assert set(listed) == {p.value for p in Permission if is_allowed(human, p.value)}
    assert "incidents:write-assigned" in listed
    assert "incidents:resolve" not in listed


def test_permissions_for_a_service_principal_excludes_human_only_permissions() -> None:
    from netsight_api.rbac import permissions_for

    robot = Identity("svc", frozenset({"administrator"}), PrincipalKind.SERVICE)
    assert "incidents:resolve" not in permissions_for(robot)
    assert "incidents:read" in permissions_for(robot)


def test_permissions_for_unknown_roles_is_empty() -> None:
    from netsight_api.rbac import permissions_for

    assert permissions_for(Identity("x", frozenset({"nope"}), PrincipalKind.HUMAN)) == []
