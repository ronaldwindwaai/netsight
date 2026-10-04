"""RBAC permission engine.

Deny-by-default: unknown roles, unknown permissions, and unauthenticated
identities are always denied.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum


class Permission(StrEnum):
    DEVICES_READ = "devices:read"
    ALERTS_READ = "alerts:read"
    INCIDENTS_READ = "incidents:read"
    INCIDENTS_WRITE = "incidents:write"
    TRAFFIC_READ = "traffic:read"
    SECURITY_READ = "security:read"
    DIAGNOSTICS_READ = "diagnostics:read"
    ACTIONS_PROPOSE = "actions:propose"
    ACTIONS_APPROVE = "actions:approve"
    ADMIN_CONFIG = "admin:config"
    REPORTS_READ = "reports:read"
    AUDIT_READ = "audit:read"


class Role(StrEnum):
    ADMINISTRATOR = "administrator"
    NETWORK_ENGINEER = "network_engineer"
    SECURITY_ANALYST = "security_analyst"
    TECHNICIAN = "technician"
    MANAGEMENT = "management"
    AUDITOR = "auditor"


_ALL_READ = {
    Permission.DEVICES_READ,
    Permission.ALERTS_READ,
    Permission.INCIDENTS_READ,
    Permission.TRAFFIC_READ,
    Permission.SECURITY_READ,
    Permission.DIAGNOSTICS_READ,
    Permission.REPORTS_READ,
}

ROLE_PERMISSIONS: Mapping[Role, frozenset[Permission]] = {
    Role.ADMINISTRATOR: frozenset(Permission),
    Role.NETWORK_ENGINEER: frozenset(
        _ALL_READ
        | {
            Permission.INCIDENTS_WRITE,
            Permission.ACTIONS_PROPOSE,
        }
    ),
    Role.SECURITY_ANALYST: frozenset(
        _ALL_READ | {Permission.INCIDENTS_WRITE, Permission.ACTIONS_PROPOSE}
    ),
    Role.TECHNICIAN: frozenset(
        {
            Permission.DEVICES_READ,
            Permission.ALERTS_READ,
            Permission.INCIDENTS_READ,
            Permission.INCIDENTS_WRITE,
            Permission.DIAGNOSTICS_READ,
            Permission.ACTIONS_PROPOSE,
        }
    ),
    Role.MANAGEMENT: frozenset(_ALL_READ | {Permission.AUDIT_READ}),
    Role.AUDITOR: frozenset(_ALL_READ | {Permission.AUDIT_READ}),
}


@dataclass(frozen=True)
class Identity:
    id: str
    roles: frozenset[str] = field(default_factory=frozenset)


def is_allowed(identity: Identity | None, permission: str) -> bool:
    if identity is None:
        return False
    try:
        perm = Permission(permission)
    except ValueError:
        return False
    for role_name in identity.roles:
        try:
            role = Role(role_name)
        except ValueError:
            continue  # unknown role contributes no permissions
        if perm in ROLE_PERMISSIONS[role]:
            return True
    return False


def require(identity: Identity | None, permission: str) -> None:
    if not is_allowed(identity, permission):
        raise PermissionError(f"denied: {permission}")
