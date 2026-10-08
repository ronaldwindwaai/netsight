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
    # Acknowledge / investigate / mitigate / close any incident.
    INCIDENTS_TRANSITION = "incidents:transition"
    INCIDENTS_ASSIGN = "incidents:assign"
    # Comments and evidence references on any incident.
    INCIDENTS_COMMENT = "incidents:comment"
    # Records the root cause; human principals only (see HUMAN_ONLY_PERMISSIONS).
    INCIDENTS_RESOLVE = "incidents:resolve"
    INCIDENTS_REOPEN = "incidents:reopen"
    # RBAC-MATRIX "Assigned": progress / comment / evidence on incidents assigned to the caller.
    INCIDENTS_WRITE_ASSIGNED = "incidents:write-assigned"
    TRAFFIC_READ = "traffic:read"
    SECURITY_READ = "security:read"
    DIAGNOSTICS_READ = "diagnostics:read"
    ACTIONS_PROPOSE = "actions:propose"
    ACTIONS_APPROVE = "actions:approve"
    ADMIN_CONFIG = "admin:config"
    REPORTS_READ = "reports:read"
    AUDIT_READ = "audit:read"


class PrincipalKind(StrEnum):
    """What kind of caller an identity is. Only an authenticated session is HUMAN."""

    HUMAN = "human"
    SERVICE = "service"
    AI = "ai"


# Permissions that record a human judgement. No service or AI principal may hold them,
# whatever role it carries: an AI-proposed root cause must be accepted by an operator.
HUMAN_ONLY_PERMISSIONS: frozenset[Permission] = frozenset(
    {Permission.INCIDENTS_RESOLVE, Permission.INCIDENTS_REOPEN}
)

_INCIDENT_FULL = {
    Permission.INCIDENTS_TRANSITION,
    Permission.INCIDENTS_ASSIGN,
    Permission.INCIDENTS_COMMENT,
    Permission.INCIDENTS_RESOLVE,
    Permission.INCIDENTS_REOPEN,
}


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
    Role.NETWORK_ENGINEER: frozenset(_ALL_READ | _INCIDENT_FULL | {Permission.ACTIONS_PROPOSE}),
    Role.SECURITY_ANALYST: frozenset(_ALL_READ | _INCIDENT_FULL | {Permission.ACTIONS_PROPOSE}),
    Role.TECHNICIAN: frozenset(
        {
            Permission.DEVICES_READ,
            Permission.ALERTS_READ,
            Permission.INCIDENTS_READ,
            Permission.INCIDENTS_WRITE_ASSIGNED,
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
    # Not human unless the authentication layer says so (deny-by-default).
    principal: PrincipalKind = PrincipalKind.SERVICE


def is_allowed(identity: Identity | None, permission: str) -> bool:
    if identity is None:
        return False
    try:
        perm = Permission(permission)
    except ValueError:
        return False
    if perm in HUMAN_ONLY_PERMISSIONS and identity.principal is not PrincipalKind.HUMAN:
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
