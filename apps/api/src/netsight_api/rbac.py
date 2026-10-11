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
    # Reduced list view: no evidence ids, no free-text resolution/comments, no timeline and no
    # assignee identity. Management holds this and not INCIDENTS_READ (RBAC-MATRIX "Summary").
    INCIDENTS_READ_SUMMARY = "incidents:read-summary"
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
    # Alert rules and maintenance windows (RBAC-MATRIX 'Alert rules'); every write is human-only.
    ALERT_RULES_READ = "alert-rules:read"
    ALERT_RULES_WRITE = "alert-rules:write"  # create / edit a draft
    ALERT_RULES_APPROVE = "alert-rules:approve"  # activation of the reviewed version
    ALERT_RULES_DISABLE = "alert-rules:disable"
    MAINTENANCE_READ = "maintenance:read"
    MAINTENANCE_WRITE = "maintenance:write"  # create / cancel a window below organisation scope
    MAINTENANCE_WRITE_ORGANISATION = "maintenance:write-organisation"  # silences everything
    TRAFFIC_READ = "traffic:read"
    SECURITY_READ = "security:read"
    DIAGNOSTICS_READ = "diagnostics:read"
    # Internet/WAN status, quality, availability and the monthly SLA figures (read-only).
    INTERNET_READ = "internet:read"
    # The bounded evidence export for ISP disputes (CSV/JSON of outage windows). Implies read.
    INTERNET_EXPORT = "internet:export"
    # The sensitive part of the Internet surface: public IP, gateway, ISP name and per-link
    # throughput. Without it those fields are withheld (null, detail_redacted=true).
    INTERNET_READ_DETAIL = "internet:read_detail"
    # Per-user identity data (PRD 10, 92). A strict-subset ladder: read (browse people, name the
    # person behind an address) > read-limited (resolve an address to its endpoint, never to a
    # person) > read-summary (aggregate counts only: no names, no identifiers).
    USERS_READ = "users:read"
    USERS_READ_LIMITED = "users:read-limited"
    USERS_READ_SUMMARY = "users:read-summary"
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
    {
        Permission.INCIDENTS_RESOLVE,
        Permission.INCIDENTS_REOPEN,
        # Monitoring configuration is never altered by an AI or service principal (AGENTS.md).
        Permission.ALERT_RULES_WRITE,
        Permission.ALERT_RULES_APPROVE,
        Permission.ALERT_RULES_DISABLE,
        Permission.MAINTENANCE_WRITE,
        Permission.MAINTENANCE_WRITE_ORGANISATION,
        # Per-user data is never browsed by a service or AI principal (inference abuse, PRD 92):
        # a person decides to look, and the read is audited under their name.
        Permission.USERS_READ,
        Permission.USERS_READ_LIMITED,
    }
)

_INCIDENT_FULL = {
    Permission.INCIDENTS_TRANSITION,
    Permission.INCIDENTS_ASSIGN,
    Permission.INCIDENTS_COMMENT,
    Permission.INCIDENTS_RESOLVE,
    Permission.INCIDENTS_REOPEN,
}

# "Scoped" in RBAC-MATRIX for Network Engineer / Security Analyst. Site scoping does not exist
# yet, so they author drafts, disable and schedule site-level maintenance, but cannot approve
# (activate) a rule or silence the whole organisation.
_ALERTING_AUTHOR = {
    Permission.ALERT_RULES_READ,
    Permission.ALERT_RULES_WRITE,
    Permission.ALERT_RULES_DISABLE,
    Permission.MAINTENANCE_READ,
    Permission.MAINTENANCE_WRITE,
}
_ALERTING_READ = {Permission.ALERT_RULES_READ, Permission.MAINTENANCE_READ}


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
    Permission.INCIDENTS_READ_SUMMARY,
    Permission.TRAFFIC_READ,
    Permission.SECURITY_READ,
    Permission.REPORTS_READ,
    Permission.INTERNET_READ,
}
# The WAN card is an Overview widget and the matrix gives Overview to every role, so every role
# reads the Internet surface (Technician included); the evidence export is narrower.
_INTERNET_EXPORT = {Permission.INTERNET_EXPORT}
# Detail (public IP, gateway, ISP, throughput) is for the roles that run or defend the network.
# Technician, Management and Auditor read status and the SLA summary only (security review M2).
_INTERNET_DETAIL = {Permission.INTERNET_READ_DETAIL}
# RBAC-MATRIX "Diagnostics": Admin / Network Engineer Full, Security Analyst "Security scope",
# Technician "Basic"; Management and Auditor have none. Site / security scoping does not exist
# yet, so every holder gets the same read-only surface. Held on its own (not in _ALL_READ) so a
# role that reads everything else is not given diagnostics by accident.
_DIAGNOSTICS = {Permission.DIAGNOSTICS_READ}
# Identity: the ladder is held as three nested sets so a role can never have a rung without the ones
# below it (asserted in test_rbac_identity.py). Auditor holds none until the owner decides.
_USERS_SUMMARY = {Permission.USERS_READ_SUMMARY}
_USERS_LIMITED = _USERS_SUMMARY | {Permission.USERS_READ_LIMITED}
_USERS_FULL = _USERS_LIMITED | {Permission.USERS_READ}

ROLE_PERMISSIONS: Mapping[Role, frozenset[Permission]] = {
    Role.ADMINISTRATOR: frozenset(Permission),
    Role.NETWORK_ENGINEER: frozenset(
        _ALL_READ
        | _DIAGNOSTICS
        | _INCIDENT_FULL
        | _ALERTING_AUTHOR
        | _INTERNET_EXPORT
        | _INTERNET_DETAIL
        | _USERS_FULL
        | {Permission.ACTIONS_PROPOSE}
    ),
    Role.SECURITY_ANALYST: frozenset(
        _ALL_READ
        | _DIAGNOSTICS
        | _INCIDENT_FULL
        | _ALERTING_AUTHOR
        | _INTERNET_DETAIL
        | _USERS_FULL
        | {Permission.ACTIONS_PROPOSE}
    ),
    Role.TECHNICIAN: frozenset(
        {
            Permission.DEVICES_READ,
            Permission.ALERTS_READ,
            Permission.INCIDENTS_READ,
            Permission.INCIDENTS_READ_SUMMARY,
            Permission.INCIDENTS_WRITE_ASSIGNED,
            Permission.DIAGNOSTICS_READ,
            Permission.INTERNET_READ,
            Permission.ACTIONS_PROPOSE,
            *_USERS_LIMITED,
        }
    ),
    # Summary only: the full incident read is withheld (human decision 2026-10-10).
    Role.MANAGEMENT: frozenset(
        (_ALL_READ - {Permission.INCIDENTS_READ}) | _USERS_SUMMARY | {Permission.AUDIT_READ}
    ),
    Role.AUDITOR: frozenset(
        _ALL_READ | _ALERTING_READ | _INTERNET_EXPORT | {Permission.AUDIT_READ}
    ),
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


def permissions_for(identity: Identity | None) -> list[str]:
    """Every permission ``identity`` holds, sorted. For the UI to enable or explain actions.

    Derived from ``is_allowed`` so it cannot drift from what the API enforces. It is advisory
    to the browser: the server re-checks every request.
    """
    return sorted(p.value for p in Permission if is_allowed(identity, p.value))


def require(identity: Identity | None, permission: str) -> None:
    if not is_allowed(identity, permission):
        raise PermissionError(f"denied: {permission}")
