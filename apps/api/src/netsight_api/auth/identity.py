"""Map verified OIDC claims to a Netsight RBAC identity.

Roles are resolved from a configurable claim and an explicit allow-list
mapping. Unknown roles are dropped (deny-by-default). A least-privilege
default role is applied only when it is a valid Netsight role.
"""

from __future__ import annotations

from typing import Any

from netsight_api.auth.settings import AuthSettings, parse_role_mapping
from netsight_api.rbac import Identity, Role


def _as_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def resolve_roles(claims: dict[str, Any], settings: AuthSettings) -> frozenset[str]:
    """Resolve Netsight roles from token claims and configured mapping."""
    mapping = parse_role_mapping(settings.role_mapping)
    claim_values: list[str] = []
    if settings.role_claim:
        claim_values = _as_list(claims.get(settings.role_claim))

    resolved: set[str] = set()
    for value in claim_values:
        role = mapping.get(value)
        if role is not None:
            resolved.add(role)

    valid_roles = {role for role in resolved if role in {r.value for r in Role}}

    if not valid_roles and settings.default_role in {r.value for r in Role}:
        valid_roles = {settings.default_role}
    # If the default role is also invalid, no roles are assigned and
    # the identity is denied every permission (deny-by-default).

    return frozenset(valid_roles)


def build_identity(claims: dict[str, Any], settings: AuthSettings, provider: str) -> Identity:
    """Build a canonical Netsight identity from verified claims.

    The primary key is the immutable provider subject, never the email
    address (docs/01-architecture/identity-architecture.md).
    """
    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject:
        raise ValueError("verified claims did not contain a subject")
    identity_id = f"{provider}:{subject}"
    return Identity(id=identity_id, roles=resolve_roles(claims, settings))
