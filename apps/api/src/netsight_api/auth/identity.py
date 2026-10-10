"""Map verified OIDC claims to a Netsight RBAC identity.

Roles are resolved from a configurable claim and an explicit allow-list
mapping. Unknown roles are dropped (deny-by-default). A least-privilege
default role is applied only when it is a valid Netsight role.
"""

from __future__ import annotations

import math
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


def mfa_asserted(claims: dict[str, Any]) -> bool:
    """True only when the verified token explicitly lists ``mfa`` in ``amr``.

    Absence proves nothing, so it is False: the step-up check then fails closed. A provider
    that does not emit ``amr`` (Google) therefore cannot satisfy step-up through OIDC.
    """
    return any(value.lower() == "mfa" for value in _as_list(claims.get("amr")))


MFA_CLOCK_SKEW_SECONDS = 5.0
# A step-up token's ``auth_time`` may precede the moment the step-up was requested by this much
# (provider clock skew and second-granularity ``auth_time``); anything older is a replayed token.
STEP_UP_REPLAY_TOLERANCE_SECONDS = 5.0


def mfa_age(
    claims: dict[str, Any],
    *,
    now: float,
    max_age: float,
    step_up_requested_at: float | None = None,
) -> tuple[float | None, str | None]:
    """How long ago the token's own second factor happened, or why it does not count.

    Returns ``(age_seconds, None)`` when the token asserts MFA (``amr``) *and* carries a numeric
    ``auth_time`` that is not in the future (beyond a small skew), not older than ``max_age`` and,
    for a step-up, not older than the moment the step-up was requested (less ``STEP_UP_REPLAY_TOLERANCE_SECONDS``). Otherwise
    ``(None, reason)`` with a static reason code (``mfa-not-asserted`` is expected for tokens
    that simply do not claim MFA). The age is relative to ``now`` so the caller can place it on
    the session store's clock; session creation time is never used.
    """
    if not mfa_asserted(claims):
        return None, "mfa-not-asserted"
    auth_time = claims.get("auth_time")
    if auth_time is None:
        return None, "auth-time-missing"
    if isinstance(auth_time, bool) or not isinstance(auth_time, (int, float)):
        return None, "auth-time-invalid"
    if not math.isfinite(auth_time):
        return None, "auth-time-invalid"
    if (
        step_up_requested_at is not None
        and auth_time < step_up_requested_at - STEP_UP_REPLAY_TOLERANCE_SECONDS
    ):
        return None, "step-up-replay"
    age = now - auth_time
    if age < -MFA_CLOCK_SKEW_SECONDS:
        return None, "auth-time-future"
    if age > max_age:
        return None, "auth-time-stale"
    return max(age, 0.0), None
