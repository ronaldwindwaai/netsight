"""Audit records for Netsight-managed authentication (ADR 0010).

Structured JSON to the ``netsight_api`` logger. Records carry a correlation ID
and an outcome, never a password, TOTP code, secret or session value.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Final, Literal

AuditOutcome = Literal["success", "failure", "denied", "locked"]

_LOGGER: Final = logging.getLogger("netsight_api.localauth")

# Fields that must never reach a log record, whatever a caller passes.
_FORBIDDEN_KEYS: Final = frozenset(
    {
        "password",
        "new_password",
        "candidate",
        "code",
        "totp",
        "totp_code",
        "token",
        "secret",
        "mfa_secret",
        "session",
        "cookie",
        "authorization",
    }
)


def _sanitise(details: dict[str, Any]) -> dict[str, Any]:
    cleaned: dict[str, Any] = {}
    for key, value in details.items():
        lowered = key.lower()
        if any(forbidden in lowered for forbidden in _FORBIDDEN_KEYS):
            continue
        if isinstance(value, (int, float, bool)) or value is None:
            cleaned[key] = value
        elif isinstance(value, str):
            # Bound the length so a crafted input cannot flood the log.
            cleaned[key] = value[:128]
    return cleaned


def record(
    event: str,
    *,
    outcome: AuditOutcome,
    correlation_id: str,
    username: str | None = None,
    **details: Any,
) -> None:
    """Emit one structured audit record."""
    payload: dict[str, Any] = {
        "event": f"localauth_{event}",
        "outcome": outcome,
        "correlation_id": correlation_id,
    }
    if username:
        payload["username"] = username[:MAX_USERNAME_FIELD]
    payload.update(_sanitise(details))

    _LOGGER.info(json.dumps(payload, sort_keys=True))


MAX_USERNAME_FIELD = 64