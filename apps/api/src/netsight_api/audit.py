"""Structured audit records for security-sensitive API mutations (AGENTS.md, PRD 32).

One JSON object per record on the ``netsight_api.audit`` logger. A record names the
action, the outcome, the acting identity, the target, the request correlation id and a
UTC timestamp. It never carries free text a caller supplied (comments, titles, root
causes), tokens, session values or connection strings: ``details`` accepts only short
scalars and any key that looks secret-bearing is dropped. Caller-chosen values that are
identifiers (assignee, evidence reference) are recorded as a length and a short hash
(``fingerprint``) so two records can be correlated without the value being disclosed.

Identifiers longer than ``MAX_FIELD_LENGTH`` are replaced by ``sha256:<hex>`` rather than
truncated, because truncation makes distinct identities indistinguishable in the trail.

Python's logging drops INFO records unless something enables them, and the success
audit is an INFO record. ``configure_audit_logging`` (called at application start-up)
therefore installs a dedicated handler and level; see docs/08-operations/AUDIT-LOGGING.md.
Emitting a record never raises: a broken sink must not turn a committed write into an
error response.

This is the interim audit sink. The durable, tamper-evident audit store (PRD 32) will
consume the same records; until then the incident timeline is the authoritative,
append-only record of who changed an incident and when.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final, Literal

AuditOutcome = Literal["success", "denied", "failure"]

_LOGGER: Final = logging.getLogger("netsight_api.audit")
_FALLBACK_LOGGER: Final = logging.getLogger("netsight_api")
MAX_FIELD_LENGTH: Final = 128
FINGERPRINT_LENGTH: Final = 16
_FORBIDDEN_KEY_PARTS: Final = frozenset(
    {"password", "secret", "token", "cookie", "session", "authorization", "dsn", "message"}
)
_LEVELS: Final = {"INFO": logging.INFO, "WARNING": logging.WARNING}
_DESTINATIONS: Final = ("stderr", "stdout", "file")
_HANDLER_MARKER: Final = "netsight_audit"


def fingerprint(value: str) -> str:
    """Short stable hash of a caller-supplied value (correlatable, not reversible in practice)."""
    digest = hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()
    return digest[:FINGERPRINT_LENGTH]


def _bounded_id(value: object) -> object:
    """Identifiers are kept verbatim when short and hashed (never truncated) when long."""
    if isinstance(value, str) and len(value) > MAX_FIELD_LENGTH:
        return "sha256:" + hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()
    return _clean(value)


def bounded_identifier(value: str) -> str:
    """An identifier for a details field: verbatim when short, hashed (never truncated) when long."""
    bounded = _bounded_id(value)
    return bounded if isinstance(bounded, str) else ""


def _clean(value: object) -> object:
    if isinstance(value, bool) or value is None or isinstance(value, int | float):
        return value
    if isinstance(value, str):
        return value[:MAX_FIELD_LENGTH]
    return None


def record_audit(
    action: str,
    *,
    outcome: AuditOutcome,
    actor_id: str | None,
    correlation_id: str,
    target: str | None = None,
    **details: object,
) -> None:
    """Emit one audit record (INFO for success, WARNING for denied and failed attempts)."""
    try:
        payload: dict[str, Any] = {
            "event": "audit",
            "ts": datetime.now(UTC).isoformat(),
            "action": action,
            "outcome": outcome,
            "actor_id": _bounded_id(actor_id),
            "target": _bounded_id(target),
            "correlation_id": _bounded_id(correlation_id),
        }
        for key, value in details.items():
            if any(part in key.lower() for part in _FORBIDDEN_KEY_PARTS):
                continue
            payload[key] = _clean(value)
        level = logging.INFO if outcome == "success" else logging.WARNING
        _LOGGER.log(level, json.dumps(payload, sort_keys=True, default=str))
    except Exception as exc:  # noqa: BLE001 — an audit sink failure must never fail the request
        _FALLBACK_LOGGER.error(
            "audit record could not be emitted", extra={"error_type": type(exc).__name__}
        )


# --- logging configuration -----------------------------------------------------------------------


@dataclass(frozen=True)
class AuditLogSettings:
    """``NETSIGHT_AUDIT_LOG_LEVEL`` INFO|WARNING, ``..._DESTINATION`` stderr|stdout|file, ``..._FILE``."""

    level: str = "INFO"
    destination: str = "stderr"
    file: str = ""

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> AuditLogSettings:
        source = os.environ if env is None else env
        level = source.get("NETSIGHT_AUDIT_LOG_LEVEL", "INFO").strip().upper()
        destination = source.get("NETSIGHT_AUDIT_LOG_DESTINATION", "stderr").strip().lower()
        file = source.get("NETSIGHT_AUDIT_LOG_FILE", "").strip()
        if level not in _LEVELS:
            # Anything above WARNING would silently discard denied and failed attempts.
            raise ValueError("NETSIGHT_AUDIT_LOG_LEVEL must be INFO or WARNING")
        if destination not in _DESTINATIONS:
            raise ValueError("NETSIGHT_AUDIT_LOG_DESTINATION must be stderr, stdout or file")
        if destination == "file" and not file:
            raise ValueError("NETSIGHT_AUDIT_LOG_FILE is required when the destination is file")
        return cls(level=level, destination=destination, file=file)


def _build_handler(settings: AuditLogSettings) -> logging.Handler:
    handler: logging.Handler
    if settings.destination == "file":
        handler = logging.FileHandler(settings.file, encoding="utf-8")
    else:
        handler = logging.StreamHandler(
            sys.stdout if settings.destination == "stdout" else sys.stderr
        )
    handler.setFormatter(logging.Formatter("%(message)s"))  # the record is already a JSON line
    setattr(handler, _HANDLER_MARKER, True)
    return handler


def configure_audit_logging(env: Mapping[str, str] | None = None) -> None:
    """Enable the audit logger at the configured level with one JSON-lines handler.

    Idempotent: a previous handler installed here is replaced, never duplicated.
    ``propagate`` is left on so test capture and any operator-installed root handler
    still see the records; leave the root logger unconfigured to avoid duplicates.
    Raises ``ValueError`` for an invalid configuration so a bad setting fails start-up.
    """
    settings = AuditLogSettings.from_env(env)
    handler = _build_handler(settings)
    for existing in list(_LOGGER.handlers):
        if getattr(existing, _HANDLER_MARKER, False):
            _LOGGER.removeHandler(existing)
            existing.close()
    _LOGGER.addHandler(handler)
    _LOGGER.setLevel(_LEVELS[settings.level])
