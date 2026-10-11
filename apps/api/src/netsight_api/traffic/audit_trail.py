"""Audit records for the traffic routes: who asked, what class of answer, never what was asked.

Every record names the actor, the action, the outcome and a **static reason code**. A read records
the state, the counts, the *names* of the filters used, the tier and the cohort rule's verdict; it
never records a filter value, an address, an application, a destination or a person's name, so the
audit trail can not become a second copy of the data it protects.

One deliberate exception, for the investigator's own accountability: when a detail-tier caller
looks up an address, device or VLAN, the record may carry a **keyed fingerprint** of that value
(``fp_<filter>``, 16 hex characters of an HMAC-SHA256). The fingerprint lets an auditor ask "who looked
up this address?" (compute the same HMAC for the address in question) and see repeated lookups of one
target, without the trail holding the address. It is keyed so it can not be reversed by hashing the
IPv4 space, and it is omitted (never degraded to a plain hash) when no key is configured.

* ``NETSIGHT_AUDIT_FILTER_FINGERPRINT``: ``on`` (default) or ``off``/``0``/``false``/``no``;
* ``NETSIGHT_AUDIT_FILTER_KEY``: the HMAC key (at least 32 characters). When unset the identity
  evidence-id key (``NETSIGHT_IDENTITY_ID_KEY``) is used; when neither is usable the fingerprints are
  omitted and that is logged once.

See docs/08-operations/AUDIT-LOGGING.md.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
from typing import Any, Final

from fastapi import Request

from netsight_api.alerting_route_support import correlation_id
from netsight_api.audit import AuditOutcome, record_audit
from netsight_api.errors import ApiError
from netsight_api.identity.id_key import ID_KEY_ENV
from netsight_api.traffic.filters import ENDPOINT_FILTERS, FilterError, FlowFilterSet

_LOGGER = logging.getLogger("netsight_api")

FINGERPRINT_ENV: Final = "NETSIGHT_AUDIT_FILTER_FINGERPRINT"
FILTER_KEY_ENV: Final = "NETSIGHT_AUDIT_FILTER_KEY"
MIN_KEY_LENGTH: Final = 32
FINGERPRINT_LENGTH: Final = 16
FINGERPRINT_CONTEXT: Final = b"netsight.audit.filter.v1"
_OFF: Final = frozenset({"off", "0", "false", "no"})
_unkeyed_logged = False


def reason_for(error: FilterError | ApiError) -> str:
    """A static reason code for a rejected request (never derived from what the caller sent)."""
    if isinstance(error, FilterError):
        if error.field == "parameter":
            return error.reason.replace(" ", "-")  # unknown-parameter, repeated-parameter
        return "invalid-filter"
    return "invalid-window"


def _write(
    request: Request, actor_id: str, action: str, outcome: AuditOutcome, **fields: Any
) -> None:
    record_audit(
        action,
        outcome=outcome,
        actor_id=actor_id,
        correlation_id=correlation_id(request),
        **fields,
    )


def denied(request: Request, actor_id: str, action: str, reason: str) -> None:
    _write(request, actor_id, action, "denied", reason=reason)


def failed(request: Request, actor_id: str, action: str, reason: str) -> None:
    _write(request, actor_id, action, "failure", reason=reason)


def read(
    request: Request, actor_id: str, action: str, *, failure: bool = False, **fields: Any
) -> None:
    """A completed read. ``fields`` are counts, state names and tier labels, never values."""
    _write(request, actor_id, action, "failure" if failure else "success", **fields)


# --- keyed fingerprints of endpoint-level filter values ---------------------------------------------


def _key() -> bytes | None:
    global _unkeyed_logged
    for name in (FILTER_KEY_ENV, ID_KEY_ENV):
        configured = os.environ.get(name, "").strip()
        if len(configured) >= MIN_KEY_LENGTH:
            return configured.encode()
    if not _unkeyed_logged:
        _unkeyed_logged = True
        _LOGGER.warning(
            "audit filter fingerprints are enabled but no key of %d characters is configured "
            "(%s or %s); they are omitted",
            MIN_KEY_LENGTH,
            FILTER_KEY_ENV,
            ID_KEY_ENV,
        )
    return None


def fingerprint_of(name: str, value: str, key: bytes) -> str:
    """``HMAC-SHA256(key, context | name | value)``, truncated: stable, keyed, not reversible."""
    message = b"\x00".join((FINGERPRINT_CONTEXT, name.encode(), value.encode()))
    return hmac.new(key, message, hashlib.sha256).hexdigest()[:FINGERPRINT_LENGTH]


def filter_fingerprints(filters: FlowFilterSet) -> dict[str, str]:
    """``fp_<filter>`` for each endpoint-level filter in use; empty when disabled or unkeyed."""
    if os.environ.get(FINGERPRINT_ENV, "on").strip().lower() in _OFF:
        return {}
    used = [name for name in filters.active() if name in ENDPOINT_FILTERS]
    key = _key() if used else None
    if key is None:
        return {}
    return {f"fp_{name}": fingerprint_of(name, str(getattr(filters, name)), key) for name in used}


def reset_for_tests() -> None:
    global _unkeyed_logged
    _unkeyed_logged = False
