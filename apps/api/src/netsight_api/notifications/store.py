"""Durable delivery-attempt storage contract and the recorder that uses it.

A delivery attempt is an identifier-only record (notification id, alert reference, channel, a
destination *label*, attempt number, status, a static code, a time). It never holds payload
text, addresses, URLs, tokens or provider messages, so storing it durably adds no secret to the
database. ``validate_attempt`` is the single definition of what a storable attempt looks like;
both the in-memory ring and the PostgreSQL repository apply it, so they cannot disagree.

``DurableDeliveryRecorder`` keeps the in-memory ring as the always-on fallback: every attempt
lands in the ring first, then in the durable store on a best-effort basis. A store failure never
stops delivery and never loses the attempt from the ring; it is counted and logged by type only.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime
from threading import Lock
from typing import TYPE_CHECKING, Final, Protocol

if TYPE_CHECKING:
    from netsight_api.notifications.dispatcher import DeliveryAttempt

_LOGGER: Final = logging.getLogger("netsight_api.notifications")
MAX_RECENT_ATTEMPTS: Final = 500
MAX_DESTINATION_LENGTH: Final = 300
MAX_ATTEMPT_NUMBER: Final = 5
_ID: Final = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_CODE: Final = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_CONTROL: Final = re.compile(r"[\x00-\x1f\x7f]")
_CHANNELS: Final = frozenset({"email", "push", "webhook"})
_STATUSES: Final = frozenset({"sent", "retrying", "failed", "dropped"})


def validate_attempt(attempt: DeliveryAttempt) -> None:
    """Raise ``ValueError`` unless the attempt is safe and bounded to store."""
    if not _ID.fullmatch(attempt.notification_id) or not _ID.fullmatch(attempt.alert_ref):
        raise ValueError("notification_id and alert_ref must be short identifiers")
    if attempt.channel not in _CHANNELS or attempt.status not in _STATUSES:
        raise ValueError("unknown channel or status")
    if not 0 <= attempt.attempt <= MAX_ATTEMPT_NUMBER:
        raise ValueError(f"attempt must be between 0 and {MAX_ATTEMPT_NUMBER}")
    if not _CODE.fullmatch(attempt.code):
        raise ValueError("code must be a short static identifier")
    destination = attempt.destination
    if not 1 <= len(destination) <= MAX_DESTINATION_LENGTH or _CONTROL.search(destination):
        raise ValueError("destination must be a short single-line label")
    if attempt.at.tzinfo is None or attempt.at.utcoffset() is None:
        raise ValueError("the attempt time must be timezone-aware")


def check_recent_limit(limit: int) -> None:
    if not 1 <= limit <= MAX_RECENT_ATTEMPTS:
        raise ValueError(f"limit must be between 1 and {MAX_RECENT_ATTEMPTS}")


class DeliveryAttemptRepository(Protocol):
    """Append-only: there is no update or delete."""

    def record(self, attempt: DeliveryAttempt) -> None: ...

    def for_notification(self, notification_id: str) -> tuple[DeliveryAttempt, ...]:
        """Attempts of one notification in attempt order (oldest first)."""
        ...

    def recent(self, limit: int = 100) -> tuple[DeliveryAttempt, ...]:
        """Newest first; ``limit`` is 1 to ``MAX_RECENT_ATTEMPTS``."""
        ...

    def last_sent_at(self, alert_ref: str) -> datetime | None:
        """Time of the latest successful send for the alert, if any (restart-safe cooldown)."""
        ...


class AttemptSink(Protocol):
    def record(self, attempt: DeliveryAttempt) -> None: ...


class DurableDeliveryRecorder:
    """Ring first, durable store best effort (see the module docstring)."""

    def __init__(self, ring: AttemptSink, durable: DeliveryAttemptRepository) -> None:
        self._ring = ring
        self._durable = durable
        self._lock = Lock()
        self._failures = 0

    @property
    def durable_failures(self) -> int:
        """Attempts the durable store did not accept (they are still in the ring)."""
        with self._lock:
            return self._failures

    def record(self, attempt: DeliveryAttempt) -> None:
        self._ring.record(attempt)
        try:
            self._durable.record(attempt)
        except Exception as exc:  # noqa: BLE001 - the ring already holds it; delivery goes on
            with self._lock:
                self._failures += 1
            _LOGGER.warning(
                "delivery attempt was not stored durably",
                extra={"error_type": type(exc).__name__},
            )
