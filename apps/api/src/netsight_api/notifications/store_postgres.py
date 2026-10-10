"""PostgreSQL implementation of the durable delivery-attempt store (see ``store``).

Append-only: the application role holds INSERT and SELECT only and the table rejects UPDATE,
DELETE and TRUNCATE by trigger. One short transaction per call, static SQL, bound parameters.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from netsight_api.notifications.dispatcher import DeliveryAttempt
from netsight_api.notifications.store import check_recent_limit, validate_attempt
from netsight_api.storage.connection import PostgresSettings

_INSERT = (
    "INSERT INTO notification_delivery_attempts (notification_id, alert_ref, channel, "
    "destination, attempt, status, code, attempted_at) "
    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
)
_COLUMNS = "notification_id, alert_ref, channel, destination, attempt, status, code, attempted_at"
_SELECT_FOR_NOTIFICATION = (
    f"SELECT {_COLUMNS} FROM notification_delivery_attempts "
    "WHERE notification_id = %s ORDER BY attempt, id LIMIT 50"
)
_SELECT_RECENT = (
    f"SELECT {_COLUMNS} FROM notification_delivery_attempts "
    "ORDER BY attempted_at DESC, id DESC LIMIT %s"
)
_SELECT_LAST_SENT = (
    "SELECT max(attempted_at) AS last_sent FROM notification_delivery_attempts "
    "WHERE alert_ref = %s AND status = 'sent'"
)


def _attempt_from_row(row: dict[str, Any]) -> DeliveryAttempt:
    return DeliveryAttempt(
        notification_id=row["notification_id"],
        alert_ref=row["alert_ref"],
        channel=row["channel"],
        destination=row["destination"],
        attempt=row["attempt"],
        status=row["status"],
        code=row["code"],
        at=row["attempted_at"],
    )


class PostgresDeliveryAttemptRepository:
    def __init__(self, settings: PostgresSettings) -> None:
        self._settings = settings

    def record(self, attempt: DeliveryAttempt) -> None:
        validate_attempt(attempt)
        with self._settings.session() as conn:
            conn.execute(
                _INSERT,
                (
                    attempt.notification_id,
                    attempt.alert_ref,
                    attempt.channel,
                    attempt.destination,
                    attempt.attempt,
                    attempt.status,
                    attempt.code,
                    attempt.at,
                ),
            )

    def for_notification(self, notification_id: str) -> tuple[DeliveryAttempt, ...]:
        with self._settings.session() as conn:
            rows = conn.execute(_SELECT_FOR_NOTIFICATION, (notification_id,)).fetchall()
        return tuple(_attempt_from_row(row) for row in rows)

    def recent(self, limit: int = 100) -> tuple[DeliveryAttempt, ...]:
        check_recent_limit(limit)
        with self._settings.session() as conn:
            rows = conn.execute(_SELECT_RECENT, (limit,)).fetchall()
        return tuple(_attempt_from_row(row) for row in rows)

    def last_sent_at(self, alert_ref: str) -> datetime | None:
        with self._settings.session() as conn:
            row = conn.execute(_SELECT_LAST_SENT, (alert_ref,)).fetchone()
        return None if row is None else row["last_sent"]
