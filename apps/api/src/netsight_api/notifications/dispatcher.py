"""Routing, escalation and bounded delivery (NOTIFICATION-ENGINE.md).

Everything that could grow is bounded: the queue (``queue_limit``; overflow is dropped and
recorded, never buffered), the retry count (``RetryPolicy`` caps attempts at 5 and each delay
at 60 s), and the delivery log (a ring buffer). The clock and the sleep function are injected,
so tests neither wait nor read the wall clock. Recorded attempts carry identifiers, a
destination *label* (a hash or a host) and a static code: never payload text, addresses,
URLs, tokens or provider messages.
"""

from __future__ import annotations

import logging
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from threading import Lock, Thread
from typing import Final, Literal, Protocol

from netsight_api.alerting.schedule import ScheduleError, schedule_active
from netsight_api.notifications.models import (
    ChannelKind,
    Destination,
    NotificationPayload,
    SendResult,
    link_is_under,
    unique_destinations,
)
from netsight_api.notifications.senders import NotificationSender
from netsight_api.notifications.store import check_recent_limit, validate_attempt
from netsight_api.schemas import AlertSchedule, AlertSeverity

_LOGGER: Final = logging.getLogger("netsight_api.notifications")
MAX_ESCALATION_SECONDS: Final = 7 * 24 * 3600
MAX_QUEUE_LIMIT: Final = 10_000
DEFAULT_SEND_TIMEOUT_SECONDS: Final = 60.0
_SEVERITY_RANK: Final = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# --- routing -----------------------------------------------------------------------------------


@dataclass(frozen=True)
class RoutingRule:
    """Severity, labels (site, team, service...) and schedule select destinations."""

    min_severity: AlertSeverity
    destinations: tuple[Destination, ...]
    labels: Mapping[str, str] = field(default_factory=dict)
    schedule: AlertSchedule | None = None


def _rule_matches(
    rule: RoutingRule, severity: AlertSeverity, labels: Mapping[str, str], at: datetime
) -> bool:
    if _SEVERITY_RANK[severity] < _SEVERITY_RANK[rule.min_severity]:
        return False
    if any(labels.get(key) != value for key, value in rule.labels.items()):
        return False
    try:
        return schedule_active(rule.schedule, at)
    except ScheduleError:
        return False  # an unevaluable schedule never routes (fail closed)


def route(
    rules: Sequence[RoutingRule],
    *,
    severity: AlertSeverity,
    labels: Mapping[str, str],
    at: datetime,
) -> tuple[Destination, ...]:
    """Destinations of every matching rule, deduplicated, in rule order. No match: nobody."""
    chosen: list[Destination] = []
    for rule in rules:
        if _rule_matches(rule, severity, labels, at):
            chosen.extend(rule.destinations)
    return unique_destinations(chosen)


# --- escalation --------------------------------------------------------------------------------


@dataclass(frozen=True)
class EscalationLevel:
    after_seconds: int
    destinations: tuple[Destination, ...]

    def __post_init__(self) -> None:
        if not 1 <= self.after_seconds <= MAX_ESCALATION_SECONDS:
            raise ValueError("after_seconds must be between 1 second and 7 days")
        if not self.destinations:
            raise ValueError("an escalation level needs at least one destination")


def escalation_due(
    levels: Sequence[EscalationLevel],
    *,
    fired_at: datetime,
    now: datetime,
    acknowledged_at: datetime | None,
    resolved_at: datetime | None,
    sent_levels: AbstractSet[int],
) -> tuple[int, ...]:
    """Indexes of levels to notify now: elapsed, not yet sent, alert neither acknowledged nor
    resolved. A late evaluator catches up on every elapsed level, in order."""
    for stop in (acknowledged_at, resolved_at):
        if stop is not None and stop <= now:
            return ()
    return tuple(
        index
        for index, level in enumerate(levels)
        if index not in sent_levels and now - fired_at >= timedelta(seconds=level.after_seconds)
    )


# --- retry policy and delivery records ----------------------------------------------------------


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 3
    base_delay_seconds: float = 1.0
    factor: float = 2.0
    max_delay_seconds: float = 30.0

    def __post_init__(self) -> None:
        if not 1 <= self.max_attempts <= 5:
            raise ValueError("max_attempts must be between 1 and 5")
        if not 0 <= self.base_delay_seconds <= 60:
            raise ValueError("base_delay_seconds must be between 0 and 60")
        if not 1 <= self.factor <= 4:
            raise ValueError("factor must be between 1 and 4")
        if not self.base_delay_seconds <= self.max_delay_seconds <= 60:
            raise ValueError("max_delay_seconds must be between the base delay and 60")

    def delay_after(self, attempt: int) -> float:
        """Seconds to wait after the failed ``attempt`` (1-based); deterministic, no jitter."""
        return min(self.base_delay_seconds * self.factor ** (attempt - 1), self.max_delay_seconds)


AttemptStatus = Literal["sent", "retrying", "failed", "dropped"]


@dataclass(frozen=True)
class DeliveryAttempt:
    notification_id: str
    alert_ref: str
    channel: ChannelKind
    destination: str
    attempt: int
    status: AttemptStatus
    code: str
    at: datetime


class DeliveryRecorder(Protocol):
    def record(self, attempt: DeliveryAttempt) -> None: ...


class InMemoryDeliveryRecorder:
    """A bounded ring of the most recent attempts: the fallback when no durable store is
    configured or reachable, and the in-memory implementation of ``DeliveryAttemptRepository``."""

    def __init__(self, maxlen: int = 1000) -> None:
        if not 1 <= maxlen <= 100_000:
            raise ValueError("maxlen must be between 1 and 100000")
        self._lock = Lock()
        self._attempts: deque[DeliveryAttempt] = deque(maxlen=maxlen)

    def record(self, attempt: DeliveryAttempt) -> None:
        validate_attempt(attempt)
        with self._lock:
            self._attempts.append(attempt)

    @property
    def attempts(self) -> tuple[DeliveryAttempt, ...]:
        with self._lock:
            return tuple(self._attempts)

    def for_notification(self, notification_id: str) -> tuple[DeliveryAttempt, ...]:
        found = (a for a in self.attempts if a.notification_id == notification_id)
        return tuple(sorted(found, key=lambda a: a.attempt))

    def recent(self, limit: int = 100) -> tuple[DeliveryAttempt, ...]:
        check_recent_limit(limit)
        ordered = sorted(enumerate(self.attempts), key=lambda pair: (pair[1].at, pair[0]))
        return tuple(attempt for _, attempt in reversed(ordered))[:limit]

    def last_sent_at(self, alert_ref: str) -> datetime | None:
        sent = [a.at for a in self.attempts if a.alert_ref == alert_ref and a.status == "sent"]
        return max(sent, default=None)


# --- dispatcher -----------------------------------------------------------------------------------


@dataclass(frozen=True)
class Notification:
    id: str
    payload: NotificationPayload
    destination: Destination


@dataclass(frozen=True)
class DeliveryOutcome:
    notification_id: str
    status: Literal["sent", "failed"]
    attempts: int
    code: str


class NotificationDispatcher:
    def __init__(
        self,
        senders: Mapping[ChannelKind, NotificationSender],
        recorder: DeliveryRecorder,
        *,
        clock: Callable[[], datetime],
        sleep: Callable[[float], None],
        policy: RetryPolicy | None = None,
        queue_limit: int = 1000,
        public_base_url: str | None = None,
        send_timeout_seconds: float = DEFAULT_SEND_TIMEOUT_SECONDS,
    ) -> None:
        if not 1 <= queue_limit <= MAX_QUEUE_LIMIT:
            raise ValueError(f"queue_limit must be between 1 and {MAX_QUEUE_LIMIT}")
        if not 0 < send_timeout_seconds <= 300:
            raise ValueError("send_timeout_seconds must be up to 300")
        self._send_timeout = send_timeout_seconds
        self._senders = dict(senders)
        self._recorder = recorder
        self._clock = clock
        self._sleep = sleep
        self._policy = policy or RetryPolicy()
        self._queue_limit = queue_limit
        self._public_base_url = public_base_url
        self._queue: deque[Notification] = deque()
        self._lock = Lock()

    @property
    def pending(self) -> int:
        with self._lock:
            return len(self._queue)

    def submit(self, notification: Notification) -> bool:
        """Queue for delivery; False (and a ``dropped`` record) when the queue is full."""
        with self._lock:
            if len(self._queue) < self._queue_limit:
                self._queue.append(notification)
                return True
        self._record(notification, 0, "dropped", "QUEUE_FULL")
        return False

    def drain(self, limit: int | None = None) -> tuple[DeliveryOutcome, ...]:
        """Deliver queued notifications in order, at most ``limit`` of them."""
        outcomes: list[DeliveryOutcome] = []
        while limit is None or len(outcomes) < limit:
            with self._lock:
                if not self._queue:
                    break
                notification = self._queue.popleft()
            outcomes.append(self.deliver(notification))
        return tuple(outcomes)

    def deliver(self, notification: Notification) -> DeliveryOutcome:
        """Send with bounded retry; every attempt is recorded.

        A link outside the configured public base URL is never sent (``LINK_REJECTED``, final):
        a notification is a message from Netsight, so it must not point somewhere else.
        """
        if not link_is_under(notification.payload.link, self._public_base_url):
            self._record(notification, 0, "failed", "LINK_REJECTED")
            return DeliveryOutcome(notification.id, "failed", 0, "LINK_REJECTED")
        sender = self._senders.get(notification.destination.kind)
        if sender is None:
            self._record(notification, 1, "failed", "NO_SENDER")
            return DeliveryOutcome(notification.id, "failed", 1, "NO_SENDER")
        result = SendResult("permanent", "SENDER_ERROR")
        for attempt in range(1, self._policy.max_attempts + 1):
            result = self._send_once(sender, notification)
            if result.status == "sent":
                self._record(notification, attempt, "sent", result.code)
                return DeliveryOutcome(notification.id, "sent", attempt, result.code)
            final = result.status != "retryable" or attempt == self._policy.max_attempts
            self._record(notification, attempt, "failed" if final else "retrying", result.code)
            if final:
                return DeliveryOutcome(notification.id, "failed", attempt, result.code)
            self._sleep(self._policy.delay_after(attempt))
        return DeliveryOutcome(notification.id, "failed", self._policy.max_attempts, result.code)

    def _send_once(self, sender: NotificationSender, notification: Notification) -> SendResult:
        """One send, bounded overall: socket timeouts bound each operation, not the whole send."""
        box: list[SendResult | Exception] = []

        def work() -> None:
            try:
                box.append(sender.send(notification.destination, notification.payload))
            except Exception as exc:  # noqa: BLE001 - handed back to the caller below
                box.append(exc)

        worker = Thread(target=work, name="netsight-send", daemon=True)
        worker.start()
        worker.join(self._send_timeout)
        if worker.is_alive() or not box:
            # Final, not retried: another attempt would only stack up hung threads, and the
            # message may in fact have gone out.
            _LOGGER.warning("notification send exceeded its overall timeout")
            return SendResult("permanent", "SEND_TIMEOUT")
        result = box[0]
        if isinstance(result, Exception):
            _LOGGER.warning(
                "notification sender raised", extra={"error_type": type(result).__name__}
            )
            return SendResult("retryable", "SENDER_ERROR")
        if result.status not in ("sent", "retryable", "permanent"):
            return SendResult("permanent", "SENDER_ERROR")
        return result

    def _record(
        self, notification: Notification, attempt: int, status: AttemptStatus, code: str
    ) -> None:
        try:
            self._recorder.record(
                DeliveryAttempt(
                    notification_id=notification.id,
                    alert_ref=notification.payload.alert_ref,
                    channel=notification.destination.kind,
                    destination=notification.destination.label,
                    attempt=attempt,
                    status=status,
                    code=code,
                    at=self._clock(),
                )
            )
        except Exception as exc:  # noqa: BLE001 - a bookkeeping failure must not stop delivery
            _LOGGER.warning(
                "delivery attempt not recorded", extra={"error_type": type(exc).__name__}
            )
