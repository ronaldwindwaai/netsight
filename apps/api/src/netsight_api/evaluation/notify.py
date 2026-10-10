"""Engine -> notification routing -> dispatcher.

``AlertNotifier.notify`` is called by the evaluation runner (never by a route) when the engine
releases a notification. It selects destinations with the routing table, keeps only channels the
rule's ``actions`` name (``email`` / ``push``), builds a payload that links to authenticated
Netsight instead of embedding telemetry, hands each notification to the bounded dispatcher
queue, and audits every outcome with static codes only (no address, token or payload text).

Restart safety: engine state lives in memory, so after a restart a still-firing alert would be
released again. The durable delivery ledger answers "was this alert sent recently?": a successful
send within the rule's cooldown suppresses the repeat. With ``cooldown_seconds = 0`` a restart can
repeat a page; that is the rule author's trade-off, recorded in NOTIFICATION-ENGINE.md.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import timedelta
from typing import Final
from urllib.parse import quote

from netsight_api.alerting.engine import Decision
from netsight_api.audit import record_audit
from netsight_api.evaluation.incidents import SERVICE_ACTOR_ID
from netsight_api.notifications.dispatcher import (
    DeliveryOutcome,
    Notification,
    NotificationDispatcher,
    RoutingRule,
    route,
)
from netsight_api.notifications.models import (
    MAX_SUMMARY_LENGTH,
    MAX_TITLE_LENGTH,
    Destination,
    NotificationPayload,
    build_link,
    sanitize_line,
)
from netsight_api.notifications.store import DeliveryAttemptRepository
from netsight_api.schemas import AlertRule

_LOGGER: Final = logging.getLogger("netsight_api.evaluation")
MAX_DESTINATIONS_PER_ALERT: Final = 100
PayloadFactory = Callable[[str], NotificationPayload]


@dataclass(frozen=True)
class NotifyResult:
    sent: int = 0
    failed: int = 0
    skipped: str | None = None  # why nothing was attempted: a static reason


class AlertNotifier:
    def __init__(
        self,
        dispatcher: NotificationDispatcher,
        routing: Sequence[RoutingRule],
        attempts: DeliveryAttemptRepository,
        *,
        public_base_url: str | None,
    ) -> None:
        self._dispatcher = dispatcher
        self._routing = tuple(routing)
        self._attempts = attempts
        self._base_url = public_base_url

    def notify(
        self,
        *,
        rule: AlertRule,
        decision: Decision,
        entity: str,
        incident_id: str | None,
        correlation_id: str,
    ) -> NotifyResult:
        if not decision.notify:
            return NotifyResult(skipped="not-due")
        destinations = self._destinations(rule, decision)
        if not destinations:
            return NotifyResult(skipped="no-destination")
        if self._base_url is None:
            self._audit_skip(correlation_id, rule, decision, "no-public-url")
            return NotifyResult(skipped="no-public-url")
        if self._within_cooldown(rule, decision):
            return NotifyResult(skipped="cooldown")
        payload_for = self._payload_builder(rule, decision, entity, incident_id, self._base_url)
        return self._deliver(destinations, payload_for, decision, incident_id, correlation_id)

    # -- internals ---------------------------------------------------------------------------

    def _destinations(self, rule: AlertRule, decision: Decision) -> tuple[Destination, ...]:
        wanted = {action for action in rule.actions if action in ("email", "push")}
        chosen = route(self._routing, severity=rule.severity, labels=rule.labels, at=decision.at)
        return tuple(d for d in chosen if d.kind in wanted)[:MAX_DESTINATIONS_PER_ALERT]

    def _within_cooldown(self, rule: AlertRule, decision: Decision) -> bool:
        if rule.cooldown_seconds <= 0:
            return False
        try:
            last = self._attempts.last_sent_at(decision.fingerprint)
        except Exception as error:  # noqa: BLE001 - an unreadable ledger must not mute a page
            _LOGGER.warning(
                "delivery ledger unreadable", extra={"error_type": type(error).__name__}
            )
            return False
        return last is not None and decision.at - last < timedelta(seconds=rule.cooldown_seconds)

    def _payload_builder(
        self,
        rule: AlertRule,
        decision: Decision,
        entity: str,
        incident_id: str | None,
        base_url: str,
    ) -> PayloadFactory:
        if incident_id is not None:
            link = f"{base_url.rstrip('/')}/incidents/{quote(incident_id, safe='')}"
        else:
            link = build_link(base_url, decision.fingerprint)
        title = sanitize_line(rule.name, MAX_TITLE_LENGTH) or "Alert"
        summary = sanitize_line(
            f"{rule.severity} alert for {entity} ({rule.condition.metric}).", MAX_SUMMARY_LENGTH
        )

        def build(notification_id: str) -> NotificationPayload:
            return NotificationPayload(
                notification_id=notification_id,
                alert_ref=decision.fingerprint,
                severity=rule.severity,
                title=title,
                summary=summary,
                link=link,
                occurred_at=decision.at,
                incident_id=incident_id,
            )

        return build

    def _deliver(
        self,
        destinations: tuple[Destination, ...],
        payload_for: PayloadFactory,
        decision: Decision,
        incident_id: str | None,
        correlation_id: str,
    ) -> NotifyResult:
        stamp = int(decision.at.timestamp())
        sent = failed = 0
        queued: list[Notification] = []
        for index, destination in enumerate(destinations):
            notification_id = f"n-{decision.fingerprint[:16]}-{stamp}-{index}"
            notification = Notification(notification_id, payload_for(notification_id), destination)
            try:
                accepted = self._dispatcher.submit(notification)
            except Exception as error:  # noqa: BLE001 - contained and reported
                self._audit(correlation_id, notification, incident_id, "DISPATCH_ERROR", 0, False)
                _LOGGER.warning("dispatch failed", extra={"error_type": type(error).__name__})
                failed += 1
                continue
            if accepted:
                queued.append(notification)
            else:
                self._audit(correlation_id, notification, incident_id, "QUEUE_FULL", 0, False)
                failed += 1
        outcomes = self._drain(len(queued))  # one notification at a time: partial results survive
        for notification in queued:
            outcome = outcomes.get(notification.id)
            ok = outcome is not None and outcome.status == "sent"
            code = outcome.code if outcome is not None else "NOT_DELIVERED"
            attempts = outcome.attempts if outcome is not None else 0
            self._audit(correlation_id, notification, incident_id, code, attempts, ok)
            sent, failed = (sent + 1, failed) if ok else (sent, failed + 1)
        return NotifyResult(sent=sent, failed=failed)

    def _drain(self, count: int) -> dict[str, DeliveryOutcome]:
        """Deliver ``count`` queued notifications, one drain call each, so a failure while
        handling one never hides the outcomes of the others (that one is ``NOT_DELIVERED``)."""
        outcomes: dict[str, DeliveryOutcome] = {}
        for _ in range(count):
            try:
                delivered = self._dispatcher.drain(limit=1)
            except Exception as error:  # noqa: BLE001 - contained and reported
                _LOGGER.warning("delivery drain failed", extra={"error_type": type(error).__name__})
                continue
            if not delivered:
                break
            outcomes.update((o.notification_id, o) for o in delivered)
        return outcomes

    @staticmethod
    def _audit(
        correlation_id: str,
        notification: Notification,
        incident_id: str | None,
        code: str,
        attempts: int,
        ok: bool,
    ) -> None:
        record_audit(
            "notification.send",
            outcome="success" if ok else "failure",
            actor_id=SERVICE_ACTOR_ID,
            correlation_id=correlation_id,
            target=notification.id,
            channel=notification.destination.kind,
            destination=notification.destination.label,
            code=code,
            attempts=attempts,
            alert=notification.payload.alert_ref,
            incident=incident_id,
        )

    @staticmethod
    def _audit_skip(correlation_id: str, rule: AlertRule, decision: Decision, reason: str) -> None:
        record_audit(
            "notification.send",
            outcome="failure",
            actor_id=SERVICE_ACTOR_ID,
            correlation_id=correlation_id,
            rule_id=rule.id,
            alert=decision.fingerprint,
            reason=reason,
        )
