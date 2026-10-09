"""Routing, escalation, rendering, settings and bounded delivery (retry/backoff, bounded queue).

Senders are fakes; the dispatcher's clock and sleep are injected, so nothing here waits or
touches the network.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from net_guard import no_network  # noqa: F401  (pytest fixture)

from netsight_api.notifications.dispatcher import (
    DeliveryAttempt,
    EscalationLevel,
    InMemoryDeliveryRecorder,
    Notification,
    NotificationDispatcher,
    RetryPolicy,
    RoutingRule,
    escalation_due,
    route,
)
from netsight_api.notifications.models import (
    EmailDestination,
    NotificationPayload,
    PushDestination,
    SendResult,
    WebhookDestination,
    build_link,
    render_email,
    render_push,
    unique_destinations,
)
from netsight_api.notifications.secret import Secret
from netsight_api.notifications.senders import FakeSender
from netsight_api.notifications.settings import NotificationSettings
from netsight_api.schemas import AlertSchedule

pytestmark = pytest.mark.usefixtures("no_network")

NOW = datetime(2026, 10, 8, 10, 0, tzinfo=UTC)
SENT = SendResult("sent", "OK")
RETRY = SendResult("retryable", "TIMEOUT")
FINAL = SendResult("permanent", "HTTP_4XX")
XSS = "<script>alert('xss')</script> \u202e \U0001f525 ${jndi:ldap://x}"


def payload(**overrides: Any) -> NotificationPayload:
    fields: dict[str, Any] = {
        "notification_id": "n-1",
        "alert_ref": "a" * 32,
        "severity": "high",
        "title": "Large upload",
        "summary": "device-1 exceeded the threshold",
        "link": "https://netsight.example.com/alerts/aaaa",
        "occurred_at": NOW,
    }
    fields.update(overrides)
    return NotificationPayload(**fields)


EMAIL = EmailDestination("ops@example.com")
PUSH = PushDestination(Secret("device-token-1"))
HOOK = WebhookDestination(Secret("https://hooks.example.com/services/s3cr3t"))


# --- payload, destinations, rendering ----------------------------------------------------------------


def test_email_subject_is_one_clean_line_even_for_a_hostile_title() -> None:
    hostile = "Disk full\r\nBcc: attacker@evil.example\r\n\r\n<b>x</b>\x00\u202e"
    rendered = render_email(payload(title=hostile[:200]))
    assert "\r" not in rendered.subject and "\n" not in rendered.subject
    assert "\x00" not in rendered.subject and "\u202e" not in rendered.subject
    assert rendered.subject.startswith("[HIGH] ")
    assert len(rendered.subject) <= 200


def test_email_is_plain_text_with_untrusted_text_left_as_text() -> None:
    rendered = render_email(payload(title=XSS, summary=XSS))
    assert "<script>" in rendered.body  # not escaped, not interpreted: plain text is not HTML
    assert "\u202e" not in rendered.body
    assert "Details (sign-in required): https://netsight.example.com/alerts/aaaa" in rendered.body


def test_push_is_bounded_plain_strings() -> None:
    rendered = render_push(payload(title="t" * 200, summary="s" * 1000))
    assert len(rendered.title) <= 80 and len(rendered.body) <= 240
    assert "\n" not in render_push(payload(title="a\nb")).title


def test_payload_rejects_oversized_or_malformed_fields() -> None:
    for bad in (
        {"title": "x" * 201},
        {"summary": "x" * 1001},
        {"notification_id": "bad id\n"},
        {"alert_ref": ""},
        {"occurred_at": datetime(2026, 10, 8, 10)},  # noqa: DTZ001 (deliberately naive)
    ):
        with pytest.raises(ValueError):
            payload(**bad)


def test_link_is_built_from_the_configured_https_base_only() -> None:
    assert (
        build_link("https://netsight.example.com/", "ab12")
        == "https://netsight.example.com/alerts/ab12"
    )
    assert (
        build_link("https://netsight.example.com", "a/b?c")
        == "https://netsight.example.com/alerts/a%2Fb%3Fc"
    )
    for base in (
        "http://netsight.example.com",
        "https://u:p@netsight.example.com",
        "javascript:1",
        "",
    ):
        with pytest.raises(ValueError):
            build_link(base, "ab12")


@pytest.mark.parametrize(
    "address",
    [
        "",
        "no-at-sign",
        "a@b",
        "a b@example.com",
        "a@example.com\r\nBcc: x@y.z",
        "a,b@example.com",
        "<a@example.com>",
    ],
)
def test_email_destination_rejects_malformed_addresses(address: str) -> None:
    with pytest.raises(ValueError, match="email"):
        EmailDestination(address)


def test_destination_labels_and_reprs_hide_the_value() -> None:
    assert "ops@example.com" not in repr(EMAIL) and "ops@example.com" not in EMAIL.label
    assert "device-token-1" not in repr(PUSH) and "device-token-1" not in PUSH.label
    assert "s3cr3t" not in repr(HOOK) and HOOK.label == "webhook:hooks.example.com"
    assert EmailDestination("OPS@example.com").label == EMAIL.label  # case-insensitive identity


def test_unique_destinations_keeps_first_occurrence_order() -> None:
    dup = EmailDestination("ops@example.com")
    assert unique_destinations([EMAIL, PUSH, dup, HOOK, PUSH]) == (EMAIL, PUSH, HOOK)


# --- routing -------------------------------------------------------------------------------------------


def test_routing_filters_by_severity_labels_and_schedule_and_dedupes() -> None:
    weekdays = AlertSchedule.model_validate(
        {
            "timezone": "UTC",
            "active": [
                {"weekdays": ["mon", "tue", "wed", "thu", "fri"], "from": "08:00", "to": "17:00"}
            ],
        }
    )
    rules = [
        RoutingRule(min_severity="high", destinations=(EMAIL,)),
        RoutingRule(min_severity="low", labels={"team": "network"}, destinations=(PUSH, EMAIL)),
        RoutingRule(min_severity="critical", destinations=(HOOK,)),
        RoutingRule(min_severity="info", labels={"team": "security"}, destinations=(HOOK,)),
        RoutingRule(min_severity="info", schedule=weekdays, destinations=(HOOK,)),
    ]
    chosen = route(rules, severity="high", labels={"team": "network", "site": "hq"}, at=NOW)
    assert chosen == (
        EMAIL,
        PUSH,
        HOOK,
    )  # rule 1, rule 2 (EMAIL deduped), schedule rule 5 (Thursday 10:00)
    off_hours = datetime(2026, 10, 10, 10, 0, tzinfo=UTC)  # Saturday
    assert route(rules, severity="high", labels={"team": "network"}, at=off_hours) == (EMAIL, PUSH)
    assert route(rules, severity="info", labels={}, at=off_hours) == ()


def test_routing_with_no_rules_or_no_match_notifies_nobody() -> None:
    assert route([], severity="critical", labels={}, at=NOW) == ()
    only_critical = [RoutingRule(min_severity="critical", destinations=(EMAIL,))]
    assert route(only_critical, severity="high", labels={}, at=NOW) == ()


def test_routing_with_an_unknown_timezone_fails_closed_to_no_destination() -> None:
    broken = AlertSchedule.model_validate(
        {
            "timezone": "Mars/Olympus",
            "active": [{"weekdays": ["thu"], "from": "00:00", "to": "00:00"}],
        }
    )
    rules = [
        RoutingRule(min_severity="info", schedule=broken, destinations=(HOOK,)),
        RoutingRule(min_severity="info", destinations=(EMAIL,)),
    ]
    assert route(rules, severity="high", labels={}, at=NOW) == (EMAIL,)


# --- escalation ----------------------------------------------------------------------------------------


LEVELS = (
    EscalationLevel(after_seconds=300, destinations=(PUSH,)),
    EscalationLevel(after_seconds=900, destinations=(HOOK,)),
)


def due(now_offset: int, **kw: Any) -> tuple[int, ...]:
    args: dict[str, Any] = {
        "fired_at": NOW,
        "now": NOW + timedelta(seconds=now_offset),
        "acknowledged_at": None,
        "resolved_at": None,
        "sent_levels": frozenset(),
    }
    args.update(kw)
    return escalation_due(LEVELS, **args)


def test_escalation_levels_become_due_in_order_and_only_once() -> None:
    assert due(299) == ()
    assert due(300) == (0,)
    assert due(899) == (0,)
    assert due(900) == (0, 1)  # catch-up when the evaluator was late
    assert due(900, sent_levels=frozenset({0})) == (1,)
    assert due(900, sent_levels=frozenset({0, 1})) == ()


def test_acknowledgement_or_resolution_stops_escalation() -> None:
    assert due(900, acknowledged_at=NOW + timedelta(seconds=100)) == ()
    assert due(900, resolved_at=NOW + timedelta(seconds=100)) == ()
    # An acknowledgement that has not happened yet at 'now' does not stop it.
    assert due(300, acknowledged_at=NOW + timedelta(seconds=400)) == (0,)
    # Acknowledged after level 0 was due: level 0 was already owed, level 1 is stopped.
    assert due(900, acknowledged_at=NOW + timedelta(seconds=600), sent_levels=frozenset({0})) == ()


def test_escalation_levels_are_validated() -> None:
    for bad in (0, -1, 7 * 24 * 3600 + 1):
        with pytest.raises(ValueError):
            EscalationLevel(after_seconds=bad, destinations=(EMAIL,))
    with pytest.raises(ValueError):
        EscalationLevel(after_seconds=60, destinations=())


# --- retry policy ----------------------------------------------------------------------------------------


def test_backoff_is_exponential_and_capped() -> None:
    policy = RetryPolicy(max_attempts=5, base_delay_seconds=1.0, factor=2.0, max_delay_seconds=5.0)
    assert [policy.delay_after(n) for n in (1, 2, 3, 4)] == [1.0, 2.0, 4.0, 5.0]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_attempts": 0},
        {"max_attempts": 6},
        {"base_delay_seconds": -1.0},
        {"factor": 0.5},
        {"factor": 5.0},
        {"max_delay_seconds": 61.0},
        {"base_delay_seconds": 10.0, "max_delay_seconds": 5.0},
    ],
)
def test_retry_policy_rejects_unbounded_or_nonsensical_values(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        RetryPolicy(**kwargs)


# --- dispatcher ------------------------------------------------------------------------------------------


class Harness:
    def __init__(self, senders: dict[str, FakeSender], **kw: Any) -> None:
        self.sleeps: list[float] = []
        self.recorder = InMemoryDeliveryRecorder(maxlen=kw.pop("maxlen", 1000))
        self.dispatcher = NotificationDispatcher(
            senders,  # type: ignore[arg-type]
            self.recorder,
            policy=kw.pop("policy", RetryPolicy(max_attempts=3, base_delay_seconds=1.0)),
            clock=lambda: NOW,
            sleep=self.sleeps.append,
            **kw,
        )


def notification(destination: Any = EMAIL, nid: str = "n-1") -> Notification:
    return Notification(id=nid, payload=payload(notification_id=nid), destination=destination)


def test_success_on_the_first_attempt_is_recorded() -> None:
    sender = FakeSender("email")
    h = Harness({"email": sender})
    outcome = h.dispatcher.deliver(notification())
    assert (outcome.status, outcome.attempts) == ("sent", 1)
    assert h.sleeps == []
    (attempt,) = h.recorder.attempts
    assert attempt == DeliveryAttempt(
        notification_id="n-1",
        alert_ref="a" * 32,
        channel="email",
        destination=EMAIL.label,
        attempt=1,
        status="sent",
        code="OK",
        at=NOW,
    )
    assert len(sender.calls) == 1


def test_retryable_failures_back_off_then_succeed() -> None:
    sender = FakeSender("email", [RETRY, RETRY, SENT])
    h = Harness({"email": sender})
    outcome = h.dispatcher.deliver(notification())
    assert (outcome.status, outcome.attempts) == ("sent", 3)
    assert h.sleeps == [1.0, 2.0]
    assert [(a.attempt, a.status, a.code) for a in h.recorder.attempts] == [
        (1, "retrying", "TIMEOUT"),
        (2, "retrying", "TIMEOUT"),
        (3, "sent", "OK"),
    ]


def test_retries_are_bounded_by_the_policy() -> None:
    sender = FakeSender("email", [RETRY] * 50)
    h = Harness({"email": sender}, policy=RetryPolicy(max_attempts=3))
    outcome = h.dispatcher.deliver(notification())
    assert (outcome.status, outcome.attempts, outcome.code) == ("failed", 3, "TIMEOUT")
    assert len(sender.calls) == 3
    assert len(h.sleeps) == 2  # no sleep after the last attempt
    assert h.recorder.attempts[-1].status == "failed"


def test_permanent_failure_is_not_retried() -> None:
    sender = FakeSender("webhook", [FINAL, SENT])
    h = Harness({"webhook": sender})
    outcome = h.dispatcher.deliver(notification(HOOK))
    assert (outcome.status, outcome.attempts, outcome.code) == ("failed", 1, "HTTP_4XX")
    assert h.sleeps == []
    assert len(sender.calls) == 1


def test_a_missing_sender_is_a_recorded_permanent_failure() -> None:
    h = Harness({})
    outcome = h.dispatcher.deliver(notification(PUSH))
    assert (outcome.status, outcome.code) == ("failed", "NO_SENDER")
    assert h.recorder.attempts[0].channel == "push"


def test_a_sender_that_raises_is_contained_and_its_message_is_never_recorded(
    caplog: pytest.LogCaptureFixture,
) -> None:
    sender = FakeSender("email", [RuntimeError("smtp password hunter2 leaked")] * 2)
    h = Harness({"email": sender}, policy=RetryPolicy(max_attempts=2))
    with caplog.at_level(logging.DEBUG):
        outcome = h.dispatcher.deliver(notification())
    assert (outcome.status, outcome.code) == ("failed", "SENDER_ERROR")
    assert "hunter2" not in repr(h.recorder.attempts) and "hunter2" not in caplog.text


def test_a_sender_returning_an_unknown_status_is_treated_as_a_permanent_failure() -> None:
    sender = FakeSender("email", [SendResult("weird", "X")])  # type: ignore[arg-type]
    h = Harness({"email": sender})
    outcome = h.dispatcher.deliver(notification())
    assert (outcome.status, outcome.code) == ("failed", "SENDER_ERROR")


def test_recorded_attempts_never_hold_the_payload_text_or_destination_value() -> None:
    h = Harness({"email": FakeSender("email")})
    h.dispatcher.deliver(
        Notification("n-1", payload(title=XSS, summary=XSS, notification_id="n-1"), EMAIL)
    )
    dump = repr(h.recorder.attempts)
    assert "script" not in dump and "ops@example.com" not in dump


def test_queue_is_bounded_and_drops_are_recorded() -> None:
    h = Harness({"email": FakeSender("email")}, queue_limit=2)
    assert h.dispatcher.submit(notification(nid="n-1")) is True
    assert h.dispatcher.submit(notification(nid="n-2")) is True
    assert h.dispatcher.submit(notification(nid="n-3")) is False
    assert h.dispatcher.pending == 2
    dropped = h.recorder.attempts[-1]
    assert (dropped.notification_id, dropped.status, dropped.code) == (
        "n-3",
        "dropped",
        "QUEUE_FULL",
    )


def test_drain_delivers_in_order_and_empties_the_queue() -> None:
    sender = FakeSender("email")
    h = Harness({"email": sender}, queue_limit=10)
    for n in range(4):
        h.dispatcher.submit(notification(nid=f"n-{n}"))
    outcomes = h.dispatcher.drain(limit=3)
    assert [o.notification_id for o in outcomes] == ["n-0", "n-1", "n-2"]
    assert h.dispatcher.pending == 1
    assert [o.notification_id for o in h.dispatcher.drain()] == ["n-3"]
    assert h.dispatcher.pending == 0
    assert [call[1].notification_id for call in sender.calls] == ["n-0", "n-1", "n-2", "n-3"]


def test_submit_works_again_once_the_queue_drains() -> None:
    h = Harness({"email": FakeSender("email")}, queue_limit=1)
    assert h.dispatcher.submit(notification(nid="n-1")) is True
    assert h.dispatcher.submit(notification(nid="n-2")) is False
    h.dispatcher.drain()
    assert h.dispatcher.submit(notification(nid="n-3")) is True


def test_the_delivery_log_is_a_bounded_ring() -> None:
    h = Harness({"email": FakeSender("email")}, maxlen=5)
    for n in range(20):
        h.dispatcher.deliver(notification(nid=f"n-{n}"))
    assert len(h.recorder.attempts) == 5
    assert h.recorder.attempts[-1].notification_id == "n-19"
    assert h.recorder.for_notification("n-0") == ()
    assert len(h.recorder.for_notification("n-19")) == 1


@pytest.mark.parametrize("bad", [0, -1, 10_001])
def test_queue_limit_is_validated(bad: int) -> None:
    with pytest.raises(ValueError):
        Harness({}, queue_limit=bad)


def test_fake_sender_records_calls_and_never_sends_anything() -> None:
    sender = FakeSender("email")
    assert sender.send(EMAIL, payload()) == SENT
    assert sender.calls == [(EMAIL.label, payload())]
    assert sender.send(HOOK, payload()) == SendResult("permanent", "DESTINATION_MISMATCH")


# --- settings --------------------------------------------------------------------------------------------


def test_settings_default_to_deny_all_webhooks() -> None:
    s = NotificationSettings.from_env({})
    assert s.webhook_allowed_hosts == frozenset()
    assert s.webhook_allowed_ports == frozenset({443})
    assert (s.webhook_timeout_seconds, s.webhook_max_response_bytes) == (5.0, 65_536)
    assert (s.max_attempts, s.queue_limit) == (3, 1000)


def test_settings_parse_the_environment() -> None:
    s = NotificationSettings.from_env(
        {
            "NETSIGHT_WEBHOOK_ALLOWED_HOSTS": " Hooks.Example.com , *.Chat.example.org ,, ",
            "NETSIGHT_WEBHOOK_ALLOWED_PORTS": "443,8443",
            "NETSIGHT_WEBHOOK_TIMEOUT_SECONDS": "10",
            "NETSIGHT_WEBHOOK_MAX_RESPONSE_BYTES": "2048",
            "NETSIGHT_NOTIFY_MAX_ATTEMPTS": "5",
            "NETSIGHT_NOTIFY_QUEUE_LIMIT": "50",
        }
    )
    assert s.webhook_allowed_hosts == frozenset({"hooks.example.com", "*.chat.example.org"})
    assert s.webhook_allowed_ports == frozenset({443, 8443})
    assert (s.webhook_timeout_seconds, s.webhook_max_response_bytes) == (10.0, 2048)
    assert (s.max_attempts, s.queue_limit) == (5, 50)


@pytest.mark.parametrize(
    "env",
    [
        {"NETSIGHT_WEBHOOK_ALLOWED_HOSTS": "https://hooks.example.com"},
        {"NETSIGHT_WEBHOOK_ALLOWED_HOSTS": "hooks.example.com:443"},
        {"NETSIGHT_WEBHOOK_ALLOWED_HOSTS": "10.0.0.1"},
        {"NETSIGHT_WEBHOOK_ALLOWED_HOSTS": "localhost"},
        {"NETSIGHT_WEBHOOK_ALLOWED_HOSTS": "*"},
        {"NETSIGHT_WEBHOOK_ALLOWED_HOSTS": "*.com"},
        {"NETSIGHT_WEBHOOK_ALLOWED_HOSTS": "a.example.com/x"},
        {"NETSIGHT_WEBHOOK_ALLOWED_PORTS": "0"},
        {"NETSIGHT_WEBHOOK_ALLOWED_PORTS": "http"},
        {"NETSIGHT_WEBHOOK_TIMEOUT_SECONDS": "0"},
        {"NETSIGHT_WEBHOOK_TIMEOUT_SECONDS": "31"},
        {"NETSIGHT_WEBHOOK_MAX_RESPONSE_BYTES": "10"},
        {"NETSIGHT_NOTIFY_MAX_ATTEMPTS": "6"},
        {"NETSIGHT_NOTIFY_QUEUE_LIMIT": "x"},
    ],
)
def test_invalid_settings_fail_start_up_instead_of_widening_access(env: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        NotificationSettings.from_env(env)
