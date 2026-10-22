"""Engine -> notification routing -> dispatcher (S6 step 2). Routes never send; the evaluation
service does, through the dispatcher, with every outcome audited and recorded."""

from __future__ import annotations

import json
import logging
from datetime import timedelta
from typing import Any

import pytest
from evaluation_support import DEVICE_A, T0, Stack, decision_for

from netsight_api.evaluation.notify import AlertNotifier
from netsight_api.notifications.dispatcher import (
    DeliveryAttempt,
    InMemoryDeliveryRecorder,
    NotificationDispatcher,
    RetryPolicy,
    RoutingRule,
)
from netsight_api.notifications.models import (
    EmailDestination,
    PushDestination,
    SendResult,
    WebhookDestination,
)
from netsight_api.notifications.routing_config import routing_rules_from_env
from netsight_api.notifications.secret import Secret
from netsight_api.notifications.senders import FakeSender

BASE = "https://netsight.example.com"
INCIDENT = "incident-00000000-0000-4000-8000-0000000000aa"
EMAIL = EmailDestination("ops@example.com")
PUSH = PushDestination(Secret("device-ref-do-not-leak"))
HOOK = WebhookDestination(Secret("https://hooks.example.com/s3cr3t"))
BIDI = chr(0x202E)


class Harness:
    def __init__(self, *, rules: tuple[RoutingRule, ...] | None = None, **dispatcher: Any) -> None:
        self.stack = Stack.build()
        self.email = FakeSender("email", dispatcher.pop("email_script", ()))
        self.push = FakeSender("push", dispatcher.pop("push_script", ()))
        self.recorder = InMemoryDeliveryRecorder()
        base_url = dispatcher.pop("public_base_url", BASE)
        senders: dict[Any, Any] = {"email": self.email, "push": self.push}
        self.dispatcher = NotificationDispatcher(
            senders,
            self.recorder,
            clock=lambda: T0,
            sleep=lambda seconds: None,
            policy=RetryPolicy(max_attempts=2),
            public_base_url=base_url,
            **dispatcher,
        )
        self.notifier = AlertNotifier(
            self.dispatcher,
            rules if rules is not None else (RoutingRule("high", (EMAIL, PUSH)),),
            self.recorder,
            public_base_url=base_url,
        )

    def notify(self, **rule_overrides: Any) -> Any:
        rule = self.last_rule = self.stack.active_rule(**rule_overrides)
        return self.notifier.notify(
            rule=rule,
            decision=decision_for(rule, DEVICE_A),
            entity=DEVICE_A,
            incident_id=INCIDENT,
            correlation_id="cycle-1",
        )


def audit_records(caplog: pytest.LogCaptureFixture) -> list[dict[str, Any]]:
    return [json.loads(r.getMessage()) for r in caplog.records if r.name == "netsight_api.audit"]


# --- routing configuration -----------------------------------------------------------------------


def test_unset_routing_configuration_routes_nowhere() -> None:
    assert routing_rules_from_env({}) == ()


def test_email_and_push_destinations_come_from_the_environment() -> None:
    rules = routing_rules_from_env(
        {
            "NETSIGHT_NOTIFY_EMAIL_TO": "ops@example.com, Oncall@Example.com ,ops@example.com",
            "NETSIGHT_NOTIFY_PUSH_DEVICES": "tok-1,tok-2",
            "NETSIGHT_NOTIFY_MIN_SEVERITY": "medium",
        }
    )
    assert all(rule.min_severity == "medium" for rule in rules)
    kinds = [d.kind for rule in rules for d in rule.destinations]
    assert kinds == ["email", "email", "push", "push"]  # the duplicate address is dropped


def test_minimum_severity_defaults_to_high() -> None:
    (rule,) = routing_rules_from_env({"NETSIGHT_NOTIFY_EMAIL_TO": "ops@example.com"})
    assert rule.min_severity == "high"


@pytest.mark.parametrize(
    "env",
    [
        {"NETSIGHT_NOTIFY_EMAIL_TO": "not-an-address"},
        {"NETSIGHT_NOTIFY_EMAIL_TO": "a@example.com\r\nBcc: x@y.z"},
        {"NETSIGHT_NOTIFY_PUSH_DEVICES": "tok\r\nX: 1"},
        {"NETSIGHT_NOTIFY_PUSH_DEVICES": "t" * 513},
        {"NETSIGHT_NOTIFY_MIN_SEVERITY": "urgent"},
        {"NETSIGHT_NOTIFY_EMAIL_TO": ",".join(f"u{i}@example.com" for i in range(51))},
    ],
)
def test_invalid_routing_configuration_fails_start_up_without_echoing_values(
    env: dict[str, str],
) -> None:
    with pytest.raises(ValueError) as raised:
        routing_rules_from_env(env)
    text = str(raised.value)
    assert "x@y.z" not in text and "not-an-address" not in text and "tok" not in text


def test_routing_config_repr_hides_push_device_references() -> None:
    rules = routing_rules_from_env({"NETSIGHT_NOTIFY_PUSH_DEVICES": "tok-secret-1"})
    assert "tok-secret-1" not in repr(rules)


# --- selection ---------------------------------------------------------------------------------------


def test_only_channels_named_in_the_rule_actions_are_used() -> None:
    both = Harness()
    result = both.notify(actions=["create_alert", "email", "push"])
    assert (result.sent, result.failed, result.skipped) == (2, 0, None)
    assert len(both.email.calls) == 1 and len(both.push.calls) == 1

    email_only = Harness()
    email_only.notify(actions=["create_alert", "email"])
    assert len(email_only.email.calls) == 1 and email_only.push.calls == []

    none = Harness()
    result = none.notify(actions=["create_alert"], incident_policy="none")
    assert (result.sent, result.skipped) == (0, "no-destination")
    assert none.email.calls == [] and none.push.calls == []


def test_severity_threshold_and_missing_routing_send_nothing() -> None:
    low = Harness()
    assert low.notify(severity="medium").skipped == "no-destination"
    assert low.email.calls == []
    nobody = Harness(rules=())
    assert nobody.notify().skipped == "no-destination"


def test_a_webhook_in_the_routing_table_is_unreachable_from_rule_actions() -> None:
    h = Harness(rules=(RoutingRule("high", (HOOK, EMAIL)),))
    result = h.notify(actions=["create_alert", "email", "push"])
    assert (result.sent, result.skipped) == (1, None)  # only the email destination matched


def test_label_routing_applies_to_the_rule_labels() -> None:
    rules = (RoutingRule("high", (EMAIL,), labels={"team": "security"}),)
    h = Harness(rules=rules)
    assert h.notify(labels={"team": "network"}).skipped == "no-destination"
    assert Harness(rules=rules).notify(labels={"team": "security"}).sent == 1


# --- payload ---------------------------------------------------------------------------------------


def test_payload_links_to_the_incident_and_carries_no_telemetry() -> None:
    h = Harness()
    h.notify()
    (_, payload) = h.email.calls[0]
    assert payload.link == f"{BASE}/incidents/{INCIDENT}"
    assert payload.incident_id == INCIDENT and payload.severity == "high"
    assert payload.alert_ref == decision_for(h.last_rule, DEVICE_A).fingerprint
    assert payload.title == "Device down" and DEVICE_A in payload.summary
    assert payload.occurred_at == T0


def test_without_an_incident_the_link_falls_back_to_the_alert_view() -> None:
    h = Harness()
    rule = h.stack.active_rule(incident_policy="none")
    decision = decision_for(rule, DEVICE_A)
    h.notifier.notify(
        rule=rule, decision=decision, entity=DEVICE_A, incident_id=None, correlation_id="c"
    )
    (_, payload) = h.email.calls[0]
    assert payload.link == f"{BASE}/alerts/{decision.fingerprint}"
    assert payload.incident_id is None


def test_hostile_rule_names_are_sanitised_and_bounded_in_the_payload() -> None:
    h = Harness()
    hostile = "Down\r\nBcc: x@y.z" + BIDI + "<script>1</script>" + "A" * 300
    h.notify(name=hostile[:255])
    (_, payload) = h.email.calls[0]
    assert len(payload.title) <= 200
    assert not any(ch in payload.title + payload.summary for ch in "\r\n" + BIDI)
    assert "<script>" in payload.title  # inert text; renderers never interpret it


def test_no_public_base_url_means_nothing_is_sent_and_it_is_said_so(
    caplog: pytest.LogCaptureFixture,
) -> None:
    h = Harness(public_base_url=None)
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        result = h.notify()
    assert (result.sent, result.skipped) == (0, "no-public-url")
    assert h.email.calls == [] and h.push.calls == []
    (record,) = audit_records(caplog)
    assert (record["action"], record["outcome"], record["reason"]) == (
        "notification.send",
        "failure",
        "no-public-url",
    )


# --- durable cooldown (restart safety) ---------------------------------------------------------------


def test_a_recent_durable_send_for_the_alert_suppresses_a_repeat_after_a_restart() -> None:
    h = Harness()
    rule = h.stack.active_rule(cooldown_seconds=3600)
    decision = decision_for(rule, DEVICE_A)
    h.recorder.record(
        DeliveryAttempt(
            "n-old",
            decision.fingerprint,
            "email",
            "email:x",
            1,
            "sent",
            "OK",
            T0 - timedelta(minutes=10),
        )
    )
    result = h.notifier.notify(
        rule=rule, decision=decision, entity=DEVICE_A, incident_id=INCIDENT, correlation_id="c"
    )
    assert (result.sent, result.skipped) == (0, "cooldown") and h.email.calls == []
    later = decision_for(rule, DEVICE_A, at=T0 + timedelta(hours=2))
    again = h.notifier.notify(
        rule=rule, decision=later, entity=DEVICE_A, incident_id=INCIDENT, correlation_id="c"
    )
    assert again.sent == 1


def test_a_decision_that_is_not_due_sends_nothing() -> None:
    h = Harness()
    rule = h.stack.active_rule()
    result = h.notifier.notify(
        rule=rule,
        decision=decision_for(rule, DEVICE_A, notify=False),
        entity=DEVICE_A,
        incident_id=INCIDENT,
        correlation_id="c",
    )
    assert (result.sent, result.skipped) == (0, "not-due") and h.email.calls == []


# --- outcomes, audit, bounds ------------------------------------------------------------------------


def test_every_send_is_audited_without_addresses_or_payload_text(
    caplog: pytest.LogCaptureFixture,
) -> None:
    h = Harness(email_script=[SendResult("permanent", "SMTP_5XX")])
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        result = h.notify(name="Very secret title", actions=["create_alert", "email", "push"])
    assert (result.sent, result.failed) == (1, 1)
    records = audit_records(caplog)
    assert [(r["action"], r["outcome"]) for r in records] == [
        ("notification.send", "failure"),
        ("notification.send", "success"),
    ]
    failure = records[0]
    assert failure["channel"] == "email" and failure["code"] == "SMTP_5XX"
    assert failure["attempts"] == 1 and failure["actor_id"] == "service:alert-evaluator"
    assert failure["target"].startswith("n-") and failure["incident"] == INCIDENT
    for text in (caplog.text,):
        assert "ops@example.com" not in text and "device-ref-do-not-leak" not in text
        assert "Very secret title" not in text


def test_retryable_failures_are_retried_by_the_dispatcher_and_recorded() -> None:
    h = Harness(email_script=[SendResult("retryable", "TIMEOUT"), SendResult("sent", "OK")])
    h.notify(actions=["create_alert", "email"])
    statuses = [(a.channel, a.attempt, a.status) for a in h.recorder.attempts]
    assert statuses == [("email", 1, "retrying"), ("email", 2, "sent")]


def test_a_full_queue_drops_and_records_instead_of_buffering_without_bound(
    caplog: pytest.LogCaptureFixture,
) -> None:
    h = Harness(queue_limit=1)
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        result = h.notify(actions=["create_alert", "email", "push"])
    assert (result.sent, result.failed) == (1, 1)
    assert any(a.status == "dropped" and a.code == "QUEUE_FULL" for a in h.recorder.attempts)
    assert {r["code"] for r in audit_records(caplog)} == {"OK", "QUEUE_FULL"}


def test_a_dispatcher_crash_is_contained_and_reported_as_a_failure() -> None:
    class Exploding:
        def submit(self, notification: Any) -> bool:
            raise RuntimeError("queue corrupted")

        def drain(self, limit: int | None = None) -> tuple[Any, ...]:
            return ()

    h = Harness()
    notifier = AlertNotifier(
        Exploding(), (RoutingRule("high", (EMAIL,)),), h.recorder, public_base_url=BASE
    )  # type: ignore[arg-type]
    rule = h.stack.active_rule()
    result = notifier.notify(
        rule=rule,
        decision=decision_for(rule, DEVICE_A),
        entity=DEVICE_A,
        incident_id=None,
        correlation_id="c",
    )
    assert (result.sent, result.failed) == (0, 1)
