"""Engine output -> incident store (ALERT-ENGINE.md anti-noise, PRD 14/17).

``AlertIncidentService.ensure`` performs the pure ``plan_incident`` decision against the store:
a firing alert gets exactly one deduplicated incident per grouping key, with an appended
``alert-linked`` timeline event, written by the *service principal* ``SERVICE_IDENTITY`` (never a
human). What it deliberately cannot do is as important as what it can:

* it never acknowledges, assigns, resolves, reopens or closes anything: resolution records a
  human judgement and stays human-only (``rbac.HUMAN_ONLY_PERMISSIONS``), so a recovered alert
  leaves its incident open for an operator;
* it never edits a rule, a window or an existing incident's content.

Idempotence rests on ``alert_incident_links``. A key (alert fingerprint, or group key for policy
``group``) points at the incident that carries it; the incident counts as open until a human
resolves it. The link is claimed by compare-and-set *before* the timeline note is written, so a
crash in between leaves a note-less incident that is still linked (never a duplicate on the next
cycle). Inside one process a lock makes the read-decide-write sequence atomic. Two evaluators on
one database can still race: the loser's claim fails, it attaches to the winner and leaves a
comment on the surplus incident (nothing is ever deleted). Run a single evaluator.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from threading import Lock
from typing import Final, Literal, Protocol

from netsight_api.alerting.engine import Decision, definition_of
from netsight_api.alerting.grouping import plan_incident
from netsight_api.audit import record_audit
from netsight_api.notifications.models import sanitize_line
from netsight_api.rbac import Identity, PrincipalKind
from netsight_api.schemas import AlertRule, Incident, IncidentSeverity, IncidentTimelineEvent
from netsight_api.storage import AlertIncidentLinkRepository, LinkKind

_LOGGER: Final = logging.getLogger("netsight_api.evaluation")
SERVICE_ACTOR_ID: Final = "service:alert-evaluator"
# Not human, no roles: it holds no permission at all, and the human-only ones are denied twice.
SERVICE_IDENTITY: Final = Identity(
    id=SERVICE_ACTOR_ID, roles=frozenset(), principal=PrincipalKind.SERVICE
)
MAX_TITLE_LENGTH: Final = 255
MAX_NOTE_LENGTH: Final = 1000
_CLOSED_STATES: Final = frozenset({"resolved", "closed"})
_SEVERITY: Final[dict[str, IncidentSeverity]] = {
    "info": "low",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}

EffectAction = Literal["none", "created", "attached"]


@dataclass(frozen=True)
class IncidentEffect:
    """What ``ensure`` did; ``incident_id`` is the incident now carrying the alert, if any."""

    action: EffectAction
    incident_id: str | None


class EvaluatorIncidents(Protocol):
    """The only incident-store operations the evaluator may use: it can open an incident, add a
    timeline note and read one back. Nothing that acknowledges, assigns, resolves or edits."""

    def create_incident(
        self, *, title: str, severity: IncidentSeverity, actor_id: str
    ) -> Incident: ...

    def append_event(
        self,
        incident_id: str,
        *,
        kind: Literal["alert-linked", "comment"],
        actor_id: str,
        message: str | None = None,
        subject_id: str | None = None,
    ) -> IncidentTimelineEvent: ...

    def get_incident(self, incident_id: str) -> Incident | None: ...


class AlertIncidentService:
    def __init__(self, incidents: EvaluatorIncidents, links: AlertIncidentLinkRepository) -> None:
        self._incidents = incidents
        self._links = links
        self._lock = Lock()

    def ensure(
        self, *, rule: AlertRule, decision: Decision, entity: str, correlation_id: str
    ) -> IncidentEffect:
        """Make sure the firing alert has an incident; raises on a store failure (audited)."""
        definition = definition_of(rule)
        if definition.incident_policy == "none":
            return IncidentEffect("none", None)
        with self._lock:
            try:
                return self._ensure(
                    rule, definition.incident_policy, decision, entity, correlation_id
                )
            except Exception as error:
                record_audit(
                    "incident.auto_create",
                    outcome="failure",
                    actor_id=SERVICE_ACTOR_ID,
                    correlation_id=correlation_id,
                    rule_id=rule.id,
                    policy=definition.incident_policy,
                    reason=type(error).__name__,
                )
                raise

    def note_recovery(self, *, rule: AlertRule, decision: Decision) -> None:
        """Record that the alert was seen to recover (raises on a store failure; retry it)."""
        if definition_of(rule).incident_policy == "none":
            return
        with self._lock:
            self._links.mark_recovered("alert", decision.fingerprint)

    # -- internals ---------------------------------------------------------------------------

    def _open(self, incident_id: str | None) -> str | None:
        """The id when that incident exists and no human has resolved it yet, else None."""
        if incident_id is None:
            return None
        incident = self._incidents.get_incident(incident_id)
        if incident is None or incident.state in _CLOSED_STATES:
            return None
        return incident.id

    def _ensure(
        self, rule: AlertRule, policy: str, decision: Decision, entity: str, correlation_id: str
    ) -> IncidentEffect:
        fingerprint, group = decision.fingerprint, decision.group_key
        alert_link = self._links.get("alert", fingerprint)
        alert_open = self._open(alert_link)
        if alert_link is not None and alert_open is None:
            if not self._links.is_recovered("alert", fingerprint):
                return IncidentEffect("none", alert_link)  # resolved, but still firing: no new one
        elif alert_open is not None and self._links.is_recovered("alert", fingerprint):
            self._links.claim("alert", fingerprint, incident_id=alert_open, replacing=alert_open)
        group_link = self._links.get("group", group) if policy == "group" else None
        group_open = self._open(group_link)
        plan = plan_incident(
            definition_of(rule),
            fingerprint=fingerprint,
            open_group_keys={group} if group_open else set(),
            open_fingerprints={fingerprint} if alert_open else set(),
        )
        if plan.action == "none":
            return IncidentEffect("none", alert_open)
        if plan.action == "attach" and group_open is not None:
            return self._attach(rule, group_open, alert_link, fingerprint, entity, correlation_id)
        return self._create(rule, policy, decision, entity, correlation_id, alert_link, group_link)

    def _attach(
        self,
        rule: AlertRule,
        incident_id: str,
        alert_link: str | None,
        fingerprint: str,
        entity: str,
        correlation_id: str,
    ) -> IncidentEffect:
        if not self._links.claim(
            "alert", fingerprint, incident_id=incident_id, replacing=alert_link
        ):
            return self._alert_claim_lost(incident_id, fingerprint, rule, correlation_id)
        self._note(incident_id, rule, fingerprint, entity)
        record_audit(
            "incident.auto_attach",
            outcome="success",
            actor_id=SERVICE_ACTOR_ID,
            correlation_id=correlation_id,
            target=incident_id,
            rule_id=rule.id,
            policy="group",
            alert=fingerprint,
        )
        return IncidentEffect("attached", incident_id)

    def _create(
        self,
        rule: AlertRule,
        policy: str,
        decision: Decision,
        entity: str,
        correlation_id: str,
        alert_link: str | None,
        group_link: str | None,
    ) -> IncidentEffect:
        fingerprint = decision.fingerprint
        incident = self._incidents.create_incident(
            title=_title(rule, entity),
            severity=_SEVERITY[rule.severity],
            actor_id=SERVICE_ACTOR_ID,
        )
        key_kind: LinkKind = "group" if policy == "group" else "alert"
        key = decision.group_key if policy == "group" else fingerprint
        replacing = group_link if policy == "group" else alert_link
        if not self._links.claim(key_kind, key, incident_id=incident.id, replacing=replacing):
            return self._yield_to_winner(incident.id, key_kind, key, rule, correlation_id)
        if policy == "group" and not self._links.claim(
            "alert", fingerprint, incident_id=incident.id, replacing=alert_link
        ):
            self._audit_claim_lost(incident.id, rule, correlation_id)
        self._note(incident.id, rule, fingerprint, entity)
        record_audit(
            "incident.auto_create",
            outcome="success",
            actor_id=SERVICE_ACTOR_ID,
            correlation_id=correlation_id,
            target=incident.id,
            rule_id=rule.id,
            policy=policy,
            alert=fingerprint,
        )
        return IncidentEffect("created", incident.id)

    def _yield_to_winner(
        self,
        surplus_id: str,
        kind: LinkKind,
        key: str,
        rule: AlertRule,
        correlation_id: str,
    ) -> IncidentEffect:
        """Another evaluator linked this key first: mark our surplus incident, join the winner."""
        winner = self._open(self._links.get(kind, key))
        self._audit_claim_lost(surplus_id, rule, correlation_id)
        reference = winner or "another incident"
        self._safe_append(
            surplus_id, "comment", f"Superseded: this alert is carried by {reference}.", None
        )
        if winner is None:
            return IncidentEffect("none", None)
        record_audit(
            "incident.auto_attach",
            outcome="success",
            actor_id=SERVICE_ACTOR_ID,
            correlation_id=correlation_id,
            target=winner,
            rule_id=rule.id,
            policy="race",
        )
        return IncidentEffect("attached", winner)

    def _alert_claim_lost(
        self, incident_id: str, fingerprint: str, rule: AlertRule, correlation_id: str
    ) -> IncidentEffect:
        """The alert key moved under us: report who carries it now; write nothing for the loser."""
        self._audit_claim_lost(incident_id, rule, correlation_id)
        return IncidentEffect("none", self._open(self._links.get("alert", fingerprint)))

    @staticmethod
    def _audit_claim_lost(incident_id: str, rule: AlertRule, correlation_id: str) -> None:
        record_audit(
            "incident.auto_create",
            outcome="failure",
            actor_id=SERVICE_ACTOR_ID,
            correlation_id=correlation_id,
            target=incident_id,
            rule_id=rule.id,
            reason="CLAIM_LOST",
        )

    def _note(self, incident_id: str, rule: AlertRule, fingerprint: str, entity: str) -> None:
        message = sanitize_line(
            f"Alert rule '{rule.name}' ({rule.severity}) fired for {entity}.", MAX_NOTE_LENGTH
        )
        self._safe_append(incident_id, "alert-linked", message, fingerprint)

    def _safe_append(
        self,
        incident_id: str,
        kind: Literal["alert-linked", "comment"],
        message: str,
        subject: str | None,
    ) -> None:
        """A failed note is logged, not raised: the link already exists, so retrying the whole
        sequence would not duplicate the incident and the incident itself is the record."""
        try:
            self._incidents.append_event(
                incident_id,
                kind=kind,
                actor_id=SERVICE_ACTOR_ID,
                message=message,
                subject_id=subject,
            )
        except Exception as error:  # noqa: BLE001 - see docstring
            _LOGGER.warning(
                "incident timeline note was not written", extra={"error_type": type(error).__name__}
            )


def _title(rule: AlertRule, entity: str) -> str:
    title = sanitize_line(f"{rule.name}: {entity}", MAX_TITLE_LENGTH)
    return title or "Alert"
