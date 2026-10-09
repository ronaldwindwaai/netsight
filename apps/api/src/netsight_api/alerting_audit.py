"""Audit details for monitoring-configuration changes (S6-3 security review H1 and M6).

Two concerns, kept out of the route modules so they stay small and share one vocabulary:

* **Silencing events.** Disabling a rule and creating or cancelling a maintenance window all
  change what gets alerted on. Their audit records carry ``silencing`` (``rule-disable``,
  ``window-create``, ``window-cancel``), the scope kind, the evaluation mode and a coarse
  duration bucket, so a log alert can single them out (for example "disable-mode window on an
  organisation scope", or "more than N silencing events per actor and hour").
* **Attribution.** An edit, approval or disable records the canonical SHA-256 of the definition
  it concerned, the actor and the rule creator as distinct fields. The rule table has no
  ``updated_by`` column (a follow-up), so this audit trail is the only record of who edited.
  Free text (the rule name, window reason) never appears; only the hash of the whole
  definition does.
"""

from __future__ import annotations

import hashlib
import json
from typing import Final, Literal

from netsight_api.alerting.engine import definition_of
from netsight_api.audit import bounded_identifier
from netsight_api.schemas import (
    AlertRule,
    AlertRuleDefinition,
    MaintenanceEvaluation,
    MaintenanceWindowDefinition,
)

SilencingEvent = Literal["rule-disable", "window-create", "window-cancel"]
INDEFINITE: Final = "indefinite"
_HOUR: Final = 3600
_BUCKETS: Final = ((_HOUR, "lte_1h"), (24 * _HOUR, "lte_24h"), (7 * 24 * _HOUR, "lte_7d"))
LONGEST_BUCKET: Final = "gt_7d"


def duration_bucket(seconds: int) -> str:
    for upper, label in _BUCKETS:
        if seconds <= upper:
            return label
    return LONGEST_BUCKET


def window_silencing_details(
    event: SilencingEvent, window: MaintenanceWindowDefinition
) -> dict[str, object]:
    seconds = int((window.ends_at - window.starts_at).total_seconds())
    return {
        "silencing": event,
        "scope_kind": window.scope.kind,
        "evaluation": window.evaluation,
        "duration_bucket": duration_bucket(seconds),
    }


def rule_disable_details(rule: AlertRule) -> dict[str, object]:
    """A disabled rule stops evaluating until someone re-approves it: an open-ended silence."""
    evaluation: MaintenanceEvaluation = "disable"
    return {
        "silencing": "rule-disable",
        "scope_kind": rule.scope.kind,
        "evaluation": evaluation,
        "duration_bucket": INDEFINITE,
    }


def definition_sha256(definition: AlertRuleDefinition) -> str:
    """SHA-256 of the canonical JSON of the definition (sorted keys, no whitespace, ASCII)."""
    canonical = json.dumps(
        definition.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def attribution_details(rule: AlertRule, *, actor_id: str) -> dict[str, object]:
    """The acting identity next to the rule creator, plus the hash of the stored definition."""
    return {
        "definition_sha256": definition_sha256(definition_of(rule)),
        "created_by": bounded_identifier(rule.created_by),
        "updated_by": bounded_identifier(actor_id),
    }
