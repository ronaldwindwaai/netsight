"""Alert identity, grouping and the incident decision (anti-noise, ALERT-ENGINE.md).

* ``alert_fingerprint`` identifies one alert: the same rule firing for the same entity is one
  alert (deduplication).
* ``group_key`` identifies a family of alerts that belong in one incident: same scope and same
  labels (group-by labels).
* ``plan_incident`` is the pure decision of what the incident policy does for a new alert; the
  caller (incident wiring, a later slice) performs it.
"""

from __future__ import annotations

import hashlib
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from typing import Final, Literal

from netsight_api.schemas import AlertRuleDefinition

_SEPARATOR: Final = "\x1f"
_DIGEST_LENGTH: Final = 32
IncidentAction = Literal["none", "create", "attach"]


def _digest(*parts: str) -> str:
    material = _SEPARATOR.join(parts).encode("utf-8", "surrogatepass")
    return hashlib.sha256(material).hexdigest()[:_DIGEST_LENGTH]


def alert_fingerprint(rule_id: str, entity: str) -> str:
    """Stable per (rule, monitored entity); the separator stops boundary shifting forgeries."""
    return _digest("alert", rule_id, entity)


def group_key(definition: AlertRuleDefinition) -> str:
    """Stable per scope and label set, independent of label order."""
    labels = [f"{key}={value}" for key, value in sorted(definition.labels.items())]
    return _digest("group", definition.scope.kind, definition.scope.ref, *labels)


@dataclass(frozen=True)
class IncidentPlan:
    action: IncidentAction
    group_key: str | None


def plan_incident(
    definition: AlertRuleDefinition,
    *,
    fingerprint: str,
    open_group_keys: AbstractSet[str],
    open_fingerprints: AbstractSet[str],
) -> IncidentPlan:
    """What the rule's incident policy does for a newly firing alert.

    ``none``: nothing. ``create``: one incident per alert, never merged, and nothing when this
    alert already has one. ``group``: attach to the open incident for the group when there is
    one, otherwise open a new incident for the group.
    """
    if definition.incident_policy == "none" or fingerprint in open_fingerprints:
        return IncidentPlan("none", None)
    if definition.incident_policy == "create":
        return IncidentPlan("create", None)
    key = group_key(definition)
    return IncidentPlan("attach" if key in open_group_keys else "create", key)
