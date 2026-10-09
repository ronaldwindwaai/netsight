"""Configuration checks that gate a rule: an invalid rule never activates (fail closed).

The pydantic contract models guarantee the *shape* of a rule. These checks cover what shape
cannot: whether the rule can actually be evaluated on this host and whether its parts agree.
They run when a rule is created or edited, again when it is approved (the host's timezone
data may have changed since), and on every evaluation.
"""

from __future__ import annotations

from dataclasses import dataclass

from netsight_api.alerting.schedule import ScheduleError, load_zone
from netsight_api.schemas import AlertRuleDefinition


@dataclass(frozen=True)
class ConfigProblem:
    """A static code and the contract field it concerns; never free text from the rule."""

    code: str
    field: str


def check_definition(definition: AlertRuleDefinition) -> tuple[ConfigProblem, ...]:
    problems: list[ConfigProblem] = []
    if definition.schedule is not None:
        try:
            load_zone(definition.schedule.timezone)
        except ScheduleError:
            problems.append(ConfigProblem("SCHEDULE_TIMEZONE_UNKNOWN", "schedule.timezone"))
    if definition.baseline_mode != "none" and definition.condition.operator == "matches":
        # The baseline detector compares numbers; a text pattern has no baseline.
        problems.append(ConfigProblem("BASELINE_REQUIRES_NUMERIC_OPERATOR", "baseline_mode"))
    if definition.incident_policy != "none" and "create_alert" not in definition.actions:
        # Incidents are created from alerts; without the alert there is nothing to attach.
        problems.append(ConfigProblem("INCIDENT_POLICY_REQUIRES_CREATE_ALERT", "incident_policy"))
    return tuple(problems)
