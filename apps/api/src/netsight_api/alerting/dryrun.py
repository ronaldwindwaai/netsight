"""Read-only rule dry-run: replay supplied observations through a definition, no effects.

Nothing is read from or written to a store, nothing is sent and no incident or alert is
created. Each observation is judged at its own timestamp (the clock is the observation time),
so schedules, maintenance windows, ``for`` and cooldown are all derived from the supplied
times and the result is a pure function of the request.
"""

from __future__ import annotations

from typing import Final

from netsight_api.alerting.engine import Observation, RuleState, evaluate_definition
from netsight_api.alerting.validation import check_definition
from netsight_api.schemas_alerting import (
    AlertRuleEvaluateObservation,
    AlertRuleEvaluateProblem,
    AlertRuleEvaluateRequest,
    AlertRuleEvaluateResponse,
    AlertRuleEvaluateResult,
)

# Only feeds the (unreported) alert fingerprint of the replay.
_DRY_RUN_RULE_ID: Final = "alert-rule-00000000-0000-4000-8000-000000000000"


def _observation(item: AlertRuleEvaluateObservation) -> Observation:
    return Observation(
        at=item.at,
        entity=item.entity,
        scopes=frozenset((scope.kind, scope.ref) for scope in item.scopes),
        value=item.value,
        text=item.text,
        anomaly=item.anomaly,
        destination=item.destination,
        device_groups=frozenset(item.device_groups),
    )


def dry_run(request: AlertRuleEvaluateRequest) -> AlertRuleEvaluateResponse:
    """Fail closed: an unevaluable definition yields problems and no decisions at all."""
    problems = check_definition(request.definition)
    if problems:
        return AlertRuleEvaluateResponse(
            valid=False,
            problems=[AlertRuleEvaluateProblem(code=p.code, field=p.field) for p in problems],
            results=[],
        )
    state = RuleState()
    results: list[AlertRuleEvaluateResult] = []
    for item in request.observations:
        observation = _observation(item)
        decision, state = evaluate_definition(
            request.definition,
            rule_id=_DRY_RUN_RULE_ID,
            observation=observation,
            state=state,
            windows=request.windows,
            clock=lambda at=observation.at: at,  # type: ignore[misc]
        )
        results.append(
            AlertRuleEvaluateResult(
                at=decision.at,
                outcome=decision.outcome,
                phase=decision.phase,
                transition=decision.transition,
                notify=decision.notify,
                blocked_by=decision.blocked_by,
                maintenance_windows=list(decision.maintenance_windows),
            )
        )
    return AlertRuleEvaluateResponse(valid=True, problems=[], results=results)
