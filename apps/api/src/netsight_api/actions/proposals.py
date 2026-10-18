"""Turning a request body or a Step 8 finding into a ``NewAction`` (Step 12).

Everything here is a refusal or a ``NewAction`` built from the catalogue: the action type must be
allow-listed, the parameters typed and in range, the target of the right kind. Refusals carry a static
code (never the offending value). The checks are recorded on the request, including the one nobody can
make yet: that the target exists. That check is ``unknown``, not ``pass``.

A quarantine proposal from a finding becomes a request that is *still only a proposal*: it enters
``pending-approval`` and nothing executes it until it is approved, step-up proven and run through an
executor (today only the dry-run executor). The endpoint's MAC, address and name are not copied into
the action store; the target is the finding's opaque id.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Final

from netsight_api.actions.catalog import (
    ParamError,
    TargetError,
    get_definition,
    validate_params,
    validate_target,
)
from netsight_api.actions.model import NewAction
from netsight_api.schemas_actions import (
    ActionActor,
    ActionCheck,
    ActionSource,
    ParamValue,
)
from netsight_api.schemas_unknown_devices import FINAL_STATES, UnknownDeviceFinding

# Not an invention of the engine's policy: the operator's severity policy only recommends a
# quarantine; how long it lasts is a parameter a person confirms. This is the pre-filled value.
DEFAULT_ISOLATION_MINUTES: Final = 60


class ProposalError(ValueError):
    """A proposal cannot be made. ``code`` is static and safe to return, log and audit."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _checks(approvals: int) -> tuple[ActionCheck, ...]:
    return (
        ActionCheck(name="catalogue", state="pass", detail="ok"),
        ActionCheck(name="parameters", state="pass", detail="ok"),
        ActionCheck(name="target-shape", state="pass", detail="ok"),
        # Nothing consults the inventory here: say so rather than imply the target was found.
        ActionCheck(name="target-exists", state="unknown", detail="not-verified"),
        ActionCheck(name="approval-policy", state="pass", detail=f"approvals-{approvals}"),
    )


def propose(
    *,
    actor: ActionActor,
    action_type: str,
    target_id: str,
    params: Mapping[str, object],
    reason: str,
    source: ActionSource | None,
    now: datetime,
) -> NewAction:
    definition = get_definition(action_type)
    if definition is None:
        raise ProposalError("action-not-allowed")
    try:
        checked = validate_params(definition, params)
        validate_target(definition, target_id)
    except (ParamError, TargetError) as exc:
        raise ProposalError(str(exc)) from None
    typed: dict[str, ParamValue] = dict(checked)
    return NewAction(
        id=f"action-{uuid.uuid4()}",
        action_type=definition.action_type,
        target_id=target_id,
        params=typed,
        risk=definition.risk,
        requester=actor,
        reason=reason,
        source=source,
        approvals_required=definition.approvals_required,
        policy_checks=_checks(definition.approvals_required),
        created_at=now,
        approve_by=now + timedelta(seconds=definition.approve_within_seconds),
        execute_within_seconds=definition.execute_within_seconds,
        timeout_seconds=definition.timeout_seconds,
    )


def propose_from_finding(
    *,
    actor: ActionActor,
    finding: UnknownDeviceFinding,
    expected_evidence_version: int,
    reason: str,
    now: datetime,
) -> NewAction:
    if finding.proposed_action is None:
        raise ProposalError("no-proposal")
    if finding.state in FINAL_STATES:
        raise ProposalError("finding-closed")
    if finding.evidence_version != expected_evidence_version:
        raise ProposalError("stale-evidence")
    return propose(
        actor=actor,
        action_type=finding.proposed_action.action_type,
        target_id=finding.id,
        params={"duration_minutes": DEFAULT_ISOLATION_MINUTES},
        reason=reason,
        source=ActionSource(
            kind="unknown-device-finding", id=finding.id, evidence_version=finding.evidence_version
        ),
        now=now,
    )
