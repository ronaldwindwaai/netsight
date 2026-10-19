"""The allow-list of controlled action types (Step 12).

There is **no generic execution**: an action is one of the entries below, with parameters that are
typed and bounded (an integer in a range, a boolean or a value from a fixed list), a target that must
match the pattern of its target kind, and a plan written here, not taken from a request. Nothing a
caller sends is ever interpolated into a command, because there is no command: an executor receives a
definition, a validated target and validated parameters.

Refusals raise ``ParamError`` / ``TargetError`` carrying a static code, never the offending value.

The catalogue is the first three of the types listed in ``docs/12-implementation/ACTION-ENGINE.md``.
``service.restart`` and ``firewall.destination.block`` are deliberately absent: the design says not to
build them until a lab proves restricted execution.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, Literal

from netsight_api.schemas_actions import (
    MAX_STEPS,
    ActionDefinition,
    ActionParamSpec,
    ActionType,
    ParamKind,
    Risk,
)

PROPOSE: Final = "actions:propose"
PROPOSE_HIGH: Final = "actions:propose-high"
_UUID: Final = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_MAX_STEP: Final = 200


class ParamError(ValueError):
    """A parameter is not acceptable. The message is a static code, never the value."""


class TargetError(ValueError):
    """The target is not acceptable for this action type. The message is a static code."""


@dataclass(frozen=True)
class ParamDef:
    name: str
    kind: ParamKind
    required: bool = True
    minimum: int | None = None
    maximum: int | None = None
    choices: tuple[str, ...] | None = None


@dataclass(frozen=True)
class ActionDef:
    action_type: ActionType
    title: str
    risk: Risk
    target_kind: str
    target_pattern: re.Pattern[str]
    params: tuple[ParamDef, ...]
    approvals_required: int
    approve_within_seconds: int
    execute_within_seconds: int
    timeout_seconds: int
    propose_permission: Literal["actions:propose", "actions:propose-high"]
    rollback_guidance: str
    plan: tuple[
        str, ...
    ]  # fixed wording; only {target} and {<param>} are filled, from validated values


CATALOG: Final[Mapping[str, ActionDef]] = {
    "endpoint.isolate": ActionDef(
        action_type="endpoint.isolate",
        title="Isolate endpoint",
        risk="C",
        target_kind="endpoint",
        target_pattern=re.compile(rf"unknown-device-{_UUID}|endpoint:[a-z0-9][a-z0-9._-]{{0,99}}"),
        params=(ParamDef("duration_minutes", "integer", minimum=5, maximum=1440),),
        approvals_required=1,
        approve_within_seconds=86_400,
        execute_within_seconds=3_600,
        timeout_seconds=30,
        propose_permission=PROPOSE_HIGH,
        rollback_guidance=(
            "Return the endpoint to the network segment it was in before isolation; the previous "
            "segment is recorded by the executor before it changes anything."
        ),
        plan=(
            "Resolve the endpoint named by {target} and confirm it is still the one proposed",
            "Would move the endpoint to the isolation segment for {duration_minutes} minutes",
            "Would verify the endpoint is reachable only from the isolation segment",
        ),
    ),
    "switch.port.disable": ActionDef(
        action_type="switch.port.disable",
        title="Disable switch port",
        risk="D",
        target_kind="interface",
        target_pattern=re.compile(r"interface:[a-z0-9][a-z0-9._-]{0,99}"),
        params=(),
        approvals_required=2,
        approve_within_seconds=86_400,
        execute_within_seconds=3_600,
        timeout_seconds=30,
        propose_permission=PROPOSE_HIGH,
        rollback_guidance="Re-enable the port with switch.port.enable once the cause is resolved.",
        plan=(
            "Resolve the interface named by {target} and record its administrative state",
            "Would set the port administratively down",
            "Would verify the port reports administratively down",
        ),
    ),
    "switch.port.enable": ActionDef(
        action_type="switch.port.enable",
        title="Enable switch port",
        risk="B",
        target_kind="interface",
        target_pattern=re.compile(r"interface:[a-z0-9][a-z0-9._-]{0,99}"),
        params=(),
        approvals_required=1,
        approve_within_seconds=86_400,
        execute_within_seconds=3_600,
        timeout_seconds=30,
        propose_permission=PROPOSE,
        rollback_guidance="Disable the port again with switch.port.disable if it should stay down.",
        plan=(
            "Resolve the interface named by {target} and record its administrative state",
            "Would set the port administratively up",
            "Would verify the port reports administratively up",
        ),
    ),
}


def get_definition(action_type: str) -> ActionDef | None:
    """The definition for an allow-listed type, else ``None`` (deny by default)."""
    return CATALOG.get(action_type) if isinstance(action_type, str) else None


def validate_target(definition: ActionDef, target_id: str) -> None:
    if not isinstance(target_id, str) or not definition.target_pattern.fullmatch(target_id):
        raise TargetError("target-not-allowed")


def _check_integer(param: ParamDef, value: object) -> int:
    # bool is a subclass of int: refuse it explicitly so True never becomes 1.
    if type(value) is not int:
        raise ParamError("parameter-type")
    if (param.minimum is not None and value < param.minimum) or (
        param.maximum is not None and value > param.maximum
    ):
        raise ParamError("parameter-range")
    return value


def _check_one(param: ParamDef, value: object) -> int | bool | str:
    if param.kind == "integer":
        return _check_integer(param, value)
    if param.kind == "boolean":
        if type(value) is not bool:
            raise ParamError("parameter-type")
        return value
    if type(value) is not str or param.choices is None or value not in param.choices:
        raise ParamError("parameter-choice")
    return value


def validate_params(
    definition: ActionDef, params: Mapping[str, object]
) -> dict[str, int | bool | str]:
    """A new mapping holding exactly the declared parameters, each checked against its type."""
    declared = {p.name: p for p in definition.params}
    if any(name not in declared for name in params):
        raise ParamError("parameter-unknown")
    checked: dict[str, int | bool | str] = {}
    for name, param in declared.items():
        if name not in params:
            if param.required:
                raise ParamError("parameter-missing")
            continue
        checked[name] = _check_one(param, params[name])
    return checked


def plan_steps(
    definition: ActionDef, target_id: str, params: Mapping[str, int | bool | str]
) -> list[str]:
    """What a dry run would do, in words fixed by the definition. Inputs must already be validated."""
    values = {"target": target_id, **{k: str(v) for k, v in params.items()}}
    steps = [template.format_map(values)[:_MAX_STEP] for template in definition.plan]
    return steps[:MAX_STEPS]


def definition_contract(definition: ActionDef) -> ActionDefinition:
    return ActionDefinition(
        action_type=definition.action_type,
        title=definition.title,
        risk=definition.risk,
        target_kind=definition.target_kind,
        params=[
            ActionParamSpec(
                name=p.name,
                kind=p.kind,
                required=p.required,
                minimum=p.minimum,
                maximum=p.maximum,
                choices=list(p.choices) if p.choices is not None else None,
            )
            for p in definition.params
        ],
        approvals_required=definition.approvals_required,
        step_up_required=True,
        approve_within_seconds=definition.approve_within_seconds,
        execute_within_seconds=definition.execute_within_seconds,
        timeout_seconds=definition.timeout_seconds,
        propose_permission=definition.propose_permission,
        rollback_guidance=definition.rollback_guidance,
    )
