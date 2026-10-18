"""The allow-list of action types and their typed parameters (Step 12): no generic execution."""

from __future__ import annotations

from typing import Any

import pytest

from netsight_api.actions.catalog import (
    CATALOG,
    ParamError,
    TargetError,
    definition_contract,
    get_definition,
    plan_steps,
    validate_params,
    validate_target,
)
from netsight_api.schemas_actions import ActionDefinition

FINDING = "unknown-device-aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
FORBIDDEN_PARAM_NAMES = {
    "command",
    "cmd",
    "script",
    "shell",
    "args",
    "argv",
    "exec",
    "query",
    "sql",
    "url",
    "path",
    "host",
    "payload",
}


def test_the_catalog_is_a_closed_allow_list() -> None:
    assert sorted(CATALOG) == ["endpoint.isolate", "switch.port.disable", "switch.port.enable"]
    assert get_definition("endpoint.isolate") is CATALOG["endpoint.isolate"]
    for unknown in (
        "shell.exec",
        "service.restart",
        "firewall.destination.block",
        "",
        "ENDPOINT.ISOLATE",
    ):
        assert get_definition(unknown) is None


@pytest.mark.parametrize("action_type", sorted(CATALOG))
def test_every_definition_is_typed_bounded_and_needs_step_up(action_type: str) -> None:
    definition = CATALOG[action_type]
    contract = definition_contract(definition)
    assert isinstance(contract, ActionDefinition)
    assert contract.step_up_required is True
    assert not FORBIDDEN_PARAM_NAMES & {p.name for p in definition.params}
    for param in definition.params:
        assert param.kind in {"integer", "boolean", "choice"}  # never a free string
    assert definition.approvals_required == (2 if definition.risk == "D" else 1)
    assert definition.timeout_seconds <= 600
    assert definition.execute_within_seconds <= 86_400
    assert definition.rollback_guidance


def test_high_risk_actions_need_the_high_risk_proposal_permission() -> None:
    assert CATALOG["endpoint.isolate"].propose_permission == "actions:propose-high"
    assert CATALOG["switch.port.disable"].propose_permission == "actions:propose-high"
    assert CATALOG["switch.port.enable"].propose_permission == "actions:propose"


def test_valid_parameters_are_returned_as_a_new_normalised_mapping() -> None:
    given = {"duration_minutes": 60}
    checked = validate_params(CATALOG["endpoint.isolate"], given)
    assert checked == {"duration_minutes": 60}
    assert checked is not given


@pytest.mark.parametrize(
    "params",
    [
        {},  # required parameter missing
        {"duration_minutes": 60, "command": "reload"},  # unknown key
        {"duration_minutes": "60"},  # wrong type
        {"duration_minutes": True},  # bool is not an integer here
        {"duration_minutes": 4},
        {"duration_minutes": 1441},
        {"duration_minutes": 10**30},
        {"duration_minutes": 60.5},
        {"duration_minutes": "60; reboot"},
        {"duration_minutes": [60]},
        {"duration_minutes": None},
        {"Duration": 60},
    ],
)
def test_bad_parameters_are_refused_with_a_static_code(params: dict[str, Any]) -> None:
    with pytest.raises(ParamError) as raised:
        validate_params(CATALOG["endpoint.isolate"], params)
    message = str(raised.value)
    assert message.replace("-", "").isalpha()  # a code, never an echo of the input
    assert "reboot" not in message


def test_an_action_without_parameters_accepts_only_an_empty_mapping() -> None:
    assert validate_params(CATALOG["switch.port.disable"], {}) == {}
    with pytest.raises(ParamError):
        validate_params(CATALOG["switch.port.disable"], {"force": True})


@pytest.mark.parametrize(
    ("action_type", "target"),
    [
        ("endpoint.isolate", FINDING),
        ("endpoint.isolate", "endpoint:laptop-12"),
        ("switch.port.disable", "interface:sw1-gi0-1"),
        ("switch.port.enable", "interface:sw1.gi0.1"),
    ],
)
def test_valid_targets(action_type: str, target: str) -> None:
    validate_target(CATALOG[action_type], target)


@pytest.mark.parametrize(
    ("action_type", "target"),
    [
        ("endpoint.isolate", "interface:sw1-gi0-1"),  # wrong kind of target
        ("switch.port.disable", FINDING),
        ("endpoint.isolate", "endpoint:"),
        ("endpoint.isolate", "endpoint:../../etc/passwd"),
        ("endpoint.isolate", "endpoint:a b"),
        ("endpoint.isolate", "endpoint:Laptop"),  # upper case
        ("endpoint.isolate", "endpoint:x\n"),  # trailing newline must not slip past `$`
        ("endpoint.isolate", "endpoint:x;reboot"),
        ("switch.port.disable", "interface:" + "a" * 200),
        ("switch.port.disable", "10.0.0.1"),
        ("switch.port.disable", ""),
    ],
)
def test_invalid_targets_are_refused(action_type: str, target: str) -> None:
    with pytest.raises(TargetError):
        validate_target(CATALOG[action_type], target)


def test_the_dry_run_plan_is_built_only_from_validated_values() -> None:
    steps = plan_steps(CATALOG["endpoint.isolate"], FINDING, {"duration_minutes": 90})
    assert steps
    assert any("90" in step for step in steps)
    assert all(len(step) <= 200 for step in steps)
    assert len(steps) <= 10
    # No step can come from request text: the plan template is the only source of words.
    assert all("{" not in step and "}" not in step for step in steps)


def test_no_definition_exposes_a_way_to_run_an_arbitrary_command() -> None:
    for definition in CATALOG.values():
        for attribute in vars(definition):
            assert attribute not in {"command", "script", "shell", "executor_command"}
