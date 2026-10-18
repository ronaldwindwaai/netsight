"""Four-way agreement for the controlled-action contracts (Step 12): JSON Schema, OpenAPI, pydantic, TS.

The browser parser runs the same vectors in ``apps/web/src/lib/api-contracts-actions.test.ts``.
"""

from __future__ import annotations

from typing import Any

import pytest
from contract_agreement import (
    OPENAPI,
    Agreement,
    assert_openapi_equals_schema,
    schema_pairs_cover_every_definition,
)
from pydantic import BaseModel

from netsight_api import schemas_actions as m
from netsight_api.actions.catalog import CATALOG

ENTITIES: dict[str, tuple[type[BaseModel], str]] = {
    "action_check": (m.ActionCheck, "ActionCheck"),
    "action_execution": (m.ActionExecution, "ActionExecution"),
    "action_event": (m.ActionHistoryEvent, "ActionHistoryEvent"),
    "action_definition": (m.ActionDefinition, "ActionDefinition"),
    "action_request": (m.ActionRequest, "ActionRequest"),
    "action_status": (m.ActionStatusResponse, "ActionStatusResponse"),
    "action_list": (m.ActionListResponse, "ActionListResponse"),
    "action_detail": (m.ActionDetailResponse, "ActionDetailResponse"),
    "action_create_request": (m.ActionCreateRequest, "ActionCreateRequest"),
    "action_from_finding_request": (m.ActionFromFindingRequest, "ActionFromFindingRequest"),
    "action_decision_request": (m.ActionDecisionRequest, "ActionDecisionRequest"),
    "action_reason_request": (m.ActionReasonRequest, "ActionReasonRequest"),
    "action_kill_switch_request": (m.KillSwitchRequest, "ActionKillSwitchRequest"),
}
AGREEMENT = Agreement("actions.vectors.json", ENTITIES)
REFS = {
    "#/$defs/actor": "ActionActor",
    "#/$defs/source": "ActionSource",
    "#/$defs/approval": "ActionApproval",
    "#/$defs/check": "ActionCheck",
    "#/$defs/verification": "ActionVerification",
    "#/$defs/rollback": "ActionRollback",
    "#/$defs/execution": "ActionExecution",
    "#/$defs/request": "ActionRequest",
    "#/$defs/historyEvent": "ActionHistoryEvent",
    "#/$defs/paramSpec": "ActionParamSpec",
    "#/$defs/definition": "ActionDefinition",
    "#/$defs/executorStatus": "ActionExecutorStatus",
    "#/$defs/killSwitchStatus": "ActionKillSwitchStatus",
    "#/$defs/storeStatus": "ActionStoreStatus",
}
PAIRS: list[tuple[str, str | None, str]] = [
    ("actions.schema.json", None, "ActionListResponse"),
    ("actions.schema.json", "actor", "ActionActor"),
    ("actions.schema.json", "source", "ActionSource"),
    ("actions.schema.json", "approval", "ActionApproval"),
    ("actions.schema.json", "check", "ActionCheck"),
    ("actions.schema.json", "verification", "ActionVerification"),
    ("actions.schema.json", "rollback", "ActionRollback"),
    ("actions.schema.json", "execution", "ActionExecution"),
    ("actions.schema.json", "request", "ActionRequest"),
    ("actions.schema.json", "historyEvent", "ActionHistoryEvent"),
    ("actions.schema.json", "paramSpec", "ActionParamSpec"),
    ("actions.schema.json", "definition", "ActionDefinition"),
    ("actions.schema.json", "executorStatus", "ActionExecutorStatus"),
    ("actions.schema.json", "killSwitchStatus", "ActionKillSwitchStatus"),
    ("actions.schema.json", "storeStatus", "ActionStoreStatus"),
    ("actions.schema.json", "statusResponse", "ActionStatusResponse"),
    ("actions.schema.json", "detailResponse", "ActionDetailResponse"),
    ("actions.schema.json", "createRequest", "ActionCreateRequest"),
    ("actions.schema.json", "fromFindingRequest", "ActionFromFindingRequest"),
    ("actions.schema.json", "decisionRequest", "ActionDecisionRequest"),
    ("actions.schema.json", "reasonRequest", "ActionReasonRequest"),
    ("actions.schema.json", "killSwitchRequest", "ActionKillSwitchRequest"),
]


def test_every_vector_entity_is_covered_and_has_valid_and_invalid_cases() -> None:
    AGREEMENT.check_coverage()


@pytest.mark.parametrize(("entity", "case"), AGREEMENT.params())
def test_json_schema_verdict(entity: str, case: dict[str, Any]) -> None:
    AGREEMENT.check_json_schema(entity, case)


@pytest.mark.parametrize(("entity", "case"), AGREEMENT.params())
def test_openapi_verdict_matches_json_schema(entity: str, case: dict[str, Any]) -> None:
    AGREEMENT.check_openapi(entity, case)


@pytest.mark.parametrize(("entity", "case"), AGREEMENT.params())
def test_pydantic_verdict(entity: str, case: dict[str, Any]) -> None:
    AGREEMENT.check_pydantic(entity, case)


@pytest.mark.parametrize(("filename", "def_name", "component"), PAIRS, ids=[p[2] for p in PAIRS])
def test_openapi_component_equals_json_schema(
    filename: str, def_name: str | None, component: str
) -> None:
    assert_openapi_equals_schema(filename, def_name, component, REFS)


def test_every_action_definition_is_paired_with_an_openapi_component() -> None:
    schema_pairs_cover_every_definition("actions.schema.json", PAIRS)
    declared = {n for n in OPENAPI["components"]["schemas"] if n.startswith("Action")}
    assert declared == {p[2] for p in PAIRS}


def test_the_action_type_enum_is_exactly_the_catalog() -> None:
    enum = OPENAPI["components"]["schemas"]["ActionCreateRequest"]["properties"]["action_type"][
        "enum"
    ]
    assert sorted(enum) == sorted(CATALOG)


def test_the_operations_document_the_error_statuses_csrf_and_idempotency() -> None:
    paths = OPENAPI["paths"]
    assert "/action-requests" not in paths  # the Step 1 placeholder is replaced
    writes = [
        ("/actions", "post"),
        ("/actions/from-finding", "post"),
        ("/actions/{action_id}/approve", "post"),
        ("/actions/{action_id}/reject", "post"),
        ("/actions/{action_id}/cancel", "post"),
        ("/actions/{action_id}/execute", "post"),
        ("/actions/kill-switch", "post"),
    ]
    for path, verb in writes:
        operation = paths[path][verb]
        assert any(p.get("name") == "X-CSRF-Token" for p in operation["parameters"]), path
        assert {"401", "403", "422", "429"} <= set(operation["responses"]), path
    for path in ("/actions", "/actions/from-finding", "/actions/{action_id}/execute"):
        names = {p.get("name") for p in paths[path]["post"]["parameters"]}
        assert "Idempotency-Key" in names, path
    for path in ("/actions/{action_id}/approve", "/actions/{action_id}/execute"):
        assert "409" in paths[path]["post"]["responses"], path
    for path in ("/actions/status", "/actions", "/actions/{action_id}"):
        assert {"200", "401", "403", "429"} <= set(paths[path]["get"]["responses"]), path


def test_no_action_contract_can_carry_a_command_a_script_or_a_credential() -> None:
    forbidden = {"command", "cmd", "script", "shell", "args", "argv", "password", "api_key"}
    for name, schema in OPENAPI["components"]["schemas"].items():
        if name.startswith("Action"):
            assert not forbidden & set(schema.get("properties", {})), name


def test_the_replay_header_is_documented_on_create_and_execute() -> None:
    paths = OPENAPI["paths"]
    assert "Idempotent-Replay" in paths["/actions"]["post"]["responses"]["201"]["headers"]
    assert (
        "Idempotent-Replay"
        in paths["/actions/{action_id}/execute"]["post"]["responses"]["200"]["headers"]
    )
