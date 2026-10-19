"""Four-way agreement for the AI copilot contracts (Step 10): JSON Schema, OpenAPI, pydantic, TS parser.

The browser parser runs the same vectors in ``apps/web/src/lib/api-contracts-copilot.test.ts``.
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

from netsight_api import schemas_copilot as m
from netsight_api.contracts import validate

ENTITIES: dict[str, tuple[type[BaseModel], str]] = {
    "copilot_evidence": (m.CopilotEvidence, "CopilotEvidence"),
    "copilot_tool_call": (m.CopilotToolCall, "CopilotToolCall"),
    "copilot_claim": (m.CopilotClaim, "CopilotClaim"),
    "copilot_answer": (m.CopilotAnswer, "CopilotAnswer"),
    "copilot_ask_request": (m.CopilotAskRequest, "CopilotAskRequest"),
    "copilot_ask": (m.CopilotAskResponse, "CopilotAskResponse"),
    "copilot_status": (m.CopilotStatusResponse, "CopilotStatusResponse"),
}
AGREEMENT = Agreement("copilot.vectors.json", ENTITIES)
REFS = {
    "#/$defs/evidence": "CopilotEvidence",
    "#/$defs/toolCall": "CopilotToolCall",
    "#/$defs/claim": "CopilotClaim",
    "#/$defs/answer": "CopilotAnswer",
}
PAIRS: list[tuple[str, str | None, str]] = [
    ("copilot.schema.json", None, "CopilotAskResponse"),
    ("copilot.schema.json", "evidence", "CopilotEvidence"),
    ("copilot.schema.json", "toolCall", "CopilotToolCall"),
    ("copilot.schema.json", "claim", "CopilotClaim"),
    ("copilot.schema.json", "answer", "CopilotAnswer"),
    ("copilot.schema.json", "askRequest", "CopilotAskRequest"),
    ("copilot.schema.json", "statusResponse", "CopilotStatusResponse"),
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


def test_every_copilot_definition_is_paired_with_an_openapi_component() -> None:
    schema_pairs_cover_every_definition("copilot.schema.json", PAIRS)
    declared = {n for n in OPENAPI["components"]["schemas"] if n.startswith("Copilot")}
    assert declared == {p[2] for p in PAIRS}


def test_the_copilot_operations_document_every_error_status_and_a_csrf_header_on_the_write() -> (
    None
):
    paths = OPENAPI["paths"]
    assert set(paths["/copilot/status"]) == {"get"}
    assert set(paths["/copilot/ask"]) == {"post"}
    ask = paths["/copilot/ask"]["post"]
    assert {"200", "401", "403", "422", "429"} <= set(ask["responses"])
    assert any(p.get("name") == "X-CSRF-Token" for p in ask["parameters"])
    assert {"200", "401", "403", "429"} <= set(paths["/copilot/status"]["get"]["responses"])


def test_a_copilot_answer_is_a_valid_generic_ai_answer() -> None:
    answer = AGREEMENT.instance("copilot_answer", {"name": "base"})
    validate("ai_answer", answer)


def test_no_copilot_contract_can_carry_a_tool_argument_a_credential_or_an_action() -> None:
    forbidden = {"tools", "tool_args", "arguments", "action", "actions", "api_key", "model_name"}
    for name, schema in OPENAPI["components"]["schemas"].items():
        if name.startswith("Copilot") and name != "CopilotStatusResponse":
            assert not forbidden & set(schema.get("properties", {})), name
