"""Four-way agreement for the forecast contracts (Step 13): JSON Schema, OpenAPI, pydantic, TS parser.

The browser parser runs the same vectors in ``apps/web/src/lib/api-contracts-forecast.test.ts``.
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

from netsight_api import schemas_forecast as m

ENTITIES: dict[str, tuple[type[BaseModel], str]] = {
    "forecast_history_point": (m.ForecastHistoryPoint, "ForecastHistoryPoint"),
    "forecast_point": (m.ForecastPoint, "ForecastPoint"),
    "forecast_method": (m.ForecastMethod, "ForecastMethod"),
    "forecast_threshold": (m.ForecastThreshold, "ForecastThreshold"),
    "forecast_crossing": (m.ForecastCrossing, "ForecastCrossing"),
    "forecast_series": (m.ForecastSeries, "ForecastSeries"),
    "forecast_recommendation": (m.ForecastRecommendation, "ForecastRecommendation"),
    "forecast_response": (m.ForecastResponse, "ForecastResponse"),
}
AGREEMENT = Agreement("forecast.vectors.json", ENTITIES)
REFS = {
    "#/$defs/historyPoint": "ForecastHistoryPoint",
    "#/$defs/point": "ForecastPoint",
    "#/$defs/method": "ForecastMethod",
    "#/$defs/threshold": "ForecastThreshold",
    "#/$defs/crossing": "ForecastCrossing",
    "#/$defs/series": "ForecastSeries",
    "#/$defs/recommendation": "ForecastRecommendation",
}
PAIRS: list[tuple[str, str | None, str]] = [
    ("forecast.schema.json", None, "ForecastResponse"),
    ("forecast.schema.json", "historyPoint", "ForecastHistoryPoint"),
    ("forecast.schema.json", "point", "ForecastPoint"),
    ("forecast.schema.json", "method", "ForecastMethod"),
    ("forecast.schema.json", "threshold", "ForecastThreshold"),
    ("forecast.schema.json", "crossing", "ForecastCrossing"),
    ("forecast.schema.json", "series", "ForecastSeries"),
    ("forecast.schema.json", "recommendation", "ForecastRecommendation"),
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


def test_every_forecast_definition_is_paired_with_an_openapi_component() -> None:
    schema_pairs_cover_every_definition("forecast.schema.json", PAIRS)
    declared = {n for n in OPENAPI["components"]["schemas"] if n.startswith("Forecast")}
    assert declared == {p[2] for p in PAIRS}


def test_the_notice_text_is_the_same_in_the_model_and_the_schema() -> None:
    props = m.ForecastResponse.model_json_schema()["properties"]["notice"]
    assert props["const"] == m.NOTICE


def test_the_forecast_operations_are_read_only_and_document_every_error_status() -> None:
    paths = OPENAPI["paths"]
    for path in ("/forecast/capacity", "/forecast/capacity/export"):
        assert set(paths[path]) == {"get"}, f"{path} must be read-only"
        assert {"200", "401", "403", "422", "429", "503"} <= set(paths[path]["get"]["responses"])
        names = {p["name"] for p in paths[path]["get"]["parameters"]}
        assert names == {"horizon_days", "history_days"}


def test_no_forecast_contract_can_carry_an_action() -> None:
    forbidden = {"action", "action_request", "command", "execute", "script", "payload"}
    for name, schema in OPENAPI["components"]["schemas"].items():
        if name.startswith("Forecast"):
            assert not forbidden & set(schema.get("properties", {})), name
    rec = OPENAPI["components"]["schemas"]["ForecastRecommendation"]["properties"]
    assert rec["advisory"] == {"const": True} and rec["executable"] == {"const": False}
