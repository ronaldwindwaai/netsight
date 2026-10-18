"""Four-way agreement for the Step 7 traffic contracts.

One shared vector file (``contracts/test-vectors/traffic.vectors.json``) drives the canonical JSON
Schema, the OpenAPI component, the pydantic model and (in ``api-contracts-traffic-explorer.test.ts``)
the browser parser. A vector marked ``jsonschema_rejects: false`` is a cross-field invariant JSON
Schema cannot express (a row's attribution matches the response-level attribution, counts add up,
a trend ratio matches the bytes); pydantic and the TS parser must still reject it.
"""

from __future__ import annotations

import copy
import json
from typing import Any, cast

import jsonschema  # type: ignore[import-untyped]
import pytest
import yaml  # type: ignore[import-untyped]
from pydantic import BaseModel, ValidationError
from referencing import Registry, Resource

from netsight_api import schemas_traffic as m
from netsight_api.contracts import SCHEMA_DIR, ContractViolation, validate

REPO_ROOT = SCHEMA_DIR.parents[1]
VECTORS: dict[str, Any] = json.loads(
    (REPO_ROOT / "contracts" / "test-vectors" / "traffic.vectors.json").read_text("utf-8")
)
OPENAPI: dict[str, Any] = yaml.safe_load(
    (REPO_ROOT / "contracts" / "openapi" / "netsight-api.yaml").read_text("utf-8")
)

# vector entity -> (pydantic model, OpenAPI component)
ENTITIES: dict[str, tuple[type[BaseModel], str]] = {
    "traffic_flow_filters": (m.FlowFilters, "TrafficFlowFilters"),
    "traffic_flow_attribution": (m.FlowAttribution, "TrafficFlowAttribution"),
    "traffic_attribution_status": (m.AttributionStatus, "TrafficAttributionStatus"),
    "traffic_flow": (m.TrafficFlow, "TrafficFlow"),
    "traffic_aggregations": (m.FlowAggregations, "TrafficAggregations"),
    "traffic_cohort": (m.CohortStatus, "TrafficCohort"),
    "traffic_flows": (m.TrafficFlowsResponse, "TrafficFlowsResponse"),
    "traffic_app_trend": (m.AppTrend, "TrafficAppTrend"),
    "traffic_application": (m.ApplicationRow, "TrafficApplication"),
    "traffic_applications": (m.TrafficApplicationsResponse, "TrafficApplicationsResponse"),
    "traffic_destination": (m.DestinationRow, "TrafficDestination"),
    "traffic_destinations": (m.TrafficDestinationsResponse, "TrafficDestinationsResponse"),
    "traffic_working_hours": (m.WorkingHours, "TrafficWorkingHours"),
    "traffic_evaluation": (m.Evaluation, "TrafficEvaluation"),
    "traffic_anomaly": (m.Anomaly, "TrafficAnomaly"),
    "traffic_first_seen": (m.FirstSeen, "TrafficFirstSeen"),
    "traffic_anomalies": (m.TrafficAnomaliesResponse, "TrafficAnomaliesResponse"),
}


def _walk(root: Any, parts: list[str]) -> Any:
    node = root
    for part in parts:
        node = node[int(part)] if isinstance(node, list) else node[part]
    return node


def build_instance(entity: str, case: dict[str, Any]) -> dict[str, Any]:
    instance = copy.deepcopy(VECTORS[entity]["base"])
    for path, value in case.get("set", {}).items():
        *parents, leaf = path.split(".")
        node = _walk(instance, parents)
        if isinstance(node, list):
            node[int(leaf)] = copy.deepcopy(value)
        else:
            node[leaf] = copy.deepcopy(value)
    for path in case.get("delete", []):
        *parents, leaf = path.split(".")
        del _walk(instance, parents)[leaf]
    return cast(dict[str, Any], instance)


def _all_cases() -> list[Any]:
    return [
        pytest.param(entity, case, id=f"{entity}:{case['name']}")
        for entity, block in VECTORS.items()
        for case in block["cases"]
    ]


def _registry() -> Registry:
    common = json.loads((SCHEMA_DIR / "common.schema.json").read_text("utf-8"))
    return Registry().with_resource(
        "../json-schema/common.schema.json", Resource.from_contents(common)
    )


def _openapi_validator(component: str) -> jsonschema.Draft202012Validator:
    wrapper = {"$ref": f"#/components/schemas/{component}", "components": OPENAPI["components"]}
    return jsonschema.Draft202012Validator(wrapper, registry=_registry())


def test_every_vector_entity_is_covered_and_has_a_canonical_schema_name() -> None:
    assert set(VECTORS) == set(ENTITIES)
    for entity in ENTITIES:
        validate(entity, build_instance(entity, {"name": "base"}))


def test_every_vector_entity_has_valid_and_invalid_cases() -> None:
    for entity, block in VECTORS.items():
        verdicts = {case["valid"] for case in block["cases"]}
        assert verdicts == {True, False}, entity
        assert len({case["name"] for case in block["cases"]}) == len(block["cases"]), entity


def test_the_suite_exercises_enough_cases_to_matter() -> None:
    assert sum(len(block["cases"]) for block in VECTORS.values()) >= 400


@pytest.mark.parametrize(("entity", "case"), _all_cases())
def test_json_schema_verdict(entity: str, case: dict[str, Any]) -> None:
    instance = build_instance(entity, case)
    if case["valid"] or not case["jsonschema_rejects"]:
        validate(entity, instance)
    else:
        with pytest.raises(ContractViolation):
            validate(entity, instance)


@pytest.mark.parametrize(("entity", "case"), _all_cases())
def test_openapi_verdict_matches_json_schema(entity: str, case: dict[str, Any]) -> None:
    instance = build_instance(entity, case)
    errors = list(_openapi_validator(ENTITIES[entity][1]).iter_errors(instance))
    expected_valid = case["valid"] or not case["jsonschema_rejects"]
    assert (not errors) is expected_valid, [e.message for e in errors]


@pytest.mark.parametrize(("entity", "case"), _all_cases())
def test_pydantic_verdict(entity: str, case: dict[str, Any]) -> None:
    instance = build_instance(entity, case)
    model = ENTITIES[entity][0]
    payload = json.dumps(instance)
    if case["valid"]:
        parsed = model.model_validate_json(payload)
        validate(entity, json.loads(parsed.model_dump_json(by_alias=True)))  # lossless round trip
        assert json.loads(parsed.model_dump_json(by_alias=True)) == instance
    else:
        with pytest.raises(ValidationError):
            model.model_validate_json(payload)


# --- OpenAPI vs JSON Schema structural diff ---------------------------------

FRESHNESS_REF = "common.schema.json#/$defs/freshness"
RANGE_REF = "traffic.schema.json#/$defs/timeRange"
POLICY_REF = "traffic-applications.schema.json#/$defs/policy"
COHORT_REF = "traffic.schema.json#/$defs/cohort"
SHARED = {
    FRESHNESS_REF: "Freshness",
    RANGE_REF: "TrafficTimeRange",
    POLICY_REF: "TrafficPolicy",
    COHORT_REF: "TrafficCohort",
}

FLOWS_REFS = {
    **SHARED,
    "#/$defs/filters": "TrafficFlowFilters",
    "#/$defs/personRef": "TrafficPersonRef",
    "#/$defs/deviceRef": "TrafficDeviceRef",
    "#/$defs/attributionStatus": "TrafficAttributionStatus",
    "#/$defs/flowAttribution": "TrafficFlowAttribution",
    "#/$defs/flow": "TrafficFlow",
    "#/$defs/timelineBucket": "TrafficTimelineBucket",
    "#/$defs/volume": "TrafficVolume",
    "#/$defs/applicationMixItem": "TrafficApplicationMixItem",
    "#/$defs/applicationMix": "TrafficApplicationMix",
    "#/$defs/destinationShare": "TrafficDestinationShare",
    "#/$defs/aggregations": "TrafficAggregations",
}
APPS_REFS = {
    **SHARED,
    "#/$defs/policy": "TrafficPolicy",
    "#/$defs/trend": "TrafficAppTrend",
    "#/$defs/application": "TrafficApplication",
}
DEST_REFS = {**SHARED, "#/$defs/destination": "TrafficDestination"}
ANOM_REFS = {
    **SHARED,
    "#/$defs/method": "TrafficBaselineMethod",
    "#/$defs/workingHours": "TrafficWorkingHours",
    "#/$defs/evaluation": "TrafficEvaluation",
    "#/$defs/firstSeenStatus": "TrafficFirstSeenStatus",
    "#/$defs/context": "TrafficAnomalyContext",
    "#/$defs/subject": "TrafficAnomalySubject",
    "#/$defs/anomaly": "TrafficAnomaly",
    "#/$defs/firstSeen": "TrafficFirstSeen",
}
SCHEMA_PAIRS: list[tuple[str, str | None, str, dict[str, str]]] = [
    ("traffic.schema.json", "cohort", "TrafficCohort", SHARED),
    ("traffic-flows.schema.json", None, "TrafficFlowsResponse", FLOWS_REFS),
    *[
        ("traffic-flows.schema.json", d, c, FLOWS_REFS)
        for d, c in (
            ("filters", "TrafficFlowFilters"),
            ("personRef", "TrafficPersonRef"),
            ("deviceRef", "TrafficDeviceRef"),
            ("attributionStatus", "TrafficAttributionStatus"),
            ("flowAttribution", "TrafficFlowAttribution"),
            ("flow", "TrafficFlow"),
            ("timelineBucket", "TrafficTimelineBucket"),
            ("volume", "TrafficVolume"),
            ("applicationMixItem", "TrafficApplicationMixItem"),
            ("applicationMix", "TrafficApplicationMix"),
            ("destinationShare", "TrafficDestinationShare"),
            ("aggregations", "TrafficAggregations"),
        )
    ],
    ("traffic-applications.schema.json", None, "TrafficApplicationsResponse", APPS_REFS),
    ("traffic-applications.schema.json", "policy", "TrafficPolicy", APPS_REFS),
    ("traffic-applications.schema.json", "trend", "TrafficAppTrend", APPS_REFS),
    ("traffic-applications.schema.json", "application", "TrafficApplication", APPS_REFS),
    ("traffic-destinations.schema.json", None, "TrafficDestinationsResponse", DEST_REFS),
    ("traffic-destinations.schema.json", "destination", "TrafficDestination", DEST_REFS),
    ("traffic-anomalies.schema.json", None, "TrafficAnomaliesResponse", ANOM_REFS),
    *[
        ("traffic-anomalies.schema.json", d, c, ANOM_REFS)
        for d, c in (
            ("method", "TrafficBaselineMethod"),
            ("workingHours", "TrafficWorkingHours"),
            ("evaluation", "TrafficEvaluation"),
            ("firstSeenStatus", "TrafficFirstSeenStatus"),
            ("context", "TrafficAnomalyContext"),
            ("subject", "TrafficAnomalySubject"),
            ("anomaly", "TrafficAnomaly"),
            ("firstSeen", "TrafficFirstSeen"),
        )
    ],
]
_DROPPED_KEYS = {"$schema", "title", "description", "$defs"}
_ORDER_INSENSITIVE = {"required", "enum"}


def _normalise(node: Any, ref_map: dict[str, str], property_names: bool = False) -> Any:
    if isinstance(node, dict):
        out: dict[str, Any] = {}
        for key, value in node.items():
            if not property_names and key in _DROPPED_KEYS:
                continue
            if not property_names and key == "$ref" and isinstance(value, str):
                if value.startswith("#/components/schemas/"):
                    out[key] = value.rsplit("/", 1)[1]
                else:
                    out[key] = ref_map.get(value, value)
                continue
            normalised = _normalise(value, ref_map, key == "properties" and not property_names)
            if not property_names and key in _ORDER_INSENSITIVE and isinstance(normalised, list):
                normalised = sorted(normalised, key=repr)
            out[key] = normalised
        return out
    if isinstance(node, list):
        return [_normalise(item, ref_map) for item in node]
    return node


@pytest.mark.parametrize(
    ("filename", "def_name", "component", "ref_map"),
    SCHEMA_PAIRS,
    ids=[pair[2] for pair in SCHEMA_PAIRS],
)
def test_openapi_component_equals_json_schema(
    filename: str, def_name: str | None, component: str, ref_map: dict[str, str]
) -> None:
    document = json.loads((SCHEMA_DIR / filename).read_text("utf-8"))
    schema = document if def_name is None else document["$defs"][def_name]
    openapi_schema = OPENAPI["components"]["schemas"][component]
    assert _normalise(openapi_schema, ref_map) == _normalise(schema, ref_map)


def test_every_new_openapi_traffic_component_is_paired() -> None:
    paired = {pair[2] for pair in SCHEMA_PAIRS}
    declared = {
        name
        for name in OPENAPI["components"]["schemas"]
        if name.startswith("Traffic") and name not in {"TrafficTimeRange"}
    }
    assert declared == paired


# --- paths --------------------------------------------------------------------

FILTER_PARAMETERS = {
    "source_ip",
    "destination_ip",
    "device",
    "vlan",
    "application",
    "protocol",
    "port",
    "country",
    "asn",
    "direction",
}


def _parameter_names(path: str) -> set[str]:
    parameters = OPENAPI["paths"][path]["get"]["parameters"]
    names: set[str] = set()
    for parameter in parameters:
        if "$ref" in parameter:
            parameter = OPENAPI["components"]["parameters"][parameter["$ref"].rsplit("/", 1)[1]]
        names.add(parameter["name"])
    return names


def test_the_traffic_operations_are_read_only_and_document_every_error_status() -> None:
    paths = OPENAPI["paths"]
    for path in (
        "/traffic/flows",
        "/traffic/applications",
        "/traffic/destinations",
        "/traffic/anomalies",
    ):
        assert set(paths[path]) == {"get"}, f"{path} must be read-only"
        assert {"200", "401", "403", "422", "429"} <= set(paths[path]["get"]["responses"]), path
        assert paths[path]["get"]["operationId"]


def test_the_flow_explorer_documents_exactly_the_allow_listed_filters() -> None:
    names = _parameter_names("/traffic/flows")
    assert FILTER_PARAMETERS <= names
    assert names <= FILTER_PARAMETERS | {"preset", "from", "to", "limit"}


def test_applications_and_destinations_take_a_window_and_a_limit_only() -> None:
    for path in ("/traffic/applications", "/traffic/destinations"):
        assert _parameter_names(path) == {"preset", "from", "to", "limit"}
    assert _parameter_names("/traffic/anomalies") == {"preset", "from", "to"}


# --- semantics the vectors cannot name -----------------------------------------


def test_pydantic_models_forbid_unknown_fields_everywhere() -> None:
    for model, _ in ENTITIES.values():
        assert model.model_config.get("extra") == "forbid", model.__name__


def test_the_non_ok_states_are_static_and_value_free() -> None:
    base = VECTORS["traffic_anomalies"]["base"]
    refused = copy.deepcopy(base)
    refused.update(state="unknown", anomalies=[], first_seen=[], evaluated_range=None)
    with pytest.raises(ValidationError):
        m.TrafficAnomaliesResponse.model_validate(refused | {"anomalies": base["anomalies"]})
