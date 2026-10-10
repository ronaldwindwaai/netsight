"""Four-way agreement for the incident / alert-rule / maintenance-window contracts.

One shared vector file (``contracts/test-vectors/incident-alert.vectors.json``)
drives the canonical JSON Schema, the OpenAPI component, the pydantic model and
(in ``api-contracts-incident.test.ts`` / ``api-contracts-alert-rule.test.ts``)
the browser parsers. A vector marked ``jsonschema_rejects: false`` is a
cross-field invariant that JSON Schema cannot express; pydantic and the TS
parsers must still reject it, and the schemas document it in ``description``.
"""

from __future__ import annotations

import copy
import json
from typing import Any, cast

import jsonschema  # type: ignore[import-untyped]
import pytest
import yaml  # type: ignore[import-untyped]
from pydantic import BaseModel, ValidationError

from netsight_api import schemas, schemas_alerting
from netsight_api.contracts import SCHEMA_DIR, ContractViolation, validate

REPO_ROOT = SCHEMA_DIR.parents[1]
VECTORS: dict[str, Any] = json.loads(
    (REPO_ROOT / "contracts" / "test-vectors" / "incident-alert.vectors.json").read_text("utf-8")
)
OPENAPI: dict[str, Any] = yaml.safe_load(
    (REPO_ROOT / "contracts" / "openapi" / "netsight-api.yaml").read_text("utf-8")
)

# vector entity -> (contracts.py name, pydantic model, OpenAPI component)
ENTITIES: dict[str, tuple[str, type[BaseModel], str]] = {
    "incident": ("incident", schemas.Incident, "Incident"),
    "incident_resolution": (
        "incident_resolution",
        schemas.IncidentResolution,
        "IncidentResolution",
    ),
    "incident_timeline_event": (
        "incident_timeline_event",
        schemas.IncidentTimelineEvent,
        "IncidentTimelineEvent",
    ),
    "incident_list_response": (
        "incident_list",
        schemas.IncidentListResponse,
        "IncidentListResponse",
    ),
    "incident_summary_list_response": (
        "incident_summary_list",
        schemas.IncidentSummaryListResponse,
        "IncidentSummaryListResponse",
    ),
    "incident_detail_response": (
        "incident_detail",
        schemas.IncidentDetailResponse,
        "IncidentDetailResponse",
    ),
    "incident_timeline_response": (
        "incident_timeline",
        schemas.IncidentTimelineResponse,
        "IncidentTimelineResponse",
    ),
    "alert_rule": ("alert_rule", schemas.AlertRule, "AlertRule"),
    "maintenance_window": (
        "maintenance_window",
        schemas.MaintenanceWindow,
        "MaintenanceWindow",
    ),
    # S6-3: /alert-rules and /maintenance-windows envelopes and request bodies.
    "alert_rule_definition": (
        "alert_rule_definition",
        schemas.AlertRuleDefinition,
        "AlertRuleDefinition",
    ),
    "alert_rule_list_response": (
        "alert_rule_list",
        schemas_alerting.AlertRuleListResponse,
        "AlertRuleListResponse",
    ),
    "alert_rule_detail_response": (
        "alert_rule_detail",
        schemas_alerting.AlertRuleDetailResponse,
        "AlertRuleDetailResponse",
    ),
    "maintenance_window_list_response": (
        "maintenance_window_list",
        schemas_alerting.MaintenanceWindowListResponse,
        "MaintenanceWindowListResponse",
    ),
    "maintenance_window_detail_response": (
        "maintenance_window_detail",
        schemas_alerting.MaintenanceWindowDetailResponse,
        "MaintenanceWindowDetailResponse",
    ),
    "alert_rule_update_request": (
        "alert_rule_update_request",
        schemas_alerting.AlertRuleUpdateRequest,
        "AlertRuleUpdateRequest",
    ),
    "alert_rule_approve_request": (
        "alert_rule_approve_request",
        schemas_alerting.AlertRuleApproveRequest,
        "AlertRuleApproveRequest",
    ),
    "maintenance_window_create_request": (
        "maintenance_window_create_request",
        schemas_alerting.MaintenanceWindowCreateRequest,
        "MaintenanceWindowCreateRequest",
    ),
    "alert_rule_evaluate_request": (
        "alert_rule_evaluate_request",
        schemas_alerting.AlertRuleEvaluateRequest,
        "AlertRuleEvaluateRequest",
    ),
    "alert_rule_evaluate_response": (
        "alert_rule_evaluate_response",
        schemas_alerting.AlertRuleEvaluateResponse,
        "AlertRuleEvaluateResponse",
    ),
}


def _set_path(root: Any, dotted: str, value: Any) -> None:
    *parents, leaf = dotted.split(".")
    node = root
    for part in parents:
        node = node[int(part)] if isinstance(node, list) else node[part]
    if isinstance(node, list):
        node[int(leaf)] = value
    else:
        node[leaf] = value


def _delete_path(root: Any, dotted: str) -> None:
    *parents, leaf = dotted.split(".")
    node = root
    for part in parents:
        node = node[int(part)] if isinstance(node, list) else node[part]
    del node[leaf]


def build_instance(entity: str, case: dict[str, Any]) -> dict[str, Any]:
    instance = copy.deepcopy(VECTORS[entity]["base"])
    for path, value in case.get("set", {}).items():
        _set_path(instance, path, copy.deepcopy(value))
    for path in case.get("delete", []):
        _delete_path(instance, path)
    return cast(dict[str, Any], instance)


def _all_cases() -> list[Any]:
    params = []
    for entity, block in VECTORS.items():
        for case in block["cases"]:
            params.append(pytest.param(entity, case, id=f"{entity}:{case['name']}"))
    return params


def _openapi_validator(component: str) -> jsonschema.Draft202012Validator:
    wrapper = {
        "$ref": f"#/components/schemas/{component}",
        "components": OPENAPI["components"],
    }
    return jsonschema.Draft202012Validator(wrapper)


def test_every_vector_entity_is_covered() -> None:
    assert set(VECTORS) == set(ENTITIES)


@pytest.mark.parametrize(("entity", "case"), _all_cases())
def test_json_schema_verdict(entity: str, case: dict[str, Any]) -> None:
    instance = build_instance(entity, case)
    name = ENTITIES[entity][0]
    if case["valid"] or not case["jsonschema_rejects"]:
        validate(name, instance)
    else:
        with pytest.raises(ContractViolation):
            validate(name, instance)


@pytest.mark.parametrize(("entity", "case"), _all_cases())
def test_openapi_verdict_matches_json_schema(entity: str, case: dict[str, Any]) -> None:
    instance = build_instance(entity, case)
    errors = list(_openapi_validator(ENTITIES[entity][2]).iter_errors(instance))
    expected_valid = case["valid"] or not case["jsonschema_rejects"]
    assert (not errors) is expected_valid, [e.message for e in errors]


@pytest.mark.parametrize(("entity", "case"), _all_cases())
def test_pydantic_verdict(entity: str, case: dict[str, Any]) -> None:
    instance = build_instance(entity, case)
    model = ENTITIES[entity][1]
    payload = json.dumps(instance)
    if case["valid"]:
        parsed = model.model_validate_json(payload)
        # Round trip must be lossless against the canonical schema.
        validate(ENTITIES[entity][0], json.loads(parsed.model_dump_json(by_alias=True)))
    else:
        with pytest.raises(ValidationError):
            model.model_validate_json(payload)


# --- OpenAPI vs JSON Schema structural diff ---------------------------------

# JSON-schema-local $defs -> OpenAPI component names.
DEF_TO_COMPONENT = {
    "incident.schema.json": {
        "#/$defs/resolution": "IncidentResolution",
        "#/$defs/timelineEvent": "IncidentTimelineEvent",
    },
    "incident-api.schema.json": {
        "#/$defs/listResponse": "IncidentListResponse",
        "#/$defs/summary": "IncidentSummary",
        "#/$defs/summaryListResponse": "IncidentSummaryListResponse",
        "#/$defs/detailResponse": "IncidentDetailResponse",
        "#/$defs/timelineResponse": "IncidentTimelineResponse",
        "#/$defs/transitionRequest": "IncidentTransitionRequest",
        "#/$defs/assignRequest": "IncidentAssignRequest",
        "#/$defs/commentRequest": "IncidentCommentRequest",
        "#/$defs/evidenceRequest": "IncidentEvidenceRequest",
        "#/$defs/resolveRequest": "IncidentResolveRequest",
        "#/$defs/reopenRequest": "IncidentReopenRequest",
        "incident.schema.json": "Incident",
        "incident.schema.json#/$defs/timelineEvent": "IncidentTimelineEvent",
    },
    "alert-rule-api.schema.json": {
        "#/$defs/ruleDefinition": "AlertRuleDefinition",
        "#/$defs/evaluateObservation": "AlertRuleEvaluateObservation",
        "#/$defs/evaluateWindow": "AlertRuleEvaluateWindow",
        "#/$defs/evaluateProblem": "AlertRuleEvaluateProblem",
        "#/$defs/evaluateResult": "AlertRuleEvaluateResult",
        "alert-rule.schema.json": "AlertRule",
        "alert-rule.schema.json#/$defs/scope": "AlertScope",
        "alert-rule.schema.json#/$defs/condition": "AlertCondition",
        "alert-rule.schema.json#/$defs/schedule": "AlertSchedule",
        "alert-rule.schema.json#/$defs/exceptions": "AlertExceptions",
        "alert-rule.schema.json#/$defs/maintenanceWindow": "MaintenanceWindow",
    },
    "alert-rule.schema.json": {
        "#/$defs/scope": "AlertScope",
        "#/$defs/condition": "AlertCondition",
        "#/$defs/schedule": "AlertSchedule",
        "#/$defs/scheduleEntry": "AlertScheduleEntry",
        "#/$defs/exceptions": "AlertExceptions",
        "#/$defs/maintenanceWindow": "MaintenanceWindow",
    },
}
# (schema file, def name or None for the root) -> OpenAPI component.
SCHEMA_PAIRS: list[tuple[str, str | None, str]] = [
    ("incident.schema.json", None, "Incident"),
    ("incident.schema.json", "resolution", "IncidentResolution"),
    ("incident.schema.json", "timelineEvent", "IncidentTimelineEvent"),
    ("incident-api.schema.json", "listResponse", "IncidentListResponse"),
    ("incident-api.schema.json", "summary", "IncidentSummary"),
    ("incident-api.schema.json", "summaryListResponse", "IncidentSummaryListResponse"),
    ("incident-api.schema.json", "detailResponse", "IncidentDetailResponse"),
    ("incident-api.schema.json", "timelineResponse", "IncidentTimelineResponse"),
    ("incident-api.schema.json", "transitionRequest", "IncidentTransitionRequest"),
    ("incident-api.schema.json", "assignRequest", "IncidentAssignRequest"),
    ("incident-api.schema.json", "commentRequest", "IncidentCommentRequest"),
    ("incident-api.schema.json", "evidenceRequest", "IncidentEvidenceRequest"),
    ("incident-api.schema.json", "resolveRequest", "IncidentResolveRequest"),
    ("incident-api.schema.json", "reopenRequest", "IncidentReopenRequest"),
    ("alert-rule.schema.json", None, "AlertRule"),
    ("alert-rule.schema.json", "scope", "AlertScope"),
    ("alert-rule.schema.json", "condition", "AlertCondition"),
    ("alert-rule.schema.json", "schedule", "AlertSchedule"),
    ("alert-rule.schema.json", "scheduleEntry", "AlertScheduleEntry"),
    ("alert-rule.schema.json", "exceptions", "AlertExceptions"),
    ("alert-rule.schema.json", "maintenanceWindow", "MaintenanceWindow"),
    ("alert-rule-api.schema.json", "ruleDefinition", "AlertRuleDefinition"),
    ("alert-rule-api.schema.json", "ruleListResponse", "AlertRuleListResponse"),
    ("alert-rule-api.schema.json", "ruleDetailResponse", "AlertRuleDetailResponse"),
    ("alert-rule-api.schema.json", "ruleUpdateRequest", "AlertRuleUpdateRequest"),
    ("alert-rule-api.schema.json", "ruleApproveRequest", "AlertRuleApproveRequest"),
    ("alert-rule-api.schema.json", "windowListResponse", "MaintenanceWindowListResponse"),
    ("alert-rule-api.schema.json", "windowDetailResponse", "MaintenanceWindowDetailResponse"),
    ("alert-rule-api.schema.json", "windowCreateRequest", "MaintenanceWindowCreateRequest"),
    ("alert-rule-api.schema.json", "evaluateObservation", "AlertRuleEvaluateObservation"),
    ("alert-rule-api.schema.json", "evaluateWindow", "AlertRuleEvaluateWindow"),
    ("alert-rule-api.schema.json", "evaluateRequest", "AlertRuleEvaluateRequest"),
    ("alert-rule-api.schema.json", "evaluateProblem", "AlertRuleEvaluateProblem"),
    ("alert-rule-api.schema.json", "evaluateResult", "AlertRuleEvaluateResult"),
    ("alert-rule-api.schema.json", "evaluateResponse", "AlertRuleEvaluateResponse"),
]
_DROPPED_KEYS = {"$schema", "title", "description", "$defs"}
_ORDER_INSENSITIVE = {"required", "enum"}


def _normalise(node: Any, ref_map: dict[str, str], property_names: bool = False) -> Any:
    """Canonical form for comparison.

    ``property_names`` is True while inside a ``properties`` mapping, where keys
    are field names (for example a field called ``title``), not schema keywords.
    """
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
    ("filename", "def_name", "component"),
    SCHEMA_PAIRS,
    ids=[pair[2] for pair in SCHEMA_PAIRS],
)
def test_openapi_component_equals_json_schema(
    filename: str, def_name: str | None, component: str
) -> None:
    document = json.loads((SCHEMA_DIR / filename).read_text("utf-8"))
    schema = document if def_name is None else document["$defs"][def_name]
    openapi_schema = OPENAPI["components"]["schemas"][component]
    ref_map = DEF_TO_COMPONENT[filename]
    assert _normalise(openapi_schema, ref_map) == _normalise(schema, ref_map)


def test_every_openapi_component_in_this_slice_is_paired() -> None:
    paired = {pair[2] for pair in SCHEMA_PAIRS}
    declared = {
        name
        for name in OPENAPI["components"]["schemas"]
        if name.startswith(("Incident", "Alert", "Maintenance"))
        and name not in {"Alert", "AlertListResponse"}
    }
    assert declared == paired


def test_alert_rule_and_maintenance_operations_are_documented_with_every_error_status() -> None:
    paths = OPENAPI["paths"]
    write = {"401", "403", "404", "409", "422", "503"}
    create = {"401", "403", "409", "422", "429", "503"}
    expectations = {
        ("/alert-rules", "get"): {"200", "401", "403", "422"},
        ("/alert-rules", "post"): {"201", *create},
        ("/alert-rules/evaluate", "post"): {"200", "401", "403", "422", "429"},
        ("/alert-rules/{rule_id}", "get"): {"200", "401", "403", "404", "422"},
        ("/alert-rules/{rule_id}", "put"): {"200", *write},
        ("/alert-rules/{rule_id}/approve", "post"): {"200", *write},
        ("/alert-rules/{rule_id}/disable", "post"): {"200", *write},
        ("/maintenance-windows", "get"): {"200", "401", "403", "422"},
        ("/maintenance-windows", "post"): {"201", *create},
        ("/maintenance-windows/{window_id}", "get"): {"200", "401", "403", "404", "422"},
        ("/maintenance-windows/{window_id}/cancel", "post"): {"200", *write},
    }
    for (path, method), statuses in expectations.items():
        assert statuses <= set(paths[path][method]["responses"]), (path, method)
    documented = {p for p in paths if p.startswith(("/alert-rules", "/maintenance-windows"))}
    assert documented == {path for path, _ in expectations}
    # Rules and windows can never be deleted through the API.
    assert "delete" not in paths["/alert-rules/{rule_id}"]
    assert "delete" not in paths["/maintenance-windows/{window_id}"]


def test_incident_operations_are_documented_with_every_error_status() -> None:
    paths = OPENAPI["paths"]
    reads = ["/incidents", "/incidents/{incident_id}", "/incidents/{incident_id}/timeline"]
    writes = [
        f"/incidents/{{incident_id}}/{name}"
        for name in (
            "acknowledge",
            "transition",
            "assign",
            "comment",
            "evidence",
            "resolve",
            "reopen",
        )
    ]
    for path in reads:
        assert {"200", "401", "403", "422"} <= set(paths[path]["get"]["responses"]), path
    for path in writes:
        responses = set(paths[path]["post"]["responses"])
        assert {"401", "403", "404", "409", "422", "503"} <= responses, path
    assert "post" not in paths["/incidents"], "incidents are created by the engine, not by clients"
