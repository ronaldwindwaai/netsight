"""Four-way agreement for the diagnostics (S7) contracts.

One shared vector file (``contracts/test-vectors/diagnostic.vectors.json``) drives the canonical
JSON Schema, the OpenAPI component, the pydantic model and (in
``api-contracts-diagnostic.test.ts``) the browser parsers. A vector marked
``jsonschema_rejects: false`` is a cross-field invariant JSON Schema cannot express (a run names a
probable fault domain exactly when its confidence is real, ``completed_at`` is not before
``started_at``, ids are unique, ``format`` is not asserted); pydantic and the TS parsers must still
reject it, and the schemas document it in ``description``.
"""

from __future__ import annotations

import copy
import json
from typing import Any, cast

import jsonschema  # type: ignore[import-untyped]
import pytest
import yaml  # type: ignore[import-untyped]
from pydantic import BaseModel, ValidationError

from netsight_api import schemas_diagnostics
from netsight_api.contracts import SCHEMA_DIR, ContractViolation, validate

REPO_ROOT = SCHEMA_DIR.parents[1]
VECTORS: dict[str, Any] = json.loads(
    (REPO_ROOT / "contracts" / "test-vectors" / "diagnostic.vectors.json").read_text("utf-8")
)
OPENAPI: dict[str, Any] = yaml.safe_load(
    (REPO_ROOT / "contracts" / "openapi" / "netsight-api.yaml").read_text("utf-8")
)

# vector entity -> (contracts.py name, pydantic model, OpenAPI component)
ENTITIES: dict[str, tuple[str, type[BaseModel], str]] = {
    "diagnostic_finding": (
        "diagnostic_finding",
        schemas_diagnostics.DiagnosticFinding,
        "DiagnosticFinding",
    ),
    "diagnostic_probe_result": (
        "diagnostic_probe_result",
        schemas_diagnostics.DiagnosticProbeResult,
        "DiagnosticProbeResult",
    ),
    "diagnostic_run": (
        "diagnostic_run",
        schemas_diagnostics.DiagnosticRun,
        "DiagnosticRun",
    ),
    "diagnostic_run_request": (
        "diagnostic_run_request",
        schemas_diagnostics.DiagnosticRunRequest,
        "DiagnosticRunRequest",
    ),
    "diagnostic_run_response": (
        "diagnostic_run_response",
        schemas_diagnostics.DiagnosticRunResponse,
        "DiagnosticRunResponse",
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
    "diagnostic.schema.json": {
        "#/$defs/finding": "DiagnosticFinding",
        "#/$defs/probeResult": "DiagnosticProbeResult",
    },
    "diagnostic-api.schema.json": {
        "diagnostic.schema.json": "DiagnosticRun",
    },
}
# (schema file, def name or None for the root) -> OpenAPI component.
SCHEMA_PAIRS: list[tuple[str, str | None, str]] = [
    ("diagnostic.schema.json", None, "DiagnosticRun"),
    ("diagnostic.schema.json", "finding", "DiagnosticFinding"),
    ("diagnostic.schema.json", "probeResult", "DiagnosticProbeResult"),
    ("diagnostic-api.schema.json", "runRequest", "DiagnosticRunRequest"),
    ("diagnostic-api.schema.json", "runResponse", "DiagnosticRunResponse"),
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
        name for name in OPENAPI["components"]["schemas"] if name.startswith("Diagnostic")
    }
    assert declared == paired


def test_diagnostics_operation_is_documented_with_every_error_status() -> None:
    paths = OPENAPI["paths"]
    assert {"200", "401", "403", "422", "429"} <= set(paths["/diagnostics"]["post"]["responses"])
    assert "get" not in paths["/diagnostics"], "a run is created by a POST, not read by id yet"
