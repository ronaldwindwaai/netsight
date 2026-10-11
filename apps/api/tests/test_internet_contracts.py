"""Four-way agreement for the Internet/WAN contracts (Step 5).

One shared vector file (``contracts/test-vectors/internet.vectors.json``) drives the canonical JSON
Schema, the OpenAPI component, the pydantic model and (in ``api-contracts-internet.test.ts``) the
browser parser. A vector marked ``jsonschema_rejects: false`` is a cross-field invariant JSON
Schema cannot express (an outage has a start and a duration, SLA seconds add up to the period, a
window ends after it starts); pydantic and the TS parser must still reject it.
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

from netsight_api import schemas_internet as m
from netsight_api.contracts import SCHEMA_DIR, ContractViolation, validate

REPO_ROOT = SCHEMA_DIR.parents[1]
VECTORS: dict[str, Any] = json.loads(
    (REPO_ROOT / "contracts" / "test-vectors" / "internet.vectors.json").read_text("utf-8")
)
OPENAPI: dict[str, Any] = yaml.safe_load(
    (REPO_ROOT / "contracts" / "openapi" / "netsight-api.yaml").read_text("utf-8")
)

# vector entity -> (pydantic model, OpenAPI component)
ENTITIES: dict[str, tuple[type[BaseModel], str]] = {
    "internet_interface": (m.WanInterfaceReading, "WanInterfaceReading"),
    "internet_quality": (m.WanQuality, "WanQuality"),
    "internet_availability": (m.WanAvailability, "WanAvailability"),
    "internet_link": (m.WanLink, "WanLink"),
    "internet_failover": (m.WanFailover, "WanFailover"),
    "internet_response": (m.InternetResponse, "InternetResponse"),
    "internet_sla_link": (m.SlaLink, "InternetSlaLink"),
    "internet_sla_response": (m.SlaResponse, "InternetSlaResponse"),
    "internet_sla_export_window": (m.ExportWindow, "InternetSlaExportWindow"),
    "internet_sla_export_source": (m.ExportSource, "InternetSlaExportSource"),
    "internet_sla_export_link": (m.ExportLink, "InternetSlaExportLink"),
    "internet_sla_export": (m.SlaExport, "InternetSlaExport"),
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
    """The OpenAPI document points at ``../json-schema/common.schema.json`` for ``Freshness``."""
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
    else:
        with pytest.raises(ValidationError):
            model.model_validate_json(payload)


# --- OpenAPI vs JSON Schema structural diff ---------------------------------

FRESHNESS_REF = "common.schema.json#/$defs/freshness"
INTERNET_REFS = {
    FRESHNESS_REF: "Freshness",
    "#/$defs/configured": "WanConfigured",
    "#/$defs/interface": "WanInterfaceReading",
    "#/$defs/quality": "WanQuality",
    "#/$defs/availability": "WanAvailability",
    "#/$defs/link": "WanLink",
    "#/$defs/failover": "WanFailover",
}
SLA_REFS = {
    "#/$defs/violation": "InternetSlaViolation",
    "#/$defs/slaLink": "InternetSlaLink",
    "#/$defs/exportWindow": "InternetSlaExportWindow",
    "#/$defs/exportSource": "InternetSlaExportSource",
    "#/$defs/exportLink": "InternetSlaExportLink",
    "#/$defs/export": "InternetSlaExport",
}
SCHEMA_PAIRS: list[tuple[str, str | None, str, dict[str, str]]] = [
    ("internet.schema.json", None, "InternetResponse", INTERNET_REFS),
    ("internet.schema.json", "configured", "WanConfigured", INTERNET_REFS),
    ("internet.schema.json", "interface", "WanInterfaceReading", INTERNET_REFS),
    ("internet.schema.json", "quality", "WanQuality", INTERNET_REFS),
    ("internet.schema.json", "availability", "WanAvailability", INTERNET_REFS),
    ("internet.schema.json", "link", "WanLink", INTERNET_REFS),
    ("internet.schema.json", "failover", "WanFailover", INTERNET_REFS),
    ("internet-sla.schema.json", None, "InternetSlaResponse", SLA_REFS),
    ("internet-sla.schema.json", "violation", "InternetSlaViolation", SLA_REFS),
    ("internet-sla.schema.json", "slaLink", "InternetSlaLink", SLA_REFS),
    ("internet-sla.schema.json", "exportWindow", "InternetSlaExportWindow", SLA_REFS),
    ("internet-sla.schema.json", "exportSource", "InternetSlaExportSource", SLA_REFS),
    ("internet-sla.schema.json", "exportLink", "InternetSlaExportLink", SLA_REFS),
    ("internet-sla.schema.json", "export", "InternetSlaExport", SLA_REFS),
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


def test_every_openapi_internet_component_is_paired() -> None:
    paired = {pair[2] for pair in SCHEMA_PAIRS}
    declared = {
        name for name in OPENAPI["components"]["schemas"] if name.startswith(("Internet", "Wan"))
    }
    assert declared == paired


def test_the_internet_operations_are_read_only_and_document_every_error_status() -> None:
    paths = OPENAPI["paths"]
    for path, statuses in (
        ("/internet", {"200", "401", "403"}),
        ("/internet/sla", {"200", "401", "403", "422"}),
        ("/internet/sla/export", {"200", "401", "403", "422"}),
    ):
        assert set(paths[path]) == {"get"}, f"{path} must be read-only"
        assert statuses <= set(paths[path]["get"]["responses"])
    export = paths["/internet/sla/export"]["get"]["responses"]["200"]["content"]
    assert set(export) == {"application/json", "text/csv"}
