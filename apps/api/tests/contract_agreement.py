"""Shared machinery for the four-way contract agreement suites (Step 8).

One shared vector file (``contracts/test-vectors/<name>.vectors.json``) drives the canonical JSON
Schema, the OpenAPI component, the pydantic model and (in the web package) the browser parser. A
vector marked ``jsonschema_rejects: false`` is a cross-field invariant JSON Schema cannot express;
pydantic and the TS parser must still reject it. The same module diffs each OpenAPI component
against its JSON Schema definition so the two documents cannot drift.
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

from netsight_api.contracts import SCHEMA_DIR, ContractViolation, validate

REPO_ROOT = SCHEMA_DIR.parents[1]
OPENAPI: dict[str, Any] = yaml.safe_load(
    (REPO_ROOT / "contracts" / "openapi" / "netsight-api.yaml").read_text("utf-8")
)
_DROPPED_KEYS = {"$schema", "title", "description", "$defs"}
_ORDER_INSENSITIVE = {"required", "enum"}


def load_vectors(name: str) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        json.loads((REPO_ROOT / "contracts" / "test-vectors" / name).read_text("utf-8")),
    )


def _walk(root: Any, parts: list[str]) -> Any:
    node = root
    for part in parts:
        node = node[int(part)] if isinstance(node, list) else node[part]
    return node


def build_instance(vectors: dict[str, Any], entity: str, case: dict[str, Any]) -> dict[str, Any]:
    instance = copy.deepcopy(vectors[entity]["base"])
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


def all_cases(vectors: dict[str, Any]) -> list[Any]:
    return [
        pytest.param(entity, case, id=f"{entity}:{case['name']}")
        for entity, block in vectors.items()
        for case in block["cases"]
    ]


def _registry() -> Registry:
    common = json.loads((SCHEMA_DIR / "common.schema.json").read_text("utf-8"))
    return Registry().with_resource(
        "../json-schema/common.schema.json", Resource.from_contents(common)
    )


def openapi_validator(component: str) -> jsonschema.Draft202012Validator:
    wrapper = {"$ref": f"#/components/schemas/{component}", "components": OPENAPI["components"]}
    return jsonschema.Draft202012Validator(wrapper, registry=_registry())


class Agreement:
    """The four verdicts for one vector file; ``entities`` maps entity -> (model, component)."""

    def __init__(self, vectors_file: str, entities: dict[str, tuple[type[BaseModel], str]]) -> None:
        self.vectors = load_vectors(vectors_file)
        self.entities = entities

    def params(self) -> list[Any]:
        return all_cases(self.vectors)

    def instance(self, entity: str, case: dict[str, Any]) -> dict[str, Any]:
        return build_instance(self.vectors, entity, case)

    def check_json_schema(self, entity: str, case: dict[str, Any]) -> None:
        instance = self.instance(entity, case)
        if case["valid"] or not case["jsonschema_rejects"]:
            validate(entity, instance)
        else:
            with pytest.raises(ContractViolation):
                validate(entity, instance)

    def check_openapi(self, entity: str, case: dict[str, Any]) -> None:
        errors = list(
            openapi_validator(self.entities[entity][1]).iter_errors(self.instance(entity, case))
        )
        expected_valid = case["valid"] or not case["jsonschema_rejects"]
        assert (not errors) is expected_valid, [e.message for e in errors]

    def check_pydantic(self, entity: str, case: dict[str, Any]) -> None:
        model = self.entities[entity][0]
        payload = json.dumps(self.instance(entity, case))
        if case["valid"]:
            parsed = model.model_validate_json(payload)
            validate(entity, json.loads(parsed.model_dump_json(by_alias=True)))  # lossless
        else:
            with pytest.raises(ValidationError):
                model.model_validate_json(payload)

    def check_coverage(self) -> None:
        assert set(self.vectors) == set(self.entities)
        for entity, block in self.vectors.items():
            validate(entity, build_instance(self.vectors, entity, {"name": "base"}))
            verdicts = {case["valid"] for case in block["cases"]}
            assert verdicts == {True, False}, entity
            names = [case["name"] for case in block["cases"]]
            assert len(set(names)) == len(names), entity


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


def assert_openapi_equals_schema(
    filename: str, def_name: str | None, component: str, ref_map: dict[str, str]
) -> None:
    document = json.loads((SCHEMA_DIR / filename).read_text("utf-8"))
    schema = document if def_name is None else document["$defs"][def_name]
    openapi_schema = OPENAPI["components"]["schemas"][component]
    assert _normalise(openapi_schema, ref_map) == _normalise(schema, ref_map)


def pair_ids(pairs: list[tuple[str, str | None, str]]) -> list[str]:
    return [pair[2] for pair in pairs]


def schema_pairs_cover_every_definition(
    filename: str, pairs: list[tuple[str, str | None, str]]
) -> None:
    """Every ``$defs`` entry of the file is paired with an OpenAPI component (none can drift unseen)."""
    document = json.loads((SCHEMA_DIR / filename).read_text("utf-8"))
    paired = {pair[1] for pair in pairs if pair[0] == filename and pair[1] is not None}
    assert set(document["$defs"]) == paired
    assert any(pair[0] == filename and pair[1] is None for pair in pairs)
    for _, _, component in pairs:
        assert component in OPENAPI["components"]["schemas"]
