"""Four-way agreement for the identity-correlation contracts (Step 6).

One shared vector file (``contracts/test-vectors/identity.vectors.json``) drives the canonical JSON
Schema, the OpenAPI component, the pydantic model and (in ``api-contracts-identity.test.ts``) the
browser parser. A vector marked ``jsonschema_rejects: false`` is a cross-field or canonical-form
invariant JSON Schema cannot express (a window ends after it starts, the relation matches its
endpoint types, a session's basis is its weakest link's, counts add up, an IP is canonical);
pydantic and the TS parser must still reject it.
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

from netsight_api import schemas_identity as m
from netsight_api.contracts import SCHEMA_DIR, ContractViolation, validate

REPO_ROOT = SCHEMA_DIR.parents[1]
VECTORS: dict[str, Any] = json.loads(
    (REPO_ROOT / "contracts" / "test-vectors" / "identity.vectors.json").read_text("utf-8")
)
OPENAPI: dict[str, Any] = yaml.safe_load(
    (REPO_ROOT / "contracts" / "openapi" / "netsight-api.yaml").read_text("utf-8")
)

# vector entity -> (pydantic model, OpenAPI component)
ENTITIES: dict[str, tuple[type[BaseModel], str]] = {
    "identity_entity": (m.EntityRef, "IdentityEntityRef"),
    "identity_evidence": (m.EvidenceRef, "IdentityEvidenceRef"),
    "identity_candidate": (m.Candidate, "IdentityCandidate"),
    "identity_link": (m.IdentityLink, "IdentityLink"),
    "identity_session": (m.IdentitySession, "IdentitySession"),
    "identity_attribution": (m.Attribution, "IdentityAttribution"),
    "identity_source": (m.SourceStatus, "IdentitySourceStatus"),
    "identity_window": (m.TimeWindow, "IdentityTimeWindow"),
    "identity_resolve": (m.ResolveResponse, "IdentityResolveResponse"),
    "user_summary": (m.UserSummary, "UserSummary"),
    "user_traffic_item": (m.UserTrafficItem, "UserTrafficItem"),
    "user_traffic": (m.UserTraffic, "UserTraffic"),
    "user_security_item": (m.UserSecurityItem, "UserSecurityItem"),
    "user_security": (m.UserSecurity, "UserSecurity"),
    "user_profile": (m.UserProfile, "UserProfile"),
    "user_detail": (m.UserDetailResponse, "UserDetailResponse"),
    "users_aggregate": (m.UsersAggregateResponse, "UsersAggregateResponse"),
    "user_list": (m.UserListResponse, "UserListResponse"),
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


def test_every_entity_has_cross_field_cases_json_schema_cannot_express() -> None:
    """Pydantic and the parser must enforce what JSON Schema cannot; prove each entity tries."""
    needing = {"identity_link", "identity_session", "identity_attribution", "identity_resolve"}
    for entity in needing:
        assert any(
            not case["valid"] and case["jsonschema_rejects"] is False
            for case in VECTORS[entity]["cases"]
        ), entity


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
_IDENTITY_NAMES = {
    "entity": "IdentityEntityRef",
    "evidenceRef": "IdentityEvidenceRef",
    "candidate": "IdentityCandidate",
    "link": "IdentityLink",
    "session": "IdentitySession",
    "attribution": "IdentityAttribution",
    "sourceStatus": "IdentitySourceStatus",
    "window": "IdentityTimeWindow",
}
_USERS_NAMES = {
    "userSummary": "UserSummary",
    "trafficItem": "UserTrafficItem",
    "traffic": "UserTraffic",
    "securityItem": "UserSecurityItem",
    "security": "UserSecurity",
    "profile": "UserProfile",
    "detail": "UserDetailResponse",
    "aggregate": "UsersAggregateResponse",
}
# The core definitions are referenced both file-qualified (from the users schema, and in most places
# within the core file itself) and bare (the resolve root).
_QUALIFIED = {f"identity.schema.json#/$defs/{k}": v for k, v in _IDENTITY_NAMES.items()}
IDENTITY_REFS = {
    FRESHNESS_REF: "Freshness",
    **{f"#/$defs/{k}": v for k, v in _IDENTITY_NAMES.items()},
    **_QUALIFIED,
}
USERS_REFS = {
    FRESHNESS_REF: "Freshness",
    **_QUALIFIED,
    **{f"#/$defs/{k}": v for k, v in _USERS_NAMES.items()},
}
SCHEMA_PAIRS: list[tuple[str, str | None, str, dict[str, str]]] = [
    ("identity.schema.json", None, "IdentityResolveResponse", IDENTITY_REFS),
    ("identity.schema.json", "entity", "IdentityEntityRef", IDENTITY_REFS),
    ("identity.schema.json", "evidenceRef", "IdentityEvidenceRef", IDENTITY_REFS),
    ("identity.schema.json", "candidate", "IdentityCandidate", IDENTITY_REFS),
    ("identity.schema.json", "link", "IdentityLink", IDENTITY_REFS),
    ("identity.schema.json", "session", "IdentitySession", IDENTITY_REFS),
    ("identity.schema.json", "attribution", "IdentityAttribution", IDENTITY_REFS),
    ("identity.schema.json", "sourceStatus", "IdentitySourceStatus", IDENTITY_REFS),
    ("identity.schema.json", "window", "IdentityTimeWindow", IDENTITY_REFS),
    ("identity-users.schema.json", None, "UserListResponse", USERS_REFS),
    ("identity-users.schema.json", "userSummary", "UserSummary", USERS_REFS),
    ("identity-users.schema.json", "trafficItem", "UserTrafficItem", USERS_REFS),
    ("identity-users.schema.json", "traffic", "UserTraffic", USERS_REFS),
    ("identity-users.schema.json", "securityItem", "UserSecurityItem", USERS_REFS),
    ("identity-users.schema.json", "security", "UserSecurity", USERS_REFS),
    ("identity-users.schema.json", "profile", "UserProfile", USERS_REFS),
    ("identity-users.schema.json", "detail", "UserDetailResponse", USERS_REFS),
    ("identity-users.schema.json", "aggregate", "UsersAggregateResponse", USERS_REFS),
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


def test_every_openapi_identity_component_is_paired() -> None:
    paired = {pair[2] for pair in SCHEMA_PAIRS}
    declared = {
        name for name in OPENAPI["components"]["schemas"] if name.startswith(("Identity", "User"))
    }
    assert declared == paired


def test_the_identity_operations_are_read_only_and_document_every_error_status() -> None:
    paths = OPENAPI["paths"]
    for path, statuses in (
        ("/users", {"200", "401", "403", "422", "429"}),
        ("/users/summary", {"200", "401", "403", "429"}),
        ("/users/{user_id}", {"200", "401", "403", "404", "422", "429"}),
        ("/identity/resolve", {"200", "401", "403", "422", "429"}),
    ):
        assert set(paths[path]) == {"get"}, f"{path} must be read-only"
        assert statuses <= set(paths[path]["get"]["responses"])
