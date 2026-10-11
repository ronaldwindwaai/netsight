"""Four-way agreement for the inventory contracts (Step 8): JSON Schema, OpenAPI, pydantic, TS parser.

The browser parser runs the same vectors in ``apps/web/src/lib/api-contracts-inventory.test.ts``.
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

from netsight_api import schemas_inventory as m
from netsight_api import schemas_sources as sources

ENTITIES: dict[str, tuple[type[BaseModel], str]] = {
    "data_source_status": (sources.SourceStatus, "DataSourceStatus"),
    "inventory_field": (m.InventoryField, "InventoryField"),
    "inventory_reconcile": (m.InventoryReconcile, "InventoryReconcile"),
    "inventory_alias": (m.InventoryAlias, "InventoryAlias"),
    "inventory_item": (m.InventoryItem, "InventoryItem"),
    "inventory_summary": (m.InventorySummary, "InventorySummary"),
    "inventory_list": (m.InventoryListResponse, "InventoryListResponse"),
    "inventory_detail": (m.InventoryDetailResponse, "InventoryDetailResponse"),
    "inventory_summary_response": (m.InventorySummaryResponse, "InventorySummaryResponse"),
}
AGREEMENT = Agreement("inventory.vectors.json", ENTITIES)
REFS = {
    "common.schema.json#/$defs/sourceStatus": "DataSourceStatus",
    "#/$defs/field": "InventoryField",
    "#/$defs/reconcile": "InventoryReconcile",
    "#/$defs/alias": "InventoryAlias",
    "#/$defs/item": "InventoryItem",
    "#/$defs/classCount": "InventoryClassCount",
    "#/$defs/sourceCount": "InventorySourceCount",
    "#/$defs/summary": "InventorySummary",
}
PAIRS: list[tuple[str, str | None, str]] = [
    ("inventory.schema.json", None, "InventoryListResponse"),
    ("inventory.schema.json", "field", "InventoryField"),
    ("inventory.schema.json", "reconcile", "InventoryReconcile"),
    ("inventory.schema.json", "alias", "InventoryAlias"),
    ("inventory.schema.json", "item", "InventoryItem"),
    ("inventory.schema.json", "classCount", "InventoryClassCount"),
    ("inventory.schema.json", "sourceCount", "InventorySourceCount"),
    ("inventory.schema.json", "summary", "InventorySummary"),
    ("inventory.schema.json", "detailResponse", "InventoryDetailResponse"),
    ("inventory.schema.json", "summaryResponse", "InventorySummaryResponse"),
    ("common.schema.json", "sourceStatus", "DataSourceStatus"),
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
    if filename == "common.schema.json":
        # The shared definition is referenced, not copied: the component is a pure reference.
        assert OPENAPI["components"]["schemas"][component] == {
            "$ref": "../json-schema/common.schema.json#/$defs/sourceStatus"
        }
        return
    assert_openapi_equals_schema(filename, def_name, component, REFS)


def test_every_inventory_definition_is_paired_with_an_openapi_component() -> None:
    schema_pairs_cover_every_definition("inventory.schema.json", PAIRS)
    declared = {name for name in OPENAPI["components"]["schemas"] if name.startswith("Inventory")}
    assert declared == {p[2] for p in PAIRS if p[2].startswith("Inventory")}


def test_the_inventory_operations_are_read_only_and_document_every_error_status() -> None:
    paths = OPENAPI["paths"]
    for path, statuses in (
        ("/inventory", {"200", "401", "403", "422", "429"}),
        ("/inventory/summary", {"200", "401", "403", "429"}),
        ("/inventory/{device_id}", {"200", "401", "403", "404", "429"}),
    ):
        assert set(paths[path]) == {"get"}, f"{path} must be read-only"
        assert statuses <= set(paths[path]["get"]["responses"])


def test_the_list_operation_declares_exactly_the_supported_filters() -> None:
    names = {p["name"] for p in OPENAPI["paths"]["/inventory"]["get"]["parameters"]}
    assert names == {"page", "page_size", "asset_class", "site", "status", "source", "known", "q"}
