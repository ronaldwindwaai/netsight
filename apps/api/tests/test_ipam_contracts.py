"""Four-way agreement for the IPAM contracts (Step 8b): JSON Schema, OpenAPI, pydantic, TS parser.

The browser parser runs the same vectors in ``apps/web/src/lib/api-contracts-ipam.test.ts``.
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

from netsight_api import schemas_ipam as m

ENTITIES: dict[str, tuple[type[BaseModel], str]] = {
    "ipam_counts": (m.IpamCounts, "IpamCounts"),
    "ipam_telemetry": (m.IpamTelemetry, "IpamTelemetry"),
    "ipam_utilisation": (m.IpamUtilisation, "IpamUtilisation"),
    "ipam_reserved_range": (m.IpamReservedRange, "IpamReservedRange"),
    "ipam_prefix": (m.IpamPrefix, "IpamPrefix"),
    "ipam_vlan": (m.IpamVlan, "IpamVlan"),
    "ipam_address": (m.IpamAddress, "IpamAddress"),
    "ipam_prefix_list": (m.IpamPrefixList, "IpamPrefixList"),
    "ipam_vlan_list": (m.IpamVlanList, "IpamVlanList"),
    "ipam_address_list": (m.IpamAddressList, "IpamAddressList"),
    "ipam_summary_response": (m.IpamSummaryResponse, "IpamSummaryResponse"),
}
AGREEMENT = Agreement("ipam.vectors.json", ENTITIES)
REFS = {
    "common.schema.json#/$defs/sourceStatus": "DataSourceStatus",
    "#/$defs/counts": "IpamCounts",
    "#/$defs/telemetry": "IpamTelemetry",
    "#/$defs/utilisation": "IpamUtilisation",
    "#/$defs/reservedRange": "IpamReservedRange",
    "#/$defs/prefixVlan": "IpamPrefixVlan",
    "#/$defs/prefix": "IpamPrefix",
    "#/$defs/vlan": "IpamVlan",
    "#/$defs/address": "IpamAddress",
    "#/$defs/activityCounts": "IpamActivityCounts",
}
PAIRS: list[tuple[str, str | None, str]] = [
    ("ipam.schema.json", None, "IpamSummaryResponse"),
    ("ipam.schema.json", "counts", "IpamCounts"),
    ("ipam.schema.json", "telemetry", "IpamTelemetry"),
    ("ipam.schema.json", "utilisation", "IpamUtilisation"),
    ("ipam.schema.json", "reservedRange", "IpamReservedRange"),
    ("ipam.schema.json", "prefixVlan", "IpamPrefixVlan"),
    ("ipam.schema.json", "prefix", "IpamPrefix"),
    ("ipam.schema.json", "prefixList", "IpamPrefixList"),
    ("ipam.schema.json", "vlan", "IpamVlan"),
    ("ipam.schema.json", "vlanList", "IpamVlanList"),
    ("ipam.schema.json", "address", "IpamAddress"),
    ("ipam.schema.json", "activityCounts", "IpamActivityCounts"),
    ("ipam.schema.json", "addressList", "IpamAddressList"),
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


def test_every_ipam_definition_is_paired_with_an_openapi_component() -> None:
    schema_pairs_cover_every_definition("ipam.schema.json", PAIRS)
    declared = {name for name in OPENAPI["components"]["schemas"] if name.startswith("Ipam")}
    assert declared == {p[2] for p in PAIRS}


def test_the_ipam_operations_are_read_only_and_document_every_error_status() -> None:
    paths = OPENAPI["paths"]
    for path, statuses in (
        ("/ipam", {"200", "401", "403", "429"}),
        ("/ipam/prefixes", {"200", "401", "403", "422", "429"}),
        ("/ipam/vlans", {"200", "401", "403", "422", "429"}),
        ("/ipam/addresses", {"200", "401", "403", "422", "429"}),
    ):
        assert set(paths[path]) == {"get"}, f"{path} must be read-only"
        assert statuses <= set(paths[path]["get"]["responses"])


def test_the_list_operations_declare_exactly_the_supported_filters() -> None:
    def names(path: str) -> set[str]:
        return {p["name"] for p in OPENAPI["paths"][path]["get"]["parameters"]}

    assert names("/ipam/prefixes") == {"page", "page_size", "site", "status", "family", "q"}
    assert names("/ipam/vlans") == {"page", "page_size", "site", "q"}
    assert names("/ipam/addresses") == {"page", "page_size", "activity", "source", "prefix", "q"}


def test_percent_of_rounds_half_up_with_integers_and_never_exceeds_100() -> None:
    assert m.percent_of(106, 254) == 41.7
    assert m.percent_of(1, 8) == 12.5
    assert m.percent_of(1, 16) == 6.3  # 6.25 rounds half up, not to even
    assert m.percent_of(500, 100) == 100.0
    assert m.percent_of(0, 254) == 0.0
    assert m.percent_of(3, 0) == 100.0
