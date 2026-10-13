"""Four-way agreement for the unknown-device contracts (Step 8c): JSON Schema, OpenAPI, pydantic, TS parser.

The browser parser runs the same vectors in ``apps/web/src/lib/api-contracts-unknown-devices.test.ts``.
The three request bodies have no browser parser: the server action rebuilds them field by field
(``planUnknownDeviceRequest``), and its bounds are tested against the same limits there.
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

from netsight_api import schemas_unknown_devices as m

ENTITIES: dict[str, tuple[type[BaseModel], str]] = {
    "unknown_device_evidence_ref": (m.UnknownDeviceEvidenceRef, "UnknownDeviceEvidenceRef"),
    "unknown_device_link_slot": (m.UnknownDeviceLinkSlot, "UnknownDeviceLinkSlot"),
    "unknown_device_endpoint": (m.UnknownDeviceEndpoint, "UnknownDeviceEndpoint"),
    "unknown_device_check": (m.UnknownDeviceCheck, "UnknownDeviceCheck"),
    "unknown_device_comparison": (m.UnknownDeviceComparison, "UnknownDeviceComparison"),
    "unknown_device_proposed_action": (
        m.UnknownDeviceProposedAction,
        "UnknownDeviceProposedAction",
    ),
    "unknown_device_finding": (m.UnknownDeviceFinding, "UnknownDeviceFinding"),
    "unknown_device_state_count": (m.UnknownDeviceStateCount, "UnknownDeviceStateCount"),
    "unknown_device_severity_count": (m.UnknownDeviceSeverityCount, "UnknownDeviceSeverityCount"),
    "unknown_device_counts": (m.UnknownDeviceCounts, "UnknownDeviceCounts"),
    "unknown_device_event": (m.UnknownDeviceEvent, "UnknownDeviceEvent"),
    "unknown_device_list": (m.UnknownDeviceListResponse, "UnknownDeviceListResponse"),
    "unknown_device_detail": (m.UnknownDeviceDetailResponse, "UnknownDeviceDetailResponse"),
    "unknown_device_summary": (m.UnknownDeviceSummaryResponse, "UnknownDeviceSummaryResponse"),
    "unknown_device_timeline": (m.UnknownDeviceTimelineResponse, "UnknownDeviceTimelineResponse"),
    "unknown_device_transition_request": (
        m.UnknownDeviceTransitionRequest,
        "UnknownDeviceTransitionRequest",
    ),
    "unknown_device_assign_request": (m.UnknownDeviceAssignRequest, "UnknownDeviceAssignRequest"),
    "unknown_device_comment_request": (
        m.UnknownDeviceCommentRequest,
        "UnknownDeviceCommentRequest",
    ),
    "unknown_device_resolve_request": (
        m.UnknownDeviceResolveRequest,
        "UnknownDeviceResolveRequest",
    ),
    "unknown_device_scan": (m.UnknownDeviceScanResponse, "UnknownDeviceScanResponse"),
}
AGREEMENT = Agreement("unknown-devices.vectors.json", ENTITIES)
REFS = {
    "common.schema.json#/$defs/sourceStatus": "DataSourceStatus",
    "#/$defs/evidenceRef": "UnknownDeviceEvidenceRef",
    "#/$defs/slot": "UnknownDeviceLinkSlot",
    "#/$defs/endpoint": "UnknownDeviceEndpoint",
    "#/$defs/check": "UnknownDeviceCheck",
    "#/$defs/comparison": "UnknownDeviceComparison",
    "#/$defs/proposedAction": "UnknownDeviceProposedAction",
    "#/$defs/finding": "UnknownDeviceFinding",
    "#/$defs/stateCount": "UnknownDeviceStateCount",
    "#/$defs/severityCount": "UnknownDeviceSeverityCount",
    "#/$defs/counts": "UnknownDeviceCounts",
    "#/$defs/event": "UnknownDeviceEvent",
}
PAIRS: list[tuple[str, str | None, str]] = [
    ("unknown-devices.schema.json", None, "UnknownDeviceListResponse"),
    ("unknown-devices.schema.json", "evidenceRef", "UnknownDeviceEvidenceRef"),
    ("unknown-devices.schema.json", "slot", "UnknownDeviceLinkSlot"),
    ("unknown-devices.schema.json", "endpoint", "UnknownDeviceEndpoint"),
    ("unknown-devices.schema.json", "check", "UnknownDeviceCheck"),
    ("unknown-devices.schema.json", "comparison", "UnknownDeviceComparison"),
    ("unknown-devices.schema.json", "proposedAction", "UnknownDeviceProposedAction"),
    ("unknown-devices.schema.json", "finding", "UnknownDeviceFinding"),
    ("unknown-devices.schema.json", "stateCount", "UnknownDeviceStateCount"),
    ("unknown-devices.schema.json", "severityCount", "UnknownDeviceSeverityCount"),
    ("unknown-devices.schema.json", "counts", "UnknownDeviceCounts"),
    ("unknown-devices.schema.json", "event", "UnknownDeviceEvent"),
    ("unknown-devices.schema.json", "detailResponse", "UnknownDeviceDetailResponse"),
    ("unknown-devices.schema.json", "summaryResponse", "UnknownDeviceSummaryResponse"),
    ("unknown-devices.schema.json", "timelineResponse", "UnknownDeviceTimelineResponse"),
    ("unknown-devices.schema.json", "transitionRequest", "UnknownDeviceTransitionRequest"),
    ("unknown-devices.schema.json", "assignRequest", "UnknownDeviceAssignRequest"),
    ("unknown-devices.schema.json", "commentRequest", "UnknownDeviceCommentRequest"),
    ("unknown-devices.schema.json", "resolveRequest", "UnknownDeviceResolveRequest"),
    ("unknown-devices.schema.json", "scanResponse", "UnknownDeviceScanResponse"),
]
WRITES = {
    "acknowledge": {"200", "401", "403", "404", "409", "422", "429", "503"},
    "investigate": {"200", "401", "403", "404", "409", "422", "429", "503"},
    "assign": {"200", "401", "403", "404", "409", "422", "429", "503"},
    "comment": {"201", "401", "403", "404", "409", "422", "429", "503"},
    "resolve": {"200", "401", "403", "404", "409", "422", "429", "503"},
}


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


def test_every_unknown_device_definition_is_paired_with_an_openapi_component() -> None:
    schema_pairs_cover_every_definition("unknown-devices.schema.json", PAIRS)
    declared = {n for n in OPENAPI["components"]["schemas"] if n.startswith("UnknownDevice")}
    assert declared == {p[2] for p in PAIRS}


def test_the_read_operations_are_read_only_and_document_every_error_status() -> None:
    paths = OPENAPI["paths"]
    for path, statuses in (
        ("/unknown-devices", {"200", "401", "403", "422", "429"}),
        ("/unknown-devices/summary", {"200", "401", "403", "429"}),
        ("/unknown-devices/{finding_id}", {"200", "401", "403", "404", "429"}),
        ("/unknown-devices/{finding_id}/timeline", {"200", "401", "403", "404", "422", "429"}),
    ):
        assert set(paths[path]) == {"get"}, f"{path} must be read-only"
        assert statuses <= set(paths[path]["get"]["responses"])


def test_the_write_operations_are_posts_that_need_a_csrf_token_and_document_every_status() -> None:
    paths = OPENAPI["paths"]
    for name, statuses in WRITES.items():
        operation = paths[f"/unknown-devices/{{finding_id}}/{name}"]
        assert set(operation) == {"post"}
        post = operation["post"]
        assert statuses <= set(post["responses"]), name
        assert any(p.get("name") == "X-CSRF-Token" and p["required"] for p in post["parameters"])
    scan = paths["/unknown-devices/scan"]["post"]
    assert {"200", "401", "403", "429", "503"} <= set(scan["responses"])
    assert any(p.get("name") == "X-CSRF-Token" for p in scan["parameters"])


def test_no_operation_can_execute_a_quarantine() -> None:
    operations = [
        (path, method)
        for path, item in OPENAPI["paths"].items()
        if path.startswith("/unknown-devices")
        for method in item
    ]
    ids = {OPENAPI["paths"][p][mth]["operationId"] for p, mth in operations}
    assert not any(word in i.lower() for i in ids for word in ("quarantine", "isolate", "execute"))
    action = OPENAPI["components"]["schemas"]["UnknownDeviceProposedAction"]["properties"]
    assert action["executable"] == {"const": False}
    assert action["state"] == {"const": "proposed"}


def test_the_lifecycle_table_is_exactly_the_documented_one() -> None:
    # Written out independently of the code under test: the store tests derive their expectation from
    # ALLOWED_TRANSITIONS itself, so an edit to the table would otherwise change both sides.
    assert m.ALLOWED_TRANSITIONS == {
        "new": frozenset({"acknowledged", "resolved", "false-positive"}),
        "acknowledged": frozenset({"investigating", "resolved", "false-positive"}),
        "investigating": frozenset({"resolved", "false-positive"}),
        "resolved": frozenset(),
        "false-positive": frozenset(),
    }
