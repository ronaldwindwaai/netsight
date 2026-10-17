"""Canonical contract validation.

Every telemetry item, device, alert, incident, evidence record and action
request that crosses the Netsight platform boundary must validate against the
canonical JSON schemas in ``contracts/json-schema``. This module is the
single place platform code uses to enforce that rule.
"""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path
from typing import Any, cast

import jsonschema  # type: ignore[import-untyped]
from referencing import Registry, Resource

REPO_ROOT = Path(__file__).resolve().parents[4]
SCHEMA_DIR = REPO_ROOT / "contracts" / "json-schema"

SCHEMA_FILES = {
    "configuration_nodes": "configuration-nodes.schema.json",
    "configuration_versions": "configuration-versions.schema.json",
    "device": "device.schema.json",
    "interface": "interface.schema.json",
    "alert": "alert.schema.json",
    "incident": "incident.schema.json",
    "evidence": "evidence.schema.json",
    "action_request": "action-request.schema.json",
    "ai_answer": "ai-answer.schema.json",
    "topology": "topology.schema.json",
    "traffic_cohort": "traffic.schema.json#/$defs/cohort",
    "traffic_flows": "traffic-flows.schema.json",
    "traffic_flow": "traffic-flows.schema.json#/$defs/flow",
    "traffic_flow_filters": "traffic-flows.schema.json#/$defs/filters",
    "traffic_flow_attribution": "traffic-flows.schema.json#/$defs/flowAttribution",
    "traffic_attribution_status": "traffic-flows.schema.json#/$defs/attributionStatus",
    "traffic_aggregations": "traffic-flows.schema.json#/$defs/aggregations",
    "traffic_applications": "traffic-applications.schema.json",
    "traffic_application": "traffic-applications.schema.json#/$defs/application",
    "traffic_app_trend": "traffic-applications.schema.json#/$defs/trend",
    "traffic_destinations": "traffic-destinations.schema.json",
    "traffic_destination": "traffic-destinations.schema.json#/$defs/destination",
    "traffic_anomalies": "traffic-anomalies.schema.json",
    "traffic_anomaly": "traffic-anomalies.schema.json#/$defs/anomaly",
    "traffic_first_seen": "traffic-anomalies.schema.json#/$defs/firstSeen",
    "traffic_evaluation": "traffic-anomalies.schema.json#/$defs/evaluation",
    "traffic_working_hours": "traffic-anomalies.schema.json#/$defs/workingHours",
    "security_events": "security.schema.json",
    "incident_resolution": "incident.schema.json#/$defs/resolution",
    "incident_timeline_event": "incident.schema.json#/$defs/timelineEvent",
    "incident_list": "incident-api.schema.json#/$defs/listResponse",
    "incident_detail": "incident-api.schema.json#/$defs/detailResponse",
    "incident_summary_list": "incident-api.schema.json#/$defs/summaryListResponse",
    "incident_timeline": "incident-api.schema.json#/$defs/timelineResponse",
    "alert_rule": "alert-rule.schema.json",
    "maintenance_window": "alert-rule.schema.json#/$defs/maintenanceWindow",
    "alert_rule_definition": "alert-rule-api.schema.json#/$defs/ruleDefinition",
    "alert_rule_list": "alert-rule-api.schema.json#/$defs/ruleListResponse",
    "alert_rule_detail": "alert-rule-api.schema.json#/$defs/ruleDetailResponse",
    "alert_rule_update_request": "alert-rule-api.schema.json#/$defs/ruleUpdateRequest",
    "alert_rule_approve_request": "alert-rule-api.schema.json#/$defs/ruleApproveRequest",
    "maintenance_window_list": "alert-rule-api.schema.json#/$defs/windowListResponse",
    "maintenance_window_detail": "alert-rule-api.schema.json#/$defs/windowDetailResponse",
    "maintenance_window_create_request": "alert-rule-api.schema.json#/$defs/windowCreateRequest",
    "alert_rule_evaluate_request": "alert-rule-api.schema.json#/$defs/evaluateRequest",
    "alert_rule_evaluate_response": "alert-rule-api.schema.json#/$defs/evaluateResponse",
    "diagnostic_run": "diagnostic.schema.json",
    "diagnostic_probe_result": "diagnostic.schema.json#/$defs/probeResult",
    "diagnostic_finding": "diagnostic.schema.json#/$defs/finding",
    "diagnostic_run_request": "diagnostic-api.schema.json#/$defs/runRequest",
    "diagnostic_run_response": "diagnostic-api.schema.json#/$defs/runResponse",
    "diagnostic_session": "diagnostic-session.schema.json",
    "diagnostic_location_result": "diagnostic-session.schema.json#/$defs/locationResult",
    "diagnostic_probable_cause": "diagnostic-session.schema.json#/$defs/probableCause",
    "diagnostic_recent_changes": "diagnostic-session.schema.json#/$defs/recentChanges",
    "diagnostic_path": "diagnostic-session.schema.json#/$defs/path",
    "diagnostic_session_response": "diagnostic-api.schema.json#/$defs/sessionResponse",
    "diagnostic_session_list_response": "diagnostic-api.schema.json#/$defs/sessionListResponse",
    "internet_response": "internet.schema.json",
    "internet_interface": "internet.schema.json#/$defs/interface",
    "internet_quality": "internet.schema.json#/$defs/quality",
    "internet_availability": "internet.schema.json#/$defs/availability",
    "internet_link": "internet.schema.json#/$defs/link",
    "internet_failover": "internet.schema.json#/$defs/failover",
    "internet_sla_response": "internet-sla.schema.json",
    "internet_sla_link": "internet-sla.schema.json#/$defs/slaLink",
    "internet_sla_export_window": "internet-sla.schema.json#/$defs/exportWindow",
    "internet_sla_export_source": "internet-sla.schema.json#/$defs/exportSource",
    "internet_sla_export_link": "internet-sla.schema.json#/$defs/exportLink",
    "internet_sla_export": "internet-sla.schema.json#/$defs/export",
    "identity_entity": "identity.schema.json#/$defs/entity",
    "identity_evidence": "identity.schema.json#/$defs/evidenceRef",
    "identity_candidate": "identity.schema.json#/$defs/candidate",
    "identity_link": "identity.schema.json#/$defs/link",
    "identity_session": "identity.schema.json#/$defs/session",
    "identity_attribution": "identity.schema.json#/$defs/attribution",
    "identity_source": "identity.schema.json#/$defs/sourceStatus",
    "identity_window": "identity.schema.json#/$defs/window",
    "identity_resolve": "identity.schema.json",
    "user_summary": "identity-users.schema.json#/$defs/userSummary",
    "user_traffic_item": "identity-users.schema.json#/$defs/trafficItem",
    "user_traffic": "identity-users.schema.json#/$defs/traffic",
    "user_security_item": "identity-users.schema.json#/$defs/securityItem",
    "user_security": "identity-users.schema.json#/$defs/security",
    "user_profile": "identity-users.schema.json#/$defs/profile",
    "user_detail": "identity-users.schema.json#/$defs/detail",
    "users_aggregate": "identity-users.schema.json#/$defs/aggregate",
    "user_list": "identity-users.schema.json",
    "data_source_status": "common.schema.json#/$defs/sourceStatus",
    "inventory_list": "inventory.schema.json",
    "inventory_field": "inventory.schema.json#/$defs/field",
    "inventory_reconcile": "inventory.schema.json#/$defs/reconcile",
    "inventory_alias": "inventory.schema.json#/$defs/alias",
    "inventory_item": "inventory.schema.json#/$defs/item",
    "inventory_summary": "inventory.schema.json#/$defs/summary",
    "inventory_detail": "inventory.schema.json#/$defs/detailResponse",
    "inventory_summary_response": "inventory.schema.json#/$defs/summaryResponse",
    "ipam_summary_response": "ipam.schema.json",
    "ipam_counts": "ipam.schema.json#/$defs/counts",
    "ipam_telemetry": "ipam.schema.json#/$defs/telemetry",
    "ipam_utilisation": "ipam.schema.json#/$defs/utilisation",
    "ipam_reserved_range": "ipam.schema.json#/$defs/reservedRange",
    "ipam_prefix": "ipam.schema.json#/$defs/prefix",
    "ipam_prefix_list": "ipam.schema.json#/$defs/prefixList",
    "ipam_vlan": "ipam.schema.json#/$defs/vlan",
    "ipam_vlan_list": "ipam.schema.json#/$defs/vlanList",
    "ipam_address": "ipam.schema.json#/$defs/address",
    "ipam_address_list": "ipam.schema.json#/$defs/addressList",
    "unknown_device_list": "unknown-devices.schema.json",
    "unknown_device_evidence_ref": "unknown-devices.schema.json#/$defs/evidenceRef",
    "unknown_device_link_slot": "unknown-devices.schema.json#/$defs/slot",
    "unknown_device_endpoint": "unknown-devices.schema.json#/$defs/endpoint",
    "unknown_device_check": "unknown-devices.schema.json#/$defs/check",
    "unknown_device_comparison": "unknown-devices.schema.json#/$defs/comparison",
    "unknown_device_proposed_action": "unknown-devices.schema.json#/$defs/proposedAction",
    "unknown_device_finding": "unknown-devices.schema.json#/$defs/finding",
    "unknown_device_state_count": "unknown-devices.schema.json#/$defs/stateCount",
    "unknown_device_severity_count": "unknown-devices.schema.json#/$defs/severityCount",
    "unknown_device_counts": "unknown-devices.schema.json#/$defs/counts",
    "unknown_device_event": "unknown-devices.schema.json#/$defs/event",
    "unknown_device_detail": "unknown-devices.schema.json#/$defs/detailResponse",
    "unknown_device_summary": "unknown-devices.schema.json#/$defs/summaryResponse",
    "unknown_device_timeline": "unknown-devices.schema.json#/$defs/timelineResponse",
    "unknown_device_transition_request": "unknown-devices.schema.json#/$defs/transitionRequest",
    "unknown_device_assign_request": "unknown-devices.schema.json#/$defs/assignRequest",
    "unknown_device_comment_request": "unknown-devices.schema.json#/$defs/commentRequest",
    "unknown_device_resolve_request": "unknown-devices.schema.json#/$defs/resolveRequest",
    "unknown_device_scan": "unknown-devices.schema.json#/$defs/scanResponse",
}


class ContractViolation(ValueError):
    """Raised when an instance does not satisfy its canonical schema."""


def _read_schema(filename: str) -> dict[str, Any]:
    path = SCHEMA_DIR / filename
    if not path.is_file():
        raise FileNotFoundError(f"canonical schema missing: {path}")
    raw_schema: object = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw_schema, dict):
        raise TypeError(f"canonical schema must be an object: {path}")
    return cast(dict[str, Any], raw_schema)


def _registry() -> Registry:
    resources = []
    for path in SCHEMA_DIR.glob("*.schema.json"):
        schema = _read_schema(path.name)
        resources.append((path.name, Resource.from_contents(schema)))
    return Registry().with_resources(resources)


@cache
def _validator(name: str) -> jsonschema.Draft202012Validator:
    if name not in SCHEMA_FILES:
        raise KeyError(f"unknown canonical schema: {name}")
    filename, _, fragment = SCHEMA_FILES[name].partition("#")
    if fragment:
        # A named definition inside a canonical schema file ("file#/$defs/x").
        schema: dict[str, Any] = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": f"{filename}#{fragment}",
        }
    else:
        schema = _read_schema(filename)
    return jsonschema.Draft202012Validator(schema, registry=_registry())


def validate(name: str, instance: dict[str, Any]) -> None:
    """Validate ``instance`` against the canonical schema ``name``.

    Raises ContractViolation listing every violation found.
    """
    validator = _validator(name)
    errors = sorted(validator.iter_errors(instance), key=lambda e: list(e.path))
    if errors:
        details = "; ".join(f"{list(e.path)}: {e.message}" for e in errors)
        raise ContractViolation(f"{name}: {details}")
