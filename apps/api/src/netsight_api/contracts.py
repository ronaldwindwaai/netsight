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
    "device": "device.schema.json",
    "interface": "interface.schema.json",
    "alert": "alert.schema.json",
    "incident": "incident.schema.json",
    "evidence": "evidence.schema.json",
    "action_request": "action-request.schema.json",
    "ai_answer": "ai-answer.schema.json",
    "topology": "topology.schema.json",
    "traffic_top": "traffic.schema.json",
    "traffic_flows": "traffic-flows.schema.json",
    "security_events": "security.schema.json",
    "incident_resolution": "incident.schema.json#/$defs/resolution",
    "incident_timeline_event": "incident.schema.json#/$defs/timelineEvent",
    "incident_list": "incident-api.schema.json#/$defs/listResponse",
    "incident_detail": "incident-api.schema.json#/$defs/detailResponse",
    "incident_timeline": "incident-api.schema.json#/$defs/timelineResponse",
    "alert_rule": "alert-rule.schema.json",
    "maintenance_window": "alert-rule.schema.json#/$defs/maintenanceWindow",
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
