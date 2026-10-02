"""Canonical contract validation.

Every telemetry item, device, alert, incident, evidence record and action
request that crosses the Netsight platform boundary must validate against the
canonical JSON schemas in ``contracts/json-schema``. This module is the
single place platform code uses to enforce that rule.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

import jsonschema
from referencing import Registry, Resource

REPO_ROOT = Path(__file__).resolve().parents[4]
SCHEMA_DIR = REPO_ROOT / "contracts" / "json-schema"

SCHEMA_FILES = {
    "device": "device.schema.json",
    "alert": "alert.schema.json",
    "incident": "incident.schema.json",
    "evidence": "evidence.schema.json",
    "action_request": "action-request.schema.json",
    "ai_answer": "ai-answer.schema.json",
}


class ContractViolation(ValueError):
    """Raised when an instance does not satisfy its canonical schema."""


def _read_schema(filename: str) -> dict[str, Any]:
    path = SCHEMA_DIR / filename
    if not path.is_file():
        raise FileNotFoundError(f"canonical schema missing: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _registry() -> Registry:
    resources = []
    for path in SCHEMA_DIR.glob("*.schema.json"):
        resources.append(
            (path.name, Resource.from_contents(json.loads(path.read_text(encoding="utf-8"))))
        )
    return Registry().with_resources(resources)


@lru_cache(maxsize=None)
def _validator(name: str) -> jsonschema.Draft202012Validator:
    if name not in SCHEMA_FILES:
        raise KeyError(f"unknown canonical schema: {name}")
    schema = _read_schema(SCHEMA_FILES[name])
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
