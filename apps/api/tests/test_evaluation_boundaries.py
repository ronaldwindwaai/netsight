"""Architecture guards for the evaluation service: who may send, who may change incidents, and
what must stay pure. Static checks over the source text, so a refactor cannot quietly cross them.
"""

from __future__ import annotations

import ast
from pathlib import Path

import netsight_api

PACKAGE = Path(netsight_api.__file__).parent
SENDING_MODULES = {
    "netsight_api.notifications.smtp",
    "netsight_api.notifications.push",
    "netsight_api.notifications.webhook",
    "netsight_api.notifications.dispatcher",
    "netsight_api.evaluation.notify",
}


def imports_of(path: Path) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text("utf-8"))):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
            found.update(f"{node.module}.{alias.name}" for alias in node.names)
    return found


def test_routes_never_import_anything_that_sends() -> None:
    route_files = [*PACKAGE.glob("*_routes.py"), *PACKAGE.glob("*/routes.py")]
    assert len(route_files) >= 5
    for path in route_files:
        offending = imports_of(path) & SENDING_MODULES
        assert not offending, f"{path.name} imports a sender: {offending}"


def test_only_the_evaluation_service_wires_senders() -> None:
    importers = {
        path.relative_to(PACKAGE).as_posix()
        for path in PACKAGE.rglob("*.py")
        if imports_of(path) & {"netsight_api.notifications.smtp", "netsight_api.notifications.push"}
    }
    assert importers == {"evaluation/wiring.py"}


def test_the_evaluation_service_never_resolves_assigns_or_edits_incidents() -> None:
    forbidden = (
        "transition_state",
        "set_assignee",
        "add_evidence",
        "update_rule",
        "approve_rule",
        "disable_rule",
        "create_rule",
        "create_window",
        "cancel_window",
    )
    for path in (PACKAGE / "evaluation").glob("*.py"):
        text = path.read_text("utf-8")
        for name in forbidden:
            assert name not in text, f"{path.name} uses {name}"


def test_the_evaluation_service_has_no_web_framework_dependency() -> None:
    for path in (PACKAGE / "evaluation").glob("*.py"):
        assert not any(i.startswith(("fastapi", "starlette")) for i in imports_of(path)), path.name


def test_the_pure_engine_stays_free_of_storage_and_evaluation_code() -> None:
    for path in (PACKAGE / "alerting").glob("*.py"):
        offending = {
            i
            for i in imports_of(path)
            if i.startswith(("netsight_api.storage", "netsight_api.evaluation", "httpx", "psycopg"))
        }
        assert not offending, f"{path.name} is no longer pure: {offending}"


def test_incident_writes_by_the_service_use_only_its_service_principal() -> None:
    text = (PACKAGE / "evaluation" / "incidents.py").read_text("utf-8")
    assert text.count("actor_id=SERVICE_ACTOR_ID") >= 3
    assert "actor_id=identity" not in text and "PrincipalKind.HUMAN" not in text
