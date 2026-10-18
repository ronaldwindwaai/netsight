"""The copilot routes over HTTP: RBAC, CSRF, strict input, explicit states, audit and limits (Step 10).

Hermetic: the model is a scripted fake, the knowledge base a temp directory, Oxidized and the incident
store in-memory fakes. The real session, RBAC, CSRF and rate-limit stack runs through ``Caller``.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from alerting_support import Caller, audit_records
from copilot_support import FakeProvider, cite, model_json, write_docs

from netsight_api import copilot_routes, read_limit
from netsight_api.auth.rate_limit import RateLimiter
from netsight_api.auth.settings import session_policy
from netsight_api.contracts import validate
from netsight_api.copilot import knowledge
from netsight_api.incident_routes import get_optional_incident_store
from netsight_api.main import app
from netsight_api.storage import InMemoryIncidentRepository

BASE = "/api/v1/copilot"
OPERATIONAL = ["administrator", "network_engineer", "security_analyst", "technician", "auditor"]
HOSTILE_QUESTION_SECRET = "Hunter2Hunter2-in-a-question"


def first_citation(_messages: Any) -> str:
    return model_json(
        "A runbook applies.", facts=[cite("The runbook covers DNS outages.", "ev-001")]
    )


@pytest.fixture(autouse=True)
def _wiring(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    for name in (
        "NETSIGHT_ENV",
        "NETSIGHT_ENABLE_DEV_IDENTITY",
        "DATABASE_URL",
        "NETSIGHT_AI_BASE_URL",
        "NETSIGHT_AI_MODEL",
        "NETSIGHT_AI_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(knowledge.ROOT_ENV, str(write_docs(tmp_path / "docs")))
    knowledge.reset_for_tests()
    app.dependency_overrides.clear()
    session_policy.cache_clear()
    monkeypatch.setattr(read_limit, "_read_limiter", RateLimiter())
    monkeypatch.setattr(copilot_routes, "_ask_limiter", RateLimiter())
    copilot_routes.reset_for_tests()
    app.dependency_overrides[get_optional_incident_store] = lambda: InMemoryIncidentRepository()
    yield
    app.dependency_overrides.clear()
    session_policy.cache_clear()
    knowledge.reset_for_tests()


def use_model(reply: Any = first_citation) -> FakeProvider:
    provider = FakeProvider(reply)
    app.dependency_overrides[copilot_routes.get_model_provider] = lambda: provider
    return provider


def ask(caller: Caller, question: str = "how do I handle a dns outage?", **kwargs: Any) -> Any:
    return caller.post(f"{BASE}/ask", {"question": question}, **kwargs)


# --- authentication, authorisation, CSRF -----------------------------------------------------------------


def test_unauthenticated_callers_get_401() -> None:
    from fastapi.testclient import TestClient

    client = TestClient(app, raise_server_exceptions=False)
    assert client.get(f"{BASE}/status").status_code == 401
    assert client.post(f"{BASE}/ask", json={"question": "hello there"}).status_code == 401


@pytest.mark.parametrize("role", OPERATIONAL)
def test_operational_roles_may_ask_and_see_status(role: str) -> None:
    use_model()
    caller = Caller(role)
    assert caller.get(f"{BASE}/status").status_code == 200
    response = ask(caller)
    assert response.status_code == 200
    validate("copilot_ask", response.json())


@pytest.mark.parametrize("role", ["management", "superuser"])
def test_management_and_unknown_roles_are_denied_and_the_denial_is_audited(
    role: str, caplog: pytest.LogCaptureFixture
) -> None:
    use_model()
    caller = Caller(role)
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        assert caller.get(f"{BASE}/status").status_code == 403
        assert ask(caller).status_code == 403
    denied = [r for r in audit_records(caplog) if r["outcome"] == "denied"]
    assert {r["action"] for r in denied} >= {"copilot.ask"}


def test_a_service_or_ai_principal_cannot_ask_whatever_its_role() -> None:
    from fastapi.testclient import TestClient

    from netsight_api.auth.deps import get_current_identity
    from netsight_api.rbac import Identity, PrincipalKind

    for kind in (PrincipalKind.SERVICE, PrincipalKind.AI):
        app.dependency_overrides[get_current_identity] = lambda kind=kind: Identity(
            id="svc", roles=frozenset({"administrator"}), principal=kind
        )
        client = TestClient(app, raise_server_exceptions=False)
        assert client.get(f"{BASE}/status").status_code == 403
        assert client.post(f"{BASE}/ask", json={"question": "hello there"}).status_code == 403


def test_a_cookie_post_without_the_csrf_token_is_refused_before_anything_runs() -> None:
    provider = use_model()
    caller = Caller("network_engineer")
    assert ask(caller, csrf=None).status_code == 403
    assert ask(caller, csrf="wrong").status_code == 403
    assert provider.calls == []


# --- not-connected and states ---------------------------------------------------------------------------------


def test_without_a_configured_model_the_answer_is_not_connected_and_nothing_is_read() -> None:
    response = ask(Caller("network_engineer"))
    assert response.status_code == 200
    body = response.json()
    assert body["state"] == "not-connected"
    assert body["answer"] is None and body["evidence"] == [] and body["tool_calls"] == []
    assert body["read_only"] is True
    validate("copilot_ask", body)
    assert response.headers["cache-control"] == "no-store"


def test_a_grounded_answer_end_to_end() -> None:
    provider = use_model()
    response = ask(Caller("network_engineer"), "Why is the dns resolver down? what changed?")
    body = response.json()
    assert response.status_code == 200 and body["state"] == "ok", body
    validate("copilot_ask", body)
    sources = {e["source"] for e in body["evidence"]}
    assert {"knowledge", "incident"} <= sources
    assert body["answer"]["facts"][0]["evidence_ids"] == ["ev-001"]
    assert {t["tool"] for t in body["tool_calls"]} == {
        "search_knowledge",
        "list_open_incidents",
    }
    assert len(provider.calls) == 1


def test_a_failing_model_is_unknown_with_the_evidence_and_no_answer() -> None:
    use_model(RuntimeError("upstream exploded password=Hunter2Hunter2"))
    response = ask(Caller("technician"))
    body = response.json()
    assert response.status_code == 200 and body["state"] == "unknown"
    assert body["answer"] is None and body["evidence"]
    assert "Hunter2Hunter2" not in response.text


def test_nothing_found_is_no_evidence_and_the_model_is_not_asked() -> None:
    provider = use_model()
    body = ask(Caller("technician"), "espresso machine firmware").json()
    assert body["state"] == "no-evidence" and body["answer"] is None
    assert provider.calls == []


# --- injection, end to end (PRD scenarios 11 and 12) -----------------------------------------------------------


def test_a_poisoned_document_is_data_flagged_and_cannot_make_the_model_act() -> None:
    obeying = use_model(
        lambda _m: model_json("Done.", actions=[{"type": "disable_port"}, {"type": "approve"}])
    )
    body = ask(
        Caller("network_engineer"), "what do the printer notes say about the firewall?"
    ).json()
    assert body["state"] == "unknown" and body["answer"] is None
    hostile = [e for e in body["evidence"] if e["instruction_like"]]
    assert hostile and all("Hunter2Hunter2" not in e["excerpt"] for e in hostile)
    assert "instruction_like=true" in obeying.seen
    assert "Hunter2Hunter2" not in obeying.seen


def test_a_compliant_model_answer_carries_a_server_side_warning_about_the_poisoned_item() -> None:
    use_model(
        lambda _m: model_json(
            "The notes contain suspicious text.",
            facts=[cite("A note tells the reader to disable the firewall.", "ev-001")],
        )
    )
    body = ask(
        Caller("network_engineer"), "what do the printer notes say about the firewall?"
    ).json()
    assert body["state"] == "ok"
    warnings = [r["text"] for r in body["answer"]["recommendations"]]
    assert any("instruction to an AI" in w for w in warnings)


def test_there_is_no_write_or_execute_route_under_the_copilot_prefix() -> None:
    paths = {
        path: sorted(methods)
        for path, methods in app.openapi()["paths"].items()
        if "/copilot" in path
    }
    assert paths == {f"{BASE}/status": ["get"], f"{BASE}/ask": ["post"]}


# --- strict input ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"question": ""},
        {"question": "hi"},
        {"question": "x" * 1_001},
        {"question": "   \x00\u200b  "},
        {"question": 5},
        {"question": "valid question", "tools": ["list_open_incidents"]},
        {"question": "valid question", "role": "administrator"},
        [],
        "just a string",
    ],
)
def test_invalid_bodies_are_422_and_never_echoed(body: Any) -> None:
    provider = use_model()
    response = Caller("network_engineer").post(f"{BASE}/ask", body)
    assert response.status_code == 422
    assert "administrator" not in response.text and "list_open_incidents" not in response.text
    assert provider.calls == []


def test_a_non_json_body_is_422() -> None:
    caller = Caller("network_engineer")
    response = caller.http.post(
        f"{BASE}/ask",
        content=b"{not json",
        headers={"Content-Type": "application/json", "X-CSRF-Token": caller.session.csrf_token},
    )
    assert response.status_code == 422


# --- limits ---------------------------------------------------------------------------------------------------


def test_asking_is_rate_limited_per_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    use_model()
    monkeypatch.setattr(copilot_routes, "ASK_LIMIT_PER_MINUTE", 2)
    caller = Caller("network_engineer")
    assert ask(caller).status_code == 200
    assert ask(caller).status_code == 200
    limited = ask(caller)
    assert limited.status_code == 429 and "retry-after" in limited.headers
    assert ask(Caller("technician", subject="sub-2")).status_code == 200


def test_too_many_concurrent_questions_are_refused_not_queued(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    use_model()
    monkeypatch.setattr(copilot_routes, "MAX_CONCURRENT_ASKS", 0)
    assert ask(Caller("network_engineer")).status_code == 429


# --- audit ----------------------------------------------------------------------------------------------------


def test_the_audit_names_the_actor_state_and_tools_but_never_the_question_or_the_evidence(
    caplog: pytest.LogCaptureFixture,
) -> None:
    use_model()
    caller = Caller("security_analyst")
    question = f"why is dns down? password={HOSTILE_QUESTION_SECRET}"
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        assert ask(caller, question).status_code == 200
    raw = "\n".join(r.getMessage() for r in caplog.records if r.name == "netsight_api.audit")
    assert HOSTILE_QUESTION_SECRET not in raw and "dns down" not in raw
    assert "resolver" not in raw  # no evidence text either
    records = audit_records(caplog)
    asked = next(r for r in records if r["action"] == "copilot.ask")
    assert asked["actor_id"] == caller.identity_id and asked["outcome"] == "success"
    assert asked["state"] == "ok" and asked["question_chars"] == len(question)
    tools = [r for r in records if r["action"] == "copilot.tool"]
    assert {r["tool"] for r in tools} == {
        "search_knowledge",
        "list_open_incidents",
    }
    assert all(r["actor_id"] == caller.identity_id for r in tools)


def test_a_not_connected_answer_is_audited_too(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        ask(Caller("technician"))
    asked = next(r for r in audit_records(caplog) if r["action"] == "copilot.ask")
    assert asked["state"] == "not-connected"


# --- status ---------------------------------------------------------------------------------------------------


def test_status_reports_model_knowledge_and_the_tools_the_caller_may_use() -> None:
    caller = Caller("network_engineer")
    body = caller.get(f"{BASE}/status").json()
    validate("copilot_status", body)
    assert body["model"] == {"state": "not-connected"}
    assert body["knowledge"]["state"] == "ok" and body["knowledge"]["documents"] == 3
    assert {t["name"] for t in body["tools"]} == {
        "search_knowledge",
        "list_open_incidents",
    }
    assert all(t["allowed"] for t in body["tools"]) and body["read_only"] is True
    use_model()
    assert caller.get(f"{BASE}/status").json()["model"] == {"state": "ok"}


def test_status_never_reveals_the_model_name_endpoint_or_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NETSIGHT_AI_BASE_URL", "http://127.0.0.1:11434/v1")
    monkeypatch.setenv("NETSIGHT_AI_MODEL", "very-secret-model-name")
    monkeypatch.setenv("NETSIGHT_AI_API_KEY", "key-0123456789abcdef")
    response = Caller("network_engineer").get(f"{BASE}/status")
    assert response.json()["model"] == {"state": "ok"}
    for needle in ("very-secret-model-name", "11434", "key-0123456789abcdef"):
        assert needle not in response.text


def test_status_knowledge_states(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    caller = Caller("technician")
    monkeypatch.delenv(knowledge.ROOT_ENV)
    knowledge.reset_for_tests()
    assert caller.get(f"{BASE}/status").json()["knowledge"] == {
        "state": "not-connected",
        "documents": 0,
        "chunks": 0,
    }
    monkeypatch.setenv(knowledge.ROOT_ENV, str(tmp_path / "missing"))
    knowledge.reset_for_tests()
    assert caller.get(f"{BASE}/status").json()["knowledge"]["state"] == "unknown"


def test_the_response_matches_the_openapi_document_shape() -> None:
    use_model()
    body = ask(Caller("network_engineer")).json()
    assert json.loads(json.dumps(body)) == body
    assert set(body) == {"state", "generated_at", "read_only", "answer", "evidence", "tool_calls"}


def test_one_identity_cannot_hold_every_concurrent_slot(monkeypatch: pytest.MonkeyPatch) -> None:
    use_model()
    monkeypatch.setattr(copilot_routes, "MAX_CONCURRENT_PER_IDENTITY", 0)
    limited = ask(Caller("network_engineer"))
    assert limited.status_code == 429 and "retry-after" in limited.headers


def test_a_crash_while_answering_is_still_audited_and_releases_its_slot(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    use_model()

    async def explode(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("boom password=Hunter2Hunter2")

    monkeypatch.setattr(copilot_routes.CopilotService, "ask", explode)
    caller = Caller("network_engineer")
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        response = ask(caller)
    assert response.status_code == 500
    assert "Hunter2Hunter2" not in response.text
    asked = [r for r in audit_records(caplog) if r["action"] == "copilot.ask"]
    assert asked and asked[-1]["outcome"] == "failure" and asked[-1]["state"] == "error"
    assert copilot_routes._inflight == 0
    assert copilot_routes._inflight_by_identity.get(caller.identity_id, 0) == 0
