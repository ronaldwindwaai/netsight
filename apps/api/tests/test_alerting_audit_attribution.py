"""Audit attribution for rule changes (S6-3 security review M6).

The rule table has no ``updated_by`` column (follow-up), so the audit record is the only place
that says who edited a rule. Update, approve and disable records therefore carry the canonical
SHA-256 of the definition they concern, the acting identity and the rule creator as distinct
fields. Free text never appears in the record.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Iterator
from typing import Any

import pytest
from alerting_support import (
    RULES,
    SEED_ACTOR,
    XSS,
    Caller,
    audit_records,
    clean_environment,
    new_store,
    rule_body,
    seed_rule,
)

from netsight_api.alerting_audit import attribution_details, definition_sha256
from netsight_api.schemas import AlertRuleDefinition
from netsight_api.storage import InMemoryAlertRuleRepository


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    yield from clean_environment(monkeypatch)


@pytest.fixture
def store() -> InMemoryAlertRuleRepository:
    return new_store()


def expected_hash(body: dict[str, Any]) -> str:
    canonical = json.dumps(
        AlertRuleDefinition.model_validate_json(json.dumps(body)).model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def successes(caplog: pytest.LogCaptureFixture) -> dict[str, dict[str, Any]]:
    return {r["action"]: r for r in audit_records(caplog) if r["outcome"] == "success"}


def test_the_hash_is_canonical_independent_of_key_order_and_sensitive_to_content() -> None:
    body = rule_body()
    reordered = dict(reversed(list(body.items())))
    first = AlertRuleDefinition.model_validate_json(json.dumps(body))
    second = AlertRuleDefinition.model_validate_json(json.dumps(reordered))
    assert definition_sha256(first) == definition_sha256(second) == expected_hash(body)
    changed = AlertRuleDefinition.model_validate_json(json.dumps(rule_body(severity="low")))
    assert definition_sha256(changed) != definition_sha256(first)
    assert len(definition_sha256(first)) == 64


def test_update_records_the_editor_the_creator_and_the_new_definition_hash(
    store: InMemoryAlertRuleRepository, caplog: pytest.LogCaptureFixture
) -> None:
    rule_id, version = seed_rule(store)
    editor = Caller("network_engineer", "sub-editor")
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    edited = rule_body(severity="critical", name=XSS)
    response = editor.put(f"{RULES}/{rule_id}", {"expected_version": version, "definition": edited})
    assert response.status_code == 200
    record = successes(caplog)["alert_rule.update"]
    assert record["definition_sha256"] == expected_hash(edited)
    assert record["updated_by"] == editor.identity_id
    assert record["created_by"] == SEED_ACTOR
    assert record["updated_by"] != record["created_by"]
    assert record["actor_id"] == editor.identity_id


def test_approve_records_the_hash_of_the_stored_definition_the_approver_activated(
    store: InMemoryAlertRuleRepository, caplog: pytest.LogCaptureFixture
) -> None:
    editor = Caller("network_engineer", "sub-editor")
    created = editor.post(RULES, rule_body()).json()
    edited = rule_body(severity="medium")
    updated = editor.put(
        f"{RULES}/{created['id']}", {"expected_version": created["version"], "definition": edited}
    ).json()
    approver = Caller("administrator", "sub-approver")
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    response = approver.post(
        f"{RULES}/{created['id']}/approve", {"expected_version": updated["version"]}
    )
    assert response.status_code == 200
    record = successes(caplog)["alert_rule.approve"]
    assert record["definition_sha256"] == expected_hash(edited)
    assert record["updated_by"] == approver.identity_id
    assert record["created_by"] == editor.identity_id


def test_disable_records_the_hash_and_the_disabling_actor(
    store: InMemoryAlertRuleRepository, caplog: pytest.LogCaptureFixture
) -> None:
    rule_id, _ = seed_rule(store, status="active")
    actor = Caller("security_analyst", "sub-sec")
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    assert actor.post(f"{RULES}/{rule_id}/disable").status_code == 200
    record = successes(caplog)["alert_rule.disable"]
    assert record["definition_sha256"] == expected_hash(rule_body())
    assert record["updated_by"] == actor.identity_id
    assert record["created_by"] == SEED_ACTOR


def test_create_records_the_hash_but_no_free_text(
    store: InMemoryAlertRuleRepository, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    body = rule_body(name=XSS)
    assert Caller("network_engineer").post(RULES, body).status_code == 201
    record = successes(caplog)["alert_rule.create"]
    assert record["definition_sha256"] == expected_hash(body)
    text = "\n".join(r.getMessage() for r in caplog.records if r.name == "netsight_api.audit")
    assert "script" not in text and "DROP TABLE" not in text


def test_a_very_long_actor_id_is_hashed_not_truncated_in_the_details() -> None:
    store = InMemoryAlertRuleRepository()
    rule = store.create_rule(
        AlertRuleDefinition.model_validate_json(json.dumps(rule_body())), actor_id="a" * 255
    )
    details = attribution_details(rule, actor_id="b" * 255)
    assert str(details["created_by"]).startswith("sha256:")
    assert str(details["updated_by"]).startswith("sha256:")
    assert details["created_by"] != details["updated_by"]
