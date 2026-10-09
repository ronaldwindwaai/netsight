"""Scheduled rules fail closed when the IANA zone database is unavailable (S6-3 review, LOW).

The zone database comes from the OS (``/usr/share/zoneinfo``) or the ``tzdata`` wheel. A slim
container without either must not make scheduled rules "always active": they cannot be saved,
approved or evaluated, and the dry-run reports why. ``tzdata`` is declared as a dependency so
that normally cannot happen.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfoNotFoundError

import pytest
from alerting_support import (
    RULES,
    Caller,
    clean_environment,
    evaluate_body,
    new_store,
    observation,
    rule_body,
    seed_rule,
)

from netsight_api.alerting import schedule
from netsight_api.alerting.engine import Observation as EngineObservation
from netsight_api.alerting.engine import RuleState, evaluate_definition
from netsight_api.schemas import AlertRuleDefinition, AlertSchedule
from netsight_api.storage import InMemoryAlertRuleRepository

PROJECT = Path(__file__).resolve().parents[1]
EVALUATE = f"{RULES}/evaluate"


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    yield from clean_environment(monkeypatch)


@pytest.fixture
def store() -> InMemoryAlertRuleRepository:
    return new_store()


@pytest.fixture
def no_zone_database(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Every zone lookup fails the way a host without any tz data does."""

    def missing(_name: str) -> Any:
        raise ZoneInfoNotFoundError("No time zone found")

    schedule._load.cache_clear()
    monkeypatch.setattr(schedule, "ZoneInfo", missing)
    yield
    monkeypatch.undo()
    schedule._load.cache_clear()


def a_schedule() -> AlertSchedule:
    return AlertSchedule.model_validate(
        {
            "timezone": "Africa/Windhoek",
            "active": [{"weekdays": ["mon"], "from": "00:00", "to": "23:59"}],
        }
    )


def test_a_valid_zone_name_without_a_database_is_an_error_not_always_active(
    no_zone_database: None,
) -> None:
    with pytest.raises(schedule.ScheduleError, match="not available"):
        schedule.load_zone("Africa/Windhoek")
    with pytest.raises(schedule.ScheduleError):
        schedule.schedule_active(a_schedule(), datetime(2026, 10, 5, 12, tzinfo=UTC))


def test_a_scheduled_rule_cannot_be_saved_without_the_database(
    store: InMemoryAlertRuleRepository, no_zone_database: None
) -> None:
    response = Caller("network_engineer").post(RULES, rule_body())
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "RULE_INVALID"
    assert "SCHEDULE_TIMEZONE_UNKNOWN" in response.json()["error"]["message"]
    assert store.list_rules() == []


def test_a_scheduled_draft_cannot_be_approved_without_the_database(
    store: InMemoryAlertRuleRepository, no_zone_database: None
) -> None:
    rule_id, version = seed_rule(store)  # the store itself does not judge schedules
    response = Caller("administrator").post(
        f"{RULES}/{rule_id}/approve", {"expected_version": version}
    )
    assert response.status_code == 422 and response.json()["error"]["code"] == "RULE_INVALID"
    assert store.get_rule(rule_id).status == "draft"  # type: ignore[union-attr]


def test_an_unscheduled_rule_does_not_need_the_database(
    store: InMemoryAlertRuleRepository, no_zone_database: None
) -> None:
    response = Caller("network_engineer").post(RULES, rule_body(schedule=None))
    assert response.status_code == 201


def test_the_dry_run_reports_the_problem_and_decides_nothing(no_zone_database: None) -> None:
    response = Caller("administrator").post(EVALUATE, evaluate_body(observations=[observation(0)]))
    body = response.json()
    assert response.status_code == 200
    assert body["valid"] is False and body["results"] == []
    assert [p["code"] for p in body["problems"]] == ["SCHEDULE_TIMEZONE_UNKNOWN"]


def test_the_engine_never_fires_a_scheduled_rule_without_the_database(
    no_zone_database: None,
) -> None:
    definition = AlertRuleDefinition.model_validate_json(json.dumps(rule_body()))
    seen = EngineObservation(
        at=datetime(2026, 10, 8, 18, 30, tzinfo=UTC),
        entity="device-1",
        scopes=frozenset({("device_group", "staff-workstations")}),
        value=5e9,
        text=None,
        anomaly=None,
        destination="evil.example",
        device_groups=frozenset({"laptops"}),
    )
    decision, _ = evaluate_definition(
        definition,
        rule_id="alert-rule-00000000-0000-4000-8000-000000000000",
        observation=seen,
        state=RuleState(),
        windows=[],
        clock=lambda: seen.at,
    )
    assert decision.outcome == "invalid-config" and decision.notify is False


# --- packaging: tzdata is a declared dependency -------------------------------------------------


def test_tzdata_is_a_declared_runtime_dependency() -> None:
    project = tomllib.loads((PROJECT / "pyproject.toml").read_text("utf-8"))
    declared = [
        re.split(r"[<>=!~;\[ ]", dep, maxsplit=1)[0] for dep in project["project"]["dependencies"]
    ]
    assert "tzdata" in declared


def test_the_lock_file_records_tzdata_for_every_platform() -> None:
    lock = tomllib.loads((PROJECT / "uv.lock").read_text("utf-8"))
    package = next(p for p in lock["package"] if p["name"] == "netsight-api")
    entries = [d for d in package["dependencies"] if d["name"] == "tzdata"]
    assert entries and all("marker" not in entry for entry in entries)
    metadata = package["metadata"]["requires-dist"]
    assert any(item["name"] == "tzdata" and "marker" not in item for item in metadata)
