"""Dry-run cost controls (S6-3 security review M7).

The dry-run is a cookie POST that burns CPU (about 0.6 s for the worst accepted body), so it is
bounded four ways: a low per-identity rate, a cap on the combined size of all observation
text, a global concurrency limit that answers 503 instead of queueing, and the existing
per-field limits.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from threading import BoundedSemaphore
from typing import Any

import pytest
from alerting_support import (
    RULES,
    Caller,
    audit_records,
    clean_environment,
    evaluate_body,
    new_store,
    observation,
    rule_body,
)
from net_guard import no_network  # noqa: F401  (pytest fixture)

from netsight_api import alert_rule_routes, alerting_route_support
from netsight_api.schemas_alerting import (
    MAX_EVALUATE_OBSERVATIONS,
    MAX_EVALUATE_TOTAL_TEXT,
    MAX_OBSERVATION_TEXT,
)

EVALUATE = f"{RULES}/evaluate"
BUSY_MESSAGE = "The dry-run is busy; retry shortly"
pytestmark = pytest.mark.usefixtures("no_network")


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    yield from clean_environment(monkeypatch)
    new_store()


def text_series(count: int, size: int) -> list[dict[str, Any]]:
    return [observation(i, value=None, text="a" * size) for i in range(count)]


def text_rule() -> dict[str, Any]:
    return rule_body(
        condition={
            "metric": "security.signature",
            "operator": "matches",
            "threshold": None,
            "pattern": "a*b",
        },
        schedule=None,
        cooldown_seconds=0,
    )


# --- rate ---------------------------------------------------------------------------------------


def test_the_default_rate_is_six_per_minute_per_identity() -> None:
    assert alerting_route_support.EVALUATE_LIMIT_PER_MINUTE == 6
    caller = Caller("administrator")
    statuses = [caller.post(EVALUATE, evaluate_body()).status_code for _ in range(8)]
    assert statuses == [200] * 6 + [429, 429]
    assert Caller("auditor", "sub-other").post(EVALUATE, evaluate_body()).status_code == 200


# --- combined text size -------------------------------------------------------------------------


def test_the_combined_text_cap_is_a_multiple_of_the_per_observation_cap() -> None:
    assert MAX_EVALUATE_TOTAL_TEXT == 64 * MAX_OBSERVATION_TEXT == 262_144
    assert MAX_EVALUATE_TOTAL_TEXT < MAX_EVALUATE_OBSERVATIONS * MAX_OBSERVATION_TEXT


def test_text_exactly_at_the_cap_is_accepted() -> None:
    series = text_series(64, MAX_OBSERVATION_TEXT)
    response = Caller("administrator").post(
        EVALUATE, evaluate_body(definition=text_rule(), observations=series)
    )
    assert response.status_code == 200, response.text


def test_text_one_character_over_the_cap_is_a_422() -> None:
    series = text_series(64, MAX_OBSERVATION_TEXT)
    series.append(observation(64, value=None, text="a"))
    response = Caller("administrator").post(
        EVALUATE, evaluate_body(definition=text_rule(), observations=series)
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_the_old_worst_case_of_200_full_size_texts_is_refused() -> None:
    series = text_series(MAX_EVALUATE_OBSERVATIONS, MAX_OBSERVATION_TEXT)
    response = Caller("administrator").post(
        EVALUATE, evaluate_body(definition=text_rule(), observations=series)
    )
    assert response.status_code == 422


def test_many_short_texts_are_unaffected_by_the_combined_cap() -> None:
    series = text_series(MAX_EVALUATE_OBSERVATIONS, 100)
    response = Caller("administrator").post(
        EVALUATE, evaluate_body(definition=text_rule(), observations=series)
    )
    assert response.status_code == 200


def test_missing_text_counts_as_zero() -> None:
    series = [observation(i, text=None) for i in range(MAX_EVALUATE_OBSERVATIONS)]
    assert (
        Caller("administrator").post(EVALUATE, evaluate_body(observations=series)).status_code
        == 200
    )


# --- global concurrency -----------------------------------------------------------------------------


def test_the_concurrency_limit_is_two() -> None:
    assert alerting_route_support.EVALUATE_MAX_CONCURRENT == 2


def test_a_saturated_dry_run_answers_503_with_a_fixed_message_and_is_audited(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    monkeypatch.setattr(alerting_route_support, "_evaluate_slots", BoundedSemaphore(0))
    response = Caller("administrator").post(EVALUATE, evaluate_body())
    assert response.status_code == 503
    error = response.json()["error"]
    assert (error["code"], error["message"]) == ("EVALUATE_BUSY", BUSY_MESSAGE)
    assert [(r["outcome"], r["reason"]) for r in audit_records(caplog)] == [("denied", "busy")]


def test_at_most_two_dry_runs_run_at_once_and_the_slot_is_always_returned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gate = threading.Event()
    entered = threading.Semaphore(0)
    running = 0
    peak = 0
    lock = threading.Lock()
    real = alert_rule_routes.dry_run

    def slow(request: Any) -> Any:
        nonlocal running, peak
        with lock:
            running += 1
            peak = max(peak, running)
        entered.release()
        gate.wait(10)
        with lock:
            running -= 1
        return real(request)

    monkeypatch.setattr(alert_rule_routes, "dry_run", slow)
    results: list[int] = []

    def call(subject: str) -> None:
        results.append(Caller("administrator", subject).post(EVALUATE, evaluate_body()).status_code)

    first = [threading.Thread(target=call, args=(f"sub-{i}",)) for i in range(2)]
    for thread in first:
        thread.start()
    assert entered.acquire(timeout=5) and entered.acquire(timeout=5)
    third = Caller("administrator", "sub-third").post(EVALUATE, evaluate_body())
    assert third.status_code == 503
    gate.set()
    for thread in first:
        thread.join(10)
    assert sorted(results) == [200, 200]
    assert peak == 2
    # Both slots are back: two more runs fit.
    assert Caller("administrator", "sub-after").post(EVALUATE, evaluate_body()).status_code == 200


def test_a_failing_dry_run_still_returns_its_slot(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(_request: Any) -> Any:
        raise RuntimeError("boom")

    slots = BoundedSemaphore(1)
    monkeypatch.setattr(alerting_route_support, "_evaluate_slots", slots)
    monkeypatch.setattr(alert_rule_routes, "dry_run", boom)
    assert Caller("administrator").post(EVALUATE, evaluate_body()).status_code == 500
    assert slots.acquire(blocking=False)  # it was released despite the failure


def test_a_dispatch_failure_never_strands_the_slot(monkeypatch: pytest.MonkeyPatch) -> None:
    """No worker means nobody else can release: the route takes its claimed slot back."""

    def refuse(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("threadpool refused the job")

    slots = BoundedSemaphore(2)
    monkeypatch.setattr(alerting_route_support, "_evaluate_slots", slots)
    monkeypatch.setattr(alert_rule_routes, "run_in_threadpool", refuse)
    assert Caller("administrator").post(EVALUATE, evaluate_body()).status_code == 500
    assert slots.acquire(blocking=False) and slots.acquire(blocking=False)  # both slots are back
    assert not slots.acquire(blocking=False)


def test_the_route_never_releases_a_slot_the_worker_already_returned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The worker releases in its ``finally``; the request path must not add a second one."""

    def boom(_request: Any) -> Any:
        raise RuntimeError("boom")

    slots = threading.Semaphore(1)  # unbounded: an over-release inflates it instead of raising
    monkeypatch.setattr(alerting_route_support, "_evaluate_slots", slots)
    monkeypatch.setattr(alert_rule_routes, "dry_run", boom)
    assert Caller("administrator").post(EVALUATE, evaluate_body()).status_code == 500
    assert slots.acquire(blocking=False)  # exactly the one the worker returned
    assert not slots.acquire(blocking=False)
