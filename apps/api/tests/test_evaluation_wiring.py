"""Configuration, assembly and scheduling of the evaluation service (S6 step 2).

Off by default (no network, no database traffic); enabled only by an explicit setting; a bad
configuration fails start-up instead of silently running a weaker evaluator.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from netsight_api import main
from netsight_api.evaluation.wiring import (
    EvaluationService,
    EvaluationSettings,
    build_evaluation_service,
    run_scheduler,
)

DB = {"DATABASE_URL": "postgresql://app:app-password-xyz@127.0.0.1:1/netsight"}
ON = {"NETSIGHT_EVALUATION_ENABLED": "true", **DB}


def build(env: dict[str, str]) -> EvaluationService | None:
    return build_evaluation_service(env, librenms_client=lambda: None)


# --- settings ---------------------------------------------------------------------------------------


def test_evaluation_is_off_by_default_and_the_interval_has_a_default() -> None:
    settings = EvaluationSettings.from_env({})
    assert (settings.enabled, settings.interval_seconds) == (False, 60)


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", " on "])
def test_explicit_truthy_values_enable_it(value: str) -> None:
    assert EvaluationSettings.from_env({"NETSIGHT_EVALUATION_ENABLED": value}).enabled is True


@pytest.mark.parametrize("value", ["", "0", "false", "no", "off"])
def test_falsy_values_keep_it_off(value: str) -> None:
    assert EvaluationSettings.from_env({"NETSIGHT_EVALUATION_ENABLED": value}).enabled is False


@pytest.mark.parametrize("value", ["maybe", "2", "enable", "tru"])
def test_ambiguous_values_fail_start_up_rather_than_guess(value: str) -> None:
    with pytest.raises(ValueError, match="NETSIGHT_EVALUATION_ENABLED"):
        EvaluationSettings.from_env({"NETSIGHT_EVALUATION_ENABLED": value})


@pytest.mark.parametrize("value", ["29", "3601", "abc", "-5", "1.5"])
def test_the_interval_is_bounded(value: str) -> None:
    with pytest.raises(ValueError, match="NETSIGHT_EVALUATION_INTERVAL_SECONDS"):
        EvaluationSettings.from_env(
            {"NETSIGHT_EVALUATION_ENABLED": "1", "NETSIGHT_EVALUATION_INTERVAL_SECONDS": value}
        )


def test_interval_bounds_are_inclusive() -> None:
    for value, expected in (("30", 30), ("3600", 3600)):
        env = {"NETSIGHT_EVALUATION_INTERVAL_SECONDS": value}
        assert EvaluationSettings.from_env(env).interval_seconds == expected


# --- assembly ---------------------------------------------------------------------------------------


def test_disabled_builds_nothing_and_touches_nothing() -> None:
    assert build({}) is None
    assert build(DB) is None


def test_enabled_without_a_database_fails_start_up() -> None:
    with pytest.raises(ValueError, match="DATABASE_URL"):
        build({"NETSIGHT_EVALUATION_ENABLED": "1"})


def test_enabled_with_a_malformed_database_url_fails_start_up_without_echoing_it() -> None:
    with pytest.raises(ValueError) as raised:
        build({"NETSIGHT_EVALUATION_ENABLED": "1", "DATABASE_URL": "mysql://u:pw-secret@h/db"})
    assert "pw-secret" not in str(raised.value)


def test_enabled_with_no_channels_still_builds_and_reports_no_senders() -> None:
    service = build(ON)
    assert service is not None
    assert service.channels == () and service.interval_seconds == 60


def test_configured_channels_are_registered_and_their_secrets_stay_out_of_repr() -> None:
    env = {
        **ON,
        "NETSIGHT_PUBLIC_BASE_URL": "https://netsight.example.com",
        "NETSIGHT_SMTP_HOST": "smtp.example.com",
        "NETSIGHT_SMTP_FROM": "netsight@example.com",
        "NETSIGHT_SMTP_USERNAME": "svc",
        "NETSIGHT_SMTP_PASSWORD": "smtp-pass-do-not-leak",
        "NETSIGHT_PUSH_GATEWAY_URL": "https://push.example.com/v1/s3cr3t-path",
        "NETSIGHT_PUSH_GATEWAY_TOKEN": "gateway-token-do-not-leak",
        "NETSIGHT_WEBHOOK_ALLOWED_HOSTS": "push.example.com",
        "NETSIGHT_NOTIFY_EMAIL_TO": "ops@example.com",
        "NETSIGHT_NOTIFY_PUSH_DEVICES": "device-ref-do-not-leak",
    }
    service = build(env)
    assert service is not None and set(service.channels) == {"email", "push"}
    text = repr(service) + str(service)
    for secret in (
        "smtp-pass-do-not-leak",
        "gateway-token-do-not-leak",
        "s3cr3t-path",
        "device-ref-do-not-leak",
        "app-password-xyz",
        "ops@example.com",
    ):
        assert secret not in text


@pytest.mark.parametrize(
    "bad",
    [
        {"NETSIGHT_SMTP_HOST": "smtp.example.com"},  # no sender address
        {
            "NETSIGHT_SMTP_HOST": "smtp.example.com",
            "NETSIGHT_SMTP_FROM": "a@b.co",
            "NETSIGHT_SMTP_TLS": "none",
        },
        {"NETSIGHT_PUSH_GATEWAY_URL": "http://push.example.com/x"},
        {"NETSIGHT_NOTIFY_EMAIL_TO": "nope"},
        {"NETSIGHT_NOTIFY_MIN_SEVERITY": "urgent"},
        {"NETSIGHT_PUBLIC_BASE_URL": "http://netsight.example.com"},
        {"NETSIGHT_EVALUATION_INTERVAL_SECONDS": "5"},
    ],
)
def test_invalid_channel_configuration_fails_start_up(bad: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        build({**ON, **bad})


# --- scheduling -------------------------------------------------------------------------------------


class CountingRunner:
    def __init__(self, stop: asyncio.Event, *, stop_after: int, fail_first: bool = False) -> None:
        self.stop = stop
        self.stop_after = stop_after
        self.fail_first = fail_first
        self.cycles = 0

    async def run_cycle(self) -> Any:
        self.cycles += 1
        if self.cycles >= self.stop_after:
            self.stop.set()
        if self.fail_first and self.cycles == 1:
            raise RuntimeError("cycle blew up postgresql://u:pw@h/db")


@pytest.mark.asyncio
async def test_the_scheduler_runs_until_stopped_and_not_one_cycle_more() -> None:
    stop = asyncio.Event()
    runner = CountingRunner(stop, stop_after=3)
    await asyncio.wait_for(run_scheduler(runner, 0.01, stop), timeout=5)
    assert runner.cycles == 3


@pytest.mark.asyncio
async def test_a_failing_cycle_is_contained_and_the_next_one_runs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    stop = asyncio.Event()
    runner = CountingRunner(stop, stop_after=2, fail_first=True)
    await asyncio.wait_for(run_scheduler(runner, 0.01, stop), timeout=5)
    assert runner.cycles == 2
    assert "pw@h" not in caplog.text


@pytest.mark.asyncio
async def test_stopping_during_the_wait_returns_promptly_without_another_cycle() -> None:
    stop = asyncio.Event()
    runner = CountingRunner(stop, stop_after=10_000)
    task = asyncio.create_task(run_scheduler(runner, 3600, stop))
    await asyncio.sleep(0.05)
    stop.set()
    await asyncio.wait_for(task, timeout=2)
    assert runner.cycles == 1


@pytest.mark.asyncio
async def test_an_already_set_stop_runs_no_cycle() -> None:
    stop = asyncio.Event()
    stop.set()
    runner = CountingRunner(stop, stop_after=1)
    await asyncio.wait_for(run_scheduler(runner, 0.01, stop), timeout=5)
    assert runner.cycles == 0


# --- application lifespan ---------------------------------------------------------------------------


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in (
        "NETSIGHT_EVALUATION_ENABLED",
        "DATABASE_URL",
        "NETSIGHT_EVALUATION_INTERVAL_SECONDS",
    ):
        monkeypatch.delenv(name, raising=False)
    yield


def test_the_application_starts_no_evaluator_by_default(clean_env: None) -> None:
    with TestClient(main.app) as client:
        assert client.get("/api/v1/health").status_code == 200
        assert main.app.state.evaluation_task is None


def test_an_enabled_but_unbuildable_evaluator_stops_the_application_starting(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NETSIGHT_EVALUATION_ENABLED", "1")
    with pytest.raises(ValueError, match="DATABASE_URL"), TestClient(main.app):
        pass


def test_an_enabled_evaluator_runs_in_the_background_and_is_stopped_at_shutdown(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    cycles: list[int] = []

    class FakeRunner:
        async def run_cycle(self) -> Any:
            cycles.append(1)

    fake = EvaluationService(runner=FakeRunner(), interval_seconds=30, channels=())  # type: ignore[arg-type]
    monkeypatch.setattr(main, "build_evaluation_service", lambda **_kw: fake)
    with TestClient(main.app):
        task = main.app.state.evaluation_task
        assert task is not None
        deadline = time.monotonic() + 5
        while not cycles and time.monotonic() < deadline:
            time.sleep(0.01)
        assert cycles and not task.done()
    assert task.done() and not task.cancelled()
    assert main.app.state.evaluation_task is None
