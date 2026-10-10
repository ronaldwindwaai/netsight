"""Growth control for stored diagnostic sessions (security follow-up M: unbounded growth).

Sessions are immutable and there is no prune path yet, so the table only grows. A configurable
daily cap stops storing (never running) once reached, and a warning is logged as the cap nears.
The cap is soft: count-then-insert is not atomic, so concurrent runs can overshoot by a few.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

import pytest
from alerting_support import Caller, audit_records
from diagnostic_support import make_session
from test_diagnostic_sessions_api import (  # noqa: F401  (_wiring is the autouse fixture)
    BASE,
    _wiring,
    body,
    external_only_failure,
)

from netsight_api.diagnostic_growth import (
    DAILY_CAP_ENV,
    DEFAULT_DAILY_CAP,
    MAX_DAILY_CAP,
    read_daily_cap,
)
from netsight_api.storage.diagnostics import InMemoryDiagnosticSessionRepository

T0 = datetime(2026, 10, 10, 8, 0, tzinfo=UTC)


# --- configuration ---------------------------------------------------------------------------------


def test_the_default_applies_when_unset_or_blank() -> None:
    assert read_daily_cap({}) == DEFAULT_DAILY_CAP
    assert read_daily_cap({DAILY_CAP_ENV: "  "}) == DEFAULT_DAILY_CAP


@pytest.mark.parametrize(
    ("raw", "expected"), [("1", 1), (" 250 ", 250), (str(MAX_DAILY_CAP), MAX_DAILY_CAP)]
)
def test_a_valid_cap_is_read(raw: str, expected: int) -> None:
    assert read_daily_cap({DAILY_CAP_ENV: raw}) == expected


@pytest.mark.parametrize("raw", ["0", "-5", "abc", "1.5", "1e3", str(MAX_DAILY_CAP + 1), "٣"])
def test_an_invalid_cap_is_never_read_as_off(raw: str) -> None:
    assert read_daily_cap({DAILY_CAP_ENV: raw}) is None


# --- store count -----------------------------------------------------------------------------------


def test_the_store_counts_sessions_completed_since_a_time() -> None:
    store = InMemoryDiagnosticSessionRepository()
    for number, minutes in enumerate((0, 30, 90), start=1):
        store.save_session(
            make_session(number, completed_at=T0 + timedelta(minutes=minutes)), actor_id="u"
        )
    assert store.count_sessions_since(T0) == 3
    assert store.count_sessions_since(T0 + timedelta(minutes=30)) == 2
    assert store.count_sessions_since(T0 + timedelta(hours=3)) == 0


# --- over HTTP -------------------------------------------------------------------------------------


def post_runs(count: int) -> list[dict[str, object]]:
    caller = Caller("administrator")
    return [caller.post(BASE, body()).json() for _ in range(count)]


def test_once_the_daily_cap_is_reached_runs_still_answer_but_are_not_stored(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)
    monkeypatch.setenv(DAILY_CAP_ENV, "2")
    external_only_failure()
    first, second, third = post_runs(3)
    assert (first["stored"], second["stored"], third["stored"]) == (True, True, False)
    assert third["state"] == "ok" and third["run"] is not None
    last = [r for r in audit_records(caplog) if r["action"] == "diagnostic.run"][-1]
    assert last["stored"] is False and last["not_stored_reason"] == "daily-cap"
    assert any("daily cap" in record.getMessage() for record in caplog.records)


def test_a_warning_is_logged_as_the_cap_nears(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)
    monkeypatch.setenv(DAILY_CAP_ENV, "5")
    external_only_failure()
    post_runs(4)  # at most three rows existed before any of these runs
    assert not any("nearing" in r.getMessage() for r in caplog.records)
    post_runs(1)  # four rows already exist: 80% of 5
    assert any("nearing" in r.getMessage() for r in caplog.records)


def test_an_invalid_cap_fails_closed_and_stores_nothing(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)
    monkeypatch.setenv(DAILY_CAP_ENV, "unlimited")
    external_only_failure()
    [posted] = post_runs(1)
    assert posted["state"] == "ok" and posted["stored"] is False
    last = [r for r in audit_records(caplog) if r["action"] == "diagnostic.run"][-1]
    assert last["not_stored_reason"] == "cap-misconfigured"


def test_an_unreadable_count_does_not_lose_the_run(monkeypatch: pytest.MonkeyPatch) -> None:
    from test_diagnostic_sessions_api import ExplodingStore

    from netsight_api.diagnostic_context import get_optional_diagnostic_session_store
    from netsight_api.main import app

    external_only_failure()
    app.dependency_overrides[get_optional_diagnostic_session_store] = lambda: ExplodingStore()
    [posted] = post_runs(1)
    assert posted["state"] == "ok" and posted["stored"] is False
