"""Demo-only ASGI entry: the real API with a seeded, process-local incident store.

`netsight_api.main:app` shows no incidents unless a PostgreSQL store is configured. For local UI
review `scripts/demo-local.py` starts this module instead. It imports the unmodified application and
overrides exactly one dependency, `get_optional_incident_store`, with an in-memory repository filled
with fixture incidents (every lifecycle state, long text, an old and a fresh timeline). Nothing here
is imported by production code, no credentials are involved, and the data is lost on restart.

    cd apps/api && NETSIGHT_DEMO=1 python -m uvicorn demo_app:build_app --factory --app-dir tests/e2e

Normally started by `scripts/demo-local.py`. Importing this module changes nothing: the override is
installed only by `build_app()` / `install()`, which refuse to run unless `NETSIGHT_DEMO=1`.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

from fastapi import FastAPI

from netsight_api.incident_deps import get_optional_incident_store
from netsight_api.schemas import IncidentResolutionInput
from netsight_api.storage.memory import InMemoryIncidentRepository

OPERATOR = "local:demo.admin"
COLLEAGUE = "local:demo.operator"
LONG_TITLE = (
    "Intermittent packet loss between the branch WAN edge and the data centre spine after the "
    "scheduled firmware window, affecting voice and the finance VPN for several sites at once"
)


class _Clock:
    """A settable clock so seeded history can be back-dated; later requests use real time."""

    def __init__(self) -> None:
        self.moment: datetime | None = None

    def __call__(self) -> datetime:
        return self.moment or datetime.now(UTC)


def _resolution(restored: datetime) -> IncidentResolutionInput:
    return IncidentResolutionInput(
        summary="Rolled the edge router back to the previous firmware and confirmed the tunnel is stable.",
        root_cause_status="determined",
        root_cause="Firmware 4.2.1 renegotiated the IPsec lifetime every 90 seconds under load.",
        impact="Voice quality degraded for about 40 minutes at three branch sites.",
        restored_at=restored,
        follow_up_actions=[
            "Pin the firmware version in the change calendar",
            "Alert on tunnel flaps above 3 per hour",
        ],
    )


def seed(repo: InMemoryIncidentRepository, clock: _Clock, now: datetime) -> None:
    """Create fixture incidents with history spread over the last two weeks."""

    def at(delta: timedelta) -> None:
        clock.moment = now - delta

    at(timedelta(days=13))
    old = repo.create_incident(
        title="Core switch fan failure", severity="medium", actor_id=OPERATOR
    )
    for step, days in (("acknowledged", 12.9), ("investigating", 12.8), ("mitigated", 12.5)):
        at(timedelta(days=days))
        repo.transition_state(old.id, to_state=step, actor_id=OPERATOR)  # type: ignore[arg-type]
    at(timedelta(days=12))
    repo.transition_state(
        old.id, to_state="resolved", actor_id=OPERATOR, resolution=_resolution(clock())
    )
    at(timedelta(days=11))
    repo.transition_state(old.id, to_state="closed", actor_id=OPERATOR)

    at(timedelta(hours=26))
    long_one = repo.create_incident(title=LONG_TITLE, severity="critical", actor_id=OPERATOR)
    at(timedelta(hours=25))
    repo.transition_state(long_one.id, to_state="acknowledged", actor_id=OPERATOR)
    repo.set_assignee(long_one.id, assignee_id=COLLEAGUE, actor_id=OPERATOR)
    at(timedelta(hours=24))
    repo.transition_state(long_one.id, to_state="investigating", actor_id=COLLEAGUE)
    repo.append_event(
        long_one.id,
        kind="comment",
        actor_id=COLLEAGUE,
        message=("Capture shows retransmits on the tunnel. " * 12).strip(),
    )
    repo.append_event(
        long_one.id,
        kind="comment",
        actor_id=OPERATOR,
        message="<b>Not markup</b> https://example.test/very/long/path/that/should/wrap/and/not/overflow/the/card?query=1234567890",
    )

    at(timedelta(hours=5))
    mitigated = repo.create_incident(
        title="Edge router EDGE-RT-02 unreachable", severity="high", actor_id=OPERATOR
    )
    for step in ("acknowledged", "investigating", "mitigated"):
        at(timedelta(hours=4))
        repo.transition_state(mitigated.id, to_state=step, actor_id=OPERATOR)  # type: ignore[arg-type]

    at(timedelta(minutes=14))
    repo.create_incident(title="Wi-Fi controller high CPU", severity="low", actor_id=OPERATOR)
    at(timedelta(minutes=3))
    repo.create_incident(title="Unexpected device on VLAN 20", severity="medium", actor_id=OPERATOR)
    clock.moment = None


DEMO_ENV = "NETSIGHT_DEMO"


def _require_demo() -> None:
    if os.environ.get(DEMO_ENV) != "1":
        raise RuntimeError(f"demo_app is demo-only; refusing to run without {DEMO_ENV}=1")


def install(app: FastAPI) -> FastAPI:
    """Seed an in-memory store and override the incident dependency on `app`; returns the app."""
    _require_demo()
    clock = _Clock()
    repo = InMemoryIncidentRepository(clock=clock)
    seed(repo, clock, datetime.now(UTC))
    app.dependency_overrides[get_optional_incident_store] = lambda: repo
    return app


def uninstall(app: FastAPI) -> None:
    app.dependency_overrides.pop(get_optional_incident_store, None)


def build_app() -> FastAPI:
    """ASGI factory for uvicorn (`--factory`): the real application with the demo store installed."""
    from netsight_api.main import app

    install(app)
    return app
