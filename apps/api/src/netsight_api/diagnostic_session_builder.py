"""Assembling a diagnostic session from a finished run and its context (S7 Step 4).

Pure. The session is a snapshot: what each configured location reported, the labelled probable
cause, the explicit-topology path and the known recent changes, all derived from the run and the
context reads so the stored document cannot claim more than they support.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from netsight_api.diagnostic_cause import build_probable_cause
from netsight_api.diagnostic_changes import SourceRead, build_recent_changes
from netsight_api.diagnostic_path import TopologyRead, build_path, resolve_target
from netsight_api.schemas_diagnostic_session import DiagnosticSession, derive_location_results
from netsight_api.schemas_diagnostics import DiagnosticRun

# How far before the end of the run a recorded change is still shown as a possible correlate.
CHANGE_LOOKBACK = timedelta(hours=24)


def change_window(completed_at: datetime) -> tuple[datetime, datetime]:
    return completed_at - CHANGE_LOOKBACK, completed_at


def resolved_target_id(topology: TopologyRead, target: str) -> str | None:
    """The canonical device id of the one topology device the target names, else None."""
    if topology.state != "ok":
        return None
    device = resolve_target(topology.devices, target)
    return None if device is None else device.device_id


def assemble_session(
    *,
    run: DiagnosticRun,
    topology: TopologyRead,
    incidents: SourceRead,
    alerts: SourceRead,
) -> DiagnosticSession:
    locations = derive_location_results(run.checks)
    window_start, window_end = change_window(run.completed_at)
    return DiagnosticSession(
        run=run,
        locations=locations,
        probable_cause=build_probable_cause(run, locations),
        recent_changes=build_recent_changes(
            window_start=window_start,
            window_end=window_end,
            incidents=incidents,
            alerts=alerts,
        ),
        path=build_path(topology, run.target, run.probable_fault_domain),
    )
