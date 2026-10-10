# Blackbox Probe Integration

Purpose: independent service probing.

Probe types:
- ICMP;
- DNS;
- TCP;
- HTTP/HTTPS.

Deploy from multiple vantage points to separate host/service failures from path/firewall/external failures.

## Implementation status (S7-2)

A bounded, allowlisted, read-only probe client lives at
`apps/api/src/netsight_api/adapters/blackbox.py`. It is driven by the diagnostic run endpoint
`POST /api/v1/diagnostics` (`diagnostic_routes.py`), which assembles a canonical `DiagnosticRun`
through the pure inference in `diagnostics.py` (see `docs/12-implementation/ROOT-CAUSE-ENGINE.md`).

Configuration (environment only, never source):

| Variable | Meaning |
| --- | --- |
| `BLACKBOX_ALLOWED_TARGETS` | Comma-separated allow-list of probe targets. Empty or unset means no probe capability: the endpoint answers an explicit `not-connected` state. |
| `BLACKBOX_VANTAGE` | The vantage this prober is deployed at (e.g. `internal`, `internet`), stamped on every check it runs. A request for a different vantage is answered `unknown` — provenance is never the caller's to choose. |
| `BLACKBOX_TIMEOUT_SECONDS` | Per-probe timeout, clamped to `[0.1, 30]`; default `5`. |

Security posture:

- **Deny by default / SSRF.** The client contacts only targets on the operator allow-list. Any other
  target answers `unknown` ("the target is not in the configured probe allow-list") without opening a
  connection. No response or log line carries the allow-list, a connection string or a driver message.
- **Bounded.** Every network operation is wrapped in a timeout, the caller caps the whole run at 20 s, and
  the endpoint is rate limited per identity.
- **Honest states.** ICMP is reported `unknown` (no portable unprivileged implementation) rather than
  guessed; checks that need a source Netsight does not have connected also answer `unknown`.
- **Truthful provenance.** A check's `vantage` is where the probe actually ran, taken from this
  prober's configuration and never from the request. A request naming a vantage this prober does not
  serve is answered `unknown` ("no prober is connected for the requested vantage"); the run reports
  the vantage the checks ran from.

## UI (S7-3)

The read-only diagnostics page lives at `/diagnostics` (`apps/web/src/app/(dashboard)/diagnostics`).
An operator enters a target, an optional symptom and a set of checks, and the page runs the endpoint
through a server action (`createDiagnosticRun`) that attaches the session cookie and CSRF token
server-side — a browser can never reach the loopback API directly. The form sends no vantage: the
deployment decides where probes run and the result reports it, so no unserved vantage can be claimed.
The page renders the full state matrix honestly: idle, running, `not-connected`, `unknown`, ok
(numbered check list with PASS/FAIL/UNKNOWN pills, probable-cause card with a confidence badge,
contradictions/unknowns/alternatives, and recommended next checks), plus unauthenticated / forbidden /
rate-limited / API errors. When no fault domain is named the copy reflects what happened — failures
that did not narrow, a symptom that was not reproduced, or checks that could not be answered — rather
than calling every non-result "no fault". Follow-up actions on the target are shown as disabled,
approval-gated controls; no write is wired in this slice. The device detail "Diagnostics" tab links
here with the device hostname pre-filled (a device with no recorded hostname shows a distinct
"nothing to diagnose" state).

## Known limitations / follow-ups

- ICMP is not implemented (needs a privileged or delegated prober); it is an explicit `unknown`.
- The client probes default ports (`tcp`/`https` 443, `http` 80); a per-request port selector is a
  follow-up.
- Multi-vantage deployment (several probe nodes) and baselines/dependency/recent-change sources are
  not wired yet; those checks answer `unknown`. Until then a single prober serves exactly one vantage
  (`BLACKBOX_VANTAGE`), and the UI offers no vantage selector.
- A hop-by-hop network path view and per-check "run at" column are deferred; each check row shows
  its own `observed_at` and the run header shows completion time. The `Recent changes` panel is an
  honest `not-connected` surface until a change source exists.

## Rollback

Unset `BLACKBOX_ALLOWED_TARGETS` to disable probing (the endpoint stays up and answers
`not-connected`), or remove `app.include_router(diagnostic_router, ...)` from `main.py` to withdraw
the endpoint entirely. No migration or stored state is involved.
