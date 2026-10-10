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
| `BLACKBOX_VANTAGE` | Default vantage label stamped on checks (e.g. `internal`, `internet`). |
| `BLACKBOX_TIMEOUT_SECONDS` | Per-probe timeout, clamped to `[0.1, 30]`; default `5`. |

Security posture:

- **Deny by default / SSRF.** The client contacts only targets on the operator allow-list. Any other
  target answers `unknown` ("the target is not in the configured probe allow-list") without opening a
  connection. No response or log line carries the allow-list, a connection string or a driver message.
- **Bounded.** Every network operation is wrapped in a timeout, the caller caps the whole run at 20 s, and
  the endpoint is rate limited per identity.
- **Honest states.** ICMP is reported `unknown` (no portable unprivileged implementation) rather than
  guessed; checks that need a source Netsight does not have connected also answer `unknown`.

## Known limitations / follow-ups

- ICMP is not implemented (needs a privileged or delegated prober); it is an explicit `unknown`.
- The client probes default ports (`tcp`/`https` 443, `http` 80); a per-request port selector is a
  follow-up.
- Multi-vantage deployment (several probe nodes) and baselines/dependency/recent-change sources are
  not wired yet; those checks answer `unknown`.

## Rollback

Unset `BLACKBOX_ALLOWED_TARGETS` to disable probing (the endpoint stays up and answers
`not-connected`), or remove `app.include_router(diagnostic_router, ...)` from `main.py` to withdraw
the endpoint entirely. No migration or stored state is involved.
