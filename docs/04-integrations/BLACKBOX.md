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

## Multi-location probe sources and sessions (S7 Step 4)

A **probe source** is a Prometheus Blackbox exporter deployed at a known location. Config (environment only):

| Variable | Meaning |
| --- | --- |
| `BLACKBOX_LOCATION` | Location of the API host's own prober (`cloud-external`, `user-lan`, `server-vlan`, `branch`, `wifi`, `remote-site`); unset or unrecognised = unlocated. |
| `BLACKBOX_EXPORTER_SOURCES` | Comma-separated `location=url` pairs, one exporter per location (first wins). A URL must be http(s) with a host and no credentials, query, fragment or path; an invalid pair is dropped (counted in the log, never echoed). Prefer `https`: a plain `http://` URL is honoured but logged as a warning (count only, never the URL). Only honoured when `BLACKBOX_ALLOWED_TARGETS` is set. |
| `BLACKBOX_ALLOWED_TARGETS` | Operator-chosen names and addresses (comma separated) that may ever be probed. Validated when loaded: each entry must be letters, digits and `. _ : -`, start and end with a letter or digit, have no `..` and be at most 253 characters; wildcards, CIDR blocks, URLs, userinfo, paths, spaces and non-ASCII are dropped and counted in the log (never echoed), at most 256 entries are kept. Fail closed: nothing valid = no probing at all. IPv6 literals must not start or end with `:`. |
| `BLACKBOX_TIMEOUT_SECONDS` | Per-probe bound (0.1-30 s, default 5). For an exporter source it is also the overall wall-clock deadline of one probe, so a source that trickles bytes cannot hold a run open. Keep it above the exporter modules' own `timeout`. |
| `NETSIGHT_DIAGNOSTIC_SESSIONS_DAILY_CAP` | Sessions stored per 24 hours (1 to 1 000 000, default 5000). Once reached the run is still answered but `stored` is `false` (audited with `not_stored_reason: daily-cap`); a warning is logged from 80%. An invalid value fails closed: nothing is stored (`cap-misconfigured`). The cap is soft (count then insert are separate statements, so concurrent runs can overshoot slightly). |

`adapters/blackbox_exporter.py` asks each exporter for `icmp`, `tcp` (443), `http` and `https` via `GET /probe?module=...&target=...` (fixed modules `icmp`, `tcp_connect`, `http_2xx`); other checks come from the local prober only, so a run holds at most 12 local checks plus 4 per exporter location (<= 64). Properties: the exporter URL is operator configuration (the request can never steer which server is contacted), only allow-listed, well-formed targets are sent, no redirects, no environment proxies, identity encoding, a 1 MiB response cap and a per-request timeout. An exporter that errors, times out or returns nothing usable is `unknown` (never a failed target); `probe_success 0` is a real `fail`. Nothing the exporter returns is echoed into a result. No source for a location = that location is `not-connected`.

### Exporter-side requirements and network policy

Netsight cannot see or change how an exporter behaves, so these are requirements on the exporter deployment (reference config: `infrastructure/blackbox/blackbox.yml`, pinned by a test):

- **Redirects.** The exporter, not Netsight, follows HTTP redirects while probing. `http_2xx` MUST set `no_follow_redirects: true`; otherwise an allow-listed web server could bounce the probe to an address that was never allow-listed (cloud metadata, an internal admin interface) from the exporter's network position. Netsight itself never follows redirects when talking to the exporter. The modules Netsight asks for are exactly `icmp`, `tcp_connect` and `http_2xx` (`REQUIRED_EXPORTER_MODULES`); anything else is never requested.
- **Egress.** Run each exporter on a segment that can reach only what it is meant to probe (the location it represents). Deny its access to cloud metadata addresses (`169.254.169.254`), management planes, the database and other exporters; allow outbound only to the allow-listed targets' ports if the platform can express that.
- **Ingress.** Bind the exporter to an internal interface and allow `GET /probe` only from the Netsight API host(s). It carries no authentication in this slice, so network policy (or mTLS at a proxy) is the control; never expose it to the Internet.
- **Transport.** Use `https` between Netsight and the exporter where the exporter or its proxy can terminate TLS.
- **Timeouts.** Set the module `timeout` below `BLACKBOX_TIMEOUT_SECONDS` so a probe finishes before Netsight's deadline.

### Free text and retention

The target and the optional symptom are free text stored with the session. The `/diagnostics` form warns not to paste secrets or personal data; the text cannot be screened. The session **retention period is a pending human decision** (see `docs/06-data/DATA-RETENTION-MATRIX.md`): no period is set and no prune path is built.

A finished run is stored as an immutable **session** (PostgreSQL, migration 0004; `GET /api/v1/diagnostics`, `GET /api/v1/diagnostics/{id}`, UI `/diagnostics/[id]`). See `ROOT-CAUSE-ENGINE.md` for the location, cause, change and path rules. The session reads need `diagnostics:read` (Admin, Network Engineer, Security Analyst, Technician; Management and Auditor have none), are rate limited and bounded. Incident changes are stored as references only (id, severity, time); their titles are joined at read time for callers holding `incidents:read` and otherwise replaced by a placeholder.

Rollback: unset `BLACKBOX_EXPORTER_SOURCES` / `BLACKBOX_LOCATION` to return to the single local prober; unset `DATABASE_URL` for the session endpoints to answer `not-connected` (new runs report `stored: false`); migration 0004 down drops the table (guarded, destructive).

## Known limitations / follow-ups

- ICMP is not implemented (needs a privileged or delegated prober); it is an explicit `unknown`.
- The client probes default ports (`tcp`/`https` 443, `http` 80); a per-request port selector is a
  follow-up.
- Baselines and dependency sources are not wired yet; those checks answer `unknown`. The UI offers no
  vantage selector: provenance is the deployment's (`BLACKBOX_VANTAGE`, `BLACKBOX_LOCATION`, exporter sources).
- Exporter DNS and non-default ports are not probed (an exporter `dns` module probes a resolver, not name
  resolution of the target); the exporter modules are fixed names that must exist in each exporter's config.
- Unlocated checks (a prober with no `BLACKBOX_LOCATION`) are attributed to none of the six location rows; the session page says so and lists them under Checks.
- Path resolution reads one NetBox device page (the adapter does not paginate devices): a target beyond the
  first page reads as "not in the topology" (path `unknown`), never as a guess.

## Rollback

Unset `BLACKBOX_ALLOWED_TARGETS` to disable probing (the endpoint stays up and answers
`not-connected`), or remove `app.include_router(diagnostic_router, ...)` from `main.py` to withdraw
the endpoint entirely. No migration or stored state is involved.
