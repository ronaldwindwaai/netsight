# Screen Specifications

## Overview
Widgets: health, WAN, security, devices, users, top traffic, incidents, source freshness.

### Internet card and `/internet` (Step 5)
The overview Internet KPI shows real WAN data only: link status in words (Up/Degraded/Down/Failed over), source-reported download/upload rates and utilisation
with their freshness; with no declared link it stays an explicit "Not connected" (as before), "Restricted" when the role cannot read it, and "Unknown" when the
read failed. A stale reading is labelled and draws no gauge. Only a real reading links to `/internet`.

`/internet` (sidebar entry gated by `internet:read`; **design gap**: no approved design exists for this screen, so the layout is derived from this spec and the
shell only, DESIGN-INVENTORY): a header, a failover card (always labelled inferred, link status only), one card per declared link (name, primary/backup, status
badge with icon and word, "configured" ISP/gateway/probe location, then three blocks: Interface from LibreNMS, Quality from stored probe samples, Availability
over the last 24 h, each naming its source and freshness), and a monthly SLA panel (UTC month picker limited to the current month and the 24 before it, a
per-link table of uptime, down, degraded, unknown (no samples), outages, time sampled and violations, and read-only CSV/JSON evidence downloads for
`internet:export`). State matrix: loading (`loading.tsx`), empty (answer without links, never read as healthy), not-connected (no link declared / no sample
store, per page and per block), unknown, partial (named blocks), stale (labelled per block with a banner), permission denied, unauthenticated, rate limited and
error. Every missing value reads "Not reported", never zero; operator and telemetry text is rendered as data; colour is never the only indicator.
A role without `internet:read_detail` sees "Restricted" (not "Not reported") for the ISP, gateway, public IP and throughput, with one notice naming
the permission; the overview card then reads "Throughput restricted for your role". The SLA panel warns per link when the evidence export lists only
the first windows of the month (`windows_truncated`), shows "Not reported" for a missing outage count, and says so when the month has only just
started (an empty period, not a perfect month).

## Network Map
Full-width topology, health legend, filters, search, quick device drawer.

## Devices
Virtualised/filterable table. Columns configurable. Saved views. Device detail tabs: Summary, Interfaces, Traffic, Security, Config, Incidents, Diagnostics.

## Users
Identity confidence, current devices/IPs, activity, traffic, security, history.

## Traffic
Time range, scope, top talkers, apps, destinations, upload/download, anomalous flows. Drill to user/device.

## Security Centre
Severity overview, correlated detections, endpoint/network evidence, investigation queue.

## Incidents
List/board + detail. Detail includes evidence, impact, timeline, AI assessment, actions, ownership, post-incident.

## Alerts
Active alerts, rule builder, notification routing, maintenance windows, escalation.

## Diagnostics
Guided "Why?" workflows. Device/service selector, internal/external probes, path, dependency status, findings.
Implemented in S7-3: `/diagnostics` runs a bounded, read-only check set against an operator
allow-list from the deployment's single vantage, with an honest state matrix and a conservative
probable-cause narrative (no vantage selector is offered because a single prober serves one vantage;
the run reports where checks actually ran). Step 4 adds stored sessions: `/diagnostics` lists
recent sessions (newest first, paged; states: not-connected, unknown, empty, permission, error) and a
run offers "Open stored session"; `/diagnostics/[id]` is a read-only session page with the probable
cause (confidence, Observed/Inferred/Unknown evidence lines), results for all six probe locations
(unconfigured = Not connected, never passing), the User -> AP -> Access switch -> Core -> Firewall ->
Server path from explicit NetBox cables (unknown hops stay unknown, the suspected tier is marked
"Suspected (inferred)"), recent changes phrased "May correlate", the checks, and the full state matrix:
loading (`loading.tsx`), empty (no checks), not-connected, unknown, partial (named sections), stale
(snapshot older than 15 minutes), permission, unauthenticated, not found, rate limited and API errors.
It has no button, form or remediation control; all session text is rendered as data. Review fix pass: the run form warns (next to the target and symptom inputs) not to paste secrets or personal data because both are stored with the session; incident changes show kind, severity and time with the title replaced by a "withheld" note unless the API revealed it (it does only for `incidents:read` holders); checks from a prober with no configured location are not in any location row, and the location card says they are listed under Checks. Sessions are for roles holding `diagnostics:read` (Admin, Network Engineer, Security Analyst, Technician): the sidebar hides Diagnostics for other roles and `/diagnostics` and `/diagnostics/[id]` show an access-denied surface (no form, no API call). Deferred:
dependency/baseline evidence sources and configuration-change correlation — see
`docs/04-integrations/BLACKBOX.md`.

## Configuration
Device config versions, diffs, change timeline, drift, correlation to incidents.

## Ask Netsight
Conversation with visible evidence drawer. Never hide source freshness.

## Reports
Templates, scheduler, history, exports.

## Administration
Integrations, sites, roles, provider config, policies, retention, AI provider, audit.
