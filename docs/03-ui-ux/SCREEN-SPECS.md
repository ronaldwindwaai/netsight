# Screen Specifications

## Overview
Widgets: health, WAN, security, devices, users, top traffic, incidents, source freshness.

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
