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
the run reports where checks actually ran). Deferred: internal/external vantage selection
(multi-prober), the path view, and dependency/recent-change evidence sources — see
`docs/04-integrations/BLACKBOX.md`.

## Configuration
Device config versions, diffs, change timeline, drift, correlation to incidents.

## Ask Netsight
Conversation with visible evidence drawer. Never hide source freshness.

## Reports
Templates, scheduler, history, exports.

## Administration
Integrations, sites, roles, provider config, policies, retention, AI provider, audit.
