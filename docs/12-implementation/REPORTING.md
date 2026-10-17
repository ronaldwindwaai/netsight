# Reporting Engine

## Report types
Operational, security, WAN/SLA, traffic, incidents, configuration, capacity, inventory.

## WAN/SLA (implemented in Step 5)
The monthly WAN SLA and the ISP-dispute evidence export are served by `GET /api/v1/internet/sla` and `/internet/sla/export` (`internet:read` / `internet:export`),
computed deterministically from stored probe samples; see `INTERNET-WAN.md`. They are synchronous and bounded (not a generated-and-archived report): no scheduler,
snapshot or delivery exists for them yet.

## Architecture
Report definition -> data queries -> snapshot -> renderer -> delivery/archive.

Long reports execute asynchronously.

## Security
Report access follows RBAC and source scope. Generated downloads use short-lived authenticated links. Email should not attach sensitive full-detail reports by default unless policy permits.

## Reports catalog / WAN viewer (stage 1)

`/reports` now lists implemented report templates for which the session holds both
`reports:read` and the underlying evidence permission. `/reports/wan-sla` presents
the existing source-backed monthly SLA read, with the same bounded month range,
sampling gaps, redactions and unknown states as `/internet`. It requires
`internet:read` as well as `reports:read` at the page boundary; the backend still
independently checks the underlying evidence request. Unknown template IDs are 404,
not interpolated into vendor/API paths. Report metadata contains no invented
metrics or simulated generated reports.

CSV/JSON links use the existing authenticated `/internet/export` proxy and
`internet:export` backend gate, bounded export and read-audit path. Printing/saving
PDF uses the browser's native print flow after a user click, and is disabled for
unreadable evidence. Print CSS omits session/navigation menus, export links and
interactive controls. Month selection stays inside the report viewer; the original
Internet page's form action remains unchanged. Report HTML and downloads use the
existing dynamic/no-store source reads; the PWA worker never stores them offline.

This is an on-demand live report view, not an archived snapshot, signed artifact,
scheduler or delivery job. No report metadata/evidence is persisted, so no new
retention period or data ownership is invented. Operational/security/traffic/
incident/configuration/capacity/inventory reports, asynchronous long jobs,
scheduling/delivery/archive, authenticated expiring artifact links and a dedicated
PDF renderer remain subsequent reporting stages.

Validation: catalog permission/identifier unit tests; components for catalog
access, explicit print action and month/export navigation; full component suite,
TypeScript/ESLint, production build and Chromium catalog/viewer/mobile/error checks.
Browser checks use the real unconfigured WAN API state and do not create samples
or imply that a real monitored estate has been validated. A Reports-specific
approved visual reference and independent review are still required for final
acceptance. No source, notification or production write occurs.

Rollback: remove the Reports menu/routes/catalog/print control and revert the
optional `monthAction` extension on the shared SLA panel. The existing `/internet`
read/export behavior and backend contracts remain unchanged. No migration.
