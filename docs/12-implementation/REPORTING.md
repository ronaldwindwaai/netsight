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
