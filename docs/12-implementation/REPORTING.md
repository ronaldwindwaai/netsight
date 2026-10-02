# Reporting Engine

## Report types
Operational, security, WAN/SLA, traffic, incidents, configuration, capacity, inventory.

## Architecture
Report definition -> data queries -> snapshot -> renderer -> delivery/archive.

Long reports execute asynchronously.

## Security
Report access follows RBAC and source scope. Generated downloads use short-lived authenticated links. Email should not attach sensitive full-detail reports by default unless policy permits.
