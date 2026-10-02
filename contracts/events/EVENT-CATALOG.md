# Event Catalog

Initial domain events:
- device.discovered
- device.status.changed
- telemetry.source.stale
- alert.opened
- alert.acknowledged
- incident.created
- incident.updated
- anomaly.detected
- configuration.changed
- identity.correlation.updated
- diagnostic.completed
- action.proposed
- action.approved
- action.executed
- action.verified
- notification.sent
- authentication.succeeded
- authentication.failed
- role.changed

Events must include event ID, timestamp, correlation ID, actor where applicable and entity references.
