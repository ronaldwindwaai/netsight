# API Guidelines

Prefix: `/api/v1`

## Principles
- resource-oriented;
- typed schemas;
- explicit error envelope;
- pagination;
- idempotency for write actions;
- correlation IDs;
- backend authz;
- stable canonical models;
- no source credentials returned.

## Error envelope

```json
{
  "error": {
    "code": "SOURCE_UNAVAILABLE",
    "message": "Traffic source is unavailable",
    "correlation_id": "..."
  }
}
```

## Freshness

Telemetry responses should include evidence/source freshness where relevant.

## High-cost queries
Require bounded time ranges and enforce query limits.

## Remote actions
Never expose generic command execution. Use named action endpoints and Action Requests.
