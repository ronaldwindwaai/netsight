# Test Strategy

## Unit
Domain logic, mappings, policies, alert conditions, baseline functions.

## Contract
Every integration adapter against recorded/synthetic upstream responses.

## Integration
API + DB + queue + adapter mock/lab source.

## E2E
Critical operator journeys.

## Security
Auth, RBAC, step-up, CSRF, injection, IDOR/BOLA, rate limits, secret exposure, action workflows.

## Performance
Flow queries, device tables, topology rendering, alert ingestion.

## Resilience
Source unavailable/stale, timeouts, partial data, queue backlog.

## AI evals
See AI eval plan.
