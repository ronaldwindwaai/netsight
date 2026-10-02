# Integration Architecture

## Adapter pattern

The frontend and core domain must not depend directly on vendor response shapes.

```text
Source API -> Adapter -> Canonical Contract -> Domain Service -> API/UI
```

Each adapter owns:
- authentication to the source;
- retries/timeouts;
- pagination;
- source-specific mapping;
- version compatibility;
- freshness metadata;
- source health;
- rate limits;
- contract tests.

## Read/write separation

Where a source supports mutation, use separate credentials and code paths for:
- read;
- approved write.

Write credentials are never used for ordinary dashboards.

## Source identifiers

Keep source-native IDs as aliases, never as the only platform identity.

## Error model

Adapters return:
- success;
- partial;
- stale;
- unavailable;
- forbidden;
- invalid-source-data.

They do not silently return empty results for failed upstream requests.

## Versioning

Adapters expose their own internal interface version. Upstream API changes should be isolated to the adapter.

LibreNMS API version differences are a good example: the platform must not scatter `/api/v0` assumptions across the UI.
