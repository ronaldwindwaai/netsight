# Netsight API

FastAPI service. The FS-001 read-only endpoints are under `/api/v1`.

This service is not production-authenticated yet. Do not expose it publicly until Epic E01 identity/session/RBAC controls are implemented.

For local development only, the temporary identity bridge requires both:

- `NETSIGHT_ENV=development`
- `NETSIGHT_ENABLE_DEV_IDENTITY=true`

The bridge remains disabled by default. LibreNMS also requires
`LIBRENMS_BASE_URL` and `LIBRENMS_TOKEN`; the token is sent server-to-server as
an `Authorization: Bearer` credential and is never returned by the API.
