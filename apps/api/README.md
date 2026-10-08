# Netsight API

FastAPI service. The FS-001 read-only endpoints are under `/api/v1`.

This service is not production-authenticated yet. Do not expose it publicly until Epic E01 identity/session/RBAC controls are implemented.

For local development only, the temporary identity bridge requires both:

- `NETSIGHT_ENV=development`
- `NETSIGHT_ENABLE_DEV_IDENTITY=true`

The bridge remains disabled by default. It grants an administrator identity to every
request, so it is an ambient credential: state-changing routes still require a non-empty
`X-CSRF-Token` header and, when the browser sends `Origin`/`Referer`, an origin listed in
`NETSIGHT_ALLOWED_ORIGINS` (for example `http://localhost:3000`). Never enable it outside
local development. LibreNMS also requires
`LIBRENMS_BASE_URL` and `LIBRENMS_TOKEN`; the token is sent server-to-server as
an `Authorization: Bearer` credential and is never returned by the API.
