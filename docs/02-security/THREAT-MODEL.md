# Threat Model — Initial STRIDE Analysis

## Assets
- user identities/sessions;
- network topology;
- device inventory;
- traffic metadata;
- security events;
- integration credentials;
- action credentials;
- incident data;
- audit logs;
- configuration history;
- AI knowledge/tools.

## Major threat actors
- external attacker;
- compromised user;
- compromised administrator;
- malicious insider;
- compromised endpoint;
- supply-chain dependency;
- malicious telemetry/log producer;
- compromised integration engine.

## Trust boundaries
See system architecture.

Additional boundary added with the topology surface (S3): the NetBox
pagination URL (`next`) is source-controlled and is followed by the service
with the NetBox token attached — it is validated to the exact configured
origin before use (`adapters/netbox.py:_next_path`). Source-reported device
names cross a second boundary into the browser as inert text.

## Threats and mitigations

### Spoofing
Risk: forged session, OIDC confusion, device/user misattribution.
Mitigation: OIDC validation, tenant/domain restrictions, immutable subject IDs, session security, evidence confidence for network identity.

### Tampering
Risk: modified incidents/config/actions/audit.
Mitigation: RBAC, integrity controls, append-only audit, approvals, versioned configs.

### Repudiation
Risk: admin denies remote change.
Mitigation: authenticated action requests, timestamps, correlation IDs, approval history, immutable audit retention.

### Information disclosure
Risk: traffic metadata/topology/security logs exposed.
Mitigation: least privilege, encrypted transport/storage, field masking, management summaries, secret redaction.
Topology specifics: cross-origin pagination URLs are rejected (SSRF/credential
leak guard), adapter tokens are `repr=False` and never logged, source failures
degrade to an explicit `unknown` state with static error data, and the
`/api/v1/topology` response is validated against the canonical schema before
it leaves the boundary. Regression tests: `test_security_matrix.py`
(hostile pagination origin, hostile node name, token echo).
Traffic specifics: the ClickHouse DSN, user and password are read from the
environment only and excluded from client `repr`, so credentials cannot leak
through logs; flow labels/hostnames are treated as untrusted source text
(passed through as data, never interpreted as markup or instructions); a
failed or schema-invalid flow read degrades to an explicit `unknown` state
with static error data; and the `/api/v1/traffic/*` responses are validated
against the canonical schema before leaving the boundary.
Traffic reads are currently unscoped by site/asset and are not separately
audit-logged. Both are recorded platform follow-ups (ABAC/site scoping and an
audit event for privacy-sensitive reads) awaiting the platform RBAC/audit
slice; deny-by-default still holds because every route requires `traffic:read`.
The adapter also refuses to follow upstream redirects (no credential re-send)
and degrades transport/TLS failures to `UNAVAILABLE`; regression tests pin
both.
Security-events specifics: the Wazuh indexer URL, user, password and CA bundle are read from the environment only and excluded from client `repr`; alert signature/category/address text is untrusted telemetry (length-bounded, passed through as data, rendered as plain text, never interpreted as markup or an AI instruction); `device_id` is only ever null until agent->device mapping exists (no IP inference); the adapter is read-only (`_search` only), verifies TLS, refuses redirects, validates URL and index pattern, and any source failure or contract-invalid row degrades to an explicit `unknown` with static error data. `/api/v1/security/events` requires `security:read` and is validated against `security.schema.json` before leaving the boundary. Security reads are not site-scoped and not audit-logged yet (same platform ABAC/audit follow-ups as traffic).

### Denial of service
Risk: expensive flow queries, diagnostics floods, upstream failures.
Mitigation: rate limits, query budgets, timeouts, async jobs, caching, degradation.
Topology specifics: one request fans out to at most 12 upstream calls (≤10
cable pages × `limit=1000` + 1 NetBox devices page + 1 LibreNMS devices page), each bounded by a 10s timeout;
graphs are capped at 10,000 nodes/edges and fail closed to `unknown`.
Open follow-up: per-IP rate limiting and response caching for `/api/v1/topology`.
Traffic specifics: each traffic request fans out to at most 2 upstream
ClickHouse calls (1 `system.columns` discovery, cached for the lifetime of the
per-request client instance, + 1 data query; ≤3 when a readonly identity forbids
settings and forces one settings-free retry), each bounded by a read timeout and
an explicit window (≤31 days) plus a row limit (≤100 for top-talker/destination,
≤500 for flows). When the identity permits `max_execution_time` it is sent as a
server-side query budget. A source failure never becomes a 5xx and never returns
partial data as if complete.
Open follow-up: per-identity rate limiting (and process-level `system.columns`
caching) for `/api/v1/traffic/*` — the `/traffic` page alone issues three reads
per render, consistent with the existing `/api/v1/topology` rate-limit follow-up.
Security-events specifics: one request issues exactly one indexer `_search` bounded by a window (<=31 days), a row cap (<=500) and a read timeout. Open follow-ups: per-identity rate limiting for `/api/v1/security/events`; a single malformed hit currently degrades the whole read to `unknown` (a `partial` state would be more useful).

### Elevation of privilege
Risk: AI/tool or user obtains write capability.
Mitigation: separate credentials, backend policy, step-up auth, approval, scoped targets.

### Incident routes (S6-2) - threat-model delta
`/api/v1/incidents` adds the first authenticated state-changing API. Status after the S6-2 review fixes:

- **Elevation of privilege / tampering (fixed).** The technician's "Assigned" scope was first checked by an unlocked read before the write, so a reassignment between the check and the write was a time-of-check/time-of-use gap. The store now receives `required_assignee` and compares it with the assignee of the *locked* incident row (`ScopeViolationError` -> 403 audited as `scope`), judged before the state machine so a caller outside the scope learns nothing about the incident. Conformance tests cover the in-memory and PostgreSQL stores; a live-PostgreSQL test reassigns the incident while the technician's write waits on the row lock and proves it is refused and nothing is written. Resolve and reopen stay human-principal only (no AI/service principal can record a root cause); closing is reserved for the full roles.
- **CSRF / cross-site request forgery (hardened).** The session is resolved once per request and the CSRF decision uses that same object; the check fails closed (403) when a session-sourced identity has no session or a human identity has unknown provenance, and the token comparison is byte-safe (a non-ASCII token is an audited 403, not a 500). Cookie-authenticated writes additionally require an `Origin` (else `Referer`) from the configured allow-list (`NETSIGHT_ALLOWED_ORIGINS` plus the origin of `NETSIGHT_PUBLIC_BASE_URL`; the Host header is never trusted because of DNS rebinding); a request with neither header (a non-browser client) is accepted only with a valid token. `SameSite=None` is rejected at start-up unless `NETSIGHT_SESSION_ALLOW_SAME_SITE_NONE=true` and the cookie is Secure.
- **Development identity bridge (hardened; residual risk accepted for local development only).** With `NETSIGHT_ENV=development` and `NETSIGHT_ENABLE_DEV_IDENTITY=true` every request is an administrator with no credential, i.e. an ambient credential a foreign page in the developer's browser could ride. Bridge writes now require a non-empty `X-CSRF-Token` header (a custom header cannot be sent cross-site without a CORS preflight, which this API never grants) and the same origin allow-list. A loopback-bind guard was rejected: the app does not know its bind address and the attack originates from the developer's own browser, which is on loopback anyway. The bridge must never be enabled outside local development.
- **Repudiation (improved, not closed).** Every mutation, refused or not, emits a structured audit record. The success and failure records are written by the worker thread right after the store call so a client disconnect cannot lose them; the refusal target is the validated incident id; free-form identifiers (assignee, evidence reference) are logged as a length and short hash; over-long actor ids are hashed rather than truncated so distinct identities never collide. The `netsight_api.audit` logger is explicitly configured at start-up (INFO, JSON lines, stderr/stdout/file; `docs/08-operations/AUDIT-LOGGING.md`): before this fix Python's default WARNING level silently dropped the INFO success records. **Still open:** the sink is an operational log, not a tamper-evident store (PRD 32); reads are not audited; the append-only incident timeline remains the authoritative record.
- **Information disclosure (open).** Reads require only `incidents:read`: the technician read scope ("Assigned") is enforced for writes only, there is no site/asset scoping, and Management now has a summary-only view (decided 2026-10-10; see the Step 3 delta). Audit records never contain comment, reason, root-cause or resolution text.
- **Denial of service (partly mitigated).** Writes are rate limited per identity (60 per minute, per worker process, in memory). **Open:** reads have no rate limit and the store uses one connection per call (no pool); there is no request body size cap beyond field limits. A store failure degrades reads to an explicit `unknown` and writes to 503 without leaking the DSN or driver text; an unexpected exception is a 500 `INTERNAL_ERROR` with no detail (only pydantic validation errors and known domain errors map to 4xx).
- **Other open items.** The application role holds column-level `UPDATE` on `incidents` (state, assignee, evidence, resolution, updated_at): SQL run as that role (a bug or an injection) could change state without writing the timeline event, so the record and its history can diverge; a trigger or stored-procedure write path is the follow-up. Resolve/reopen step-up authentication was added in Step 3 (see that delta). The session store and the rate limiter are per worker process. `POST comment` is not idempotent, so a client retry after a timeout can post it twice. `assignee_id` is validated for length only, not shape.

### Alert rules, maintenance windows and notifications (S6-3) - threat-model delta
Adds the first routes that change monitoring configuration and the first outbound-call code (webhook notifications). The routes never send; the notification code is not yet wired to them. Status:

- **Elevation of privilege / tampering (controlled).** A rule is created as a draft and activates only through `alert-rules:approve` (administrators), bound to the `expected_version` the reviewer saw: the version check and the activation are one store operation under the row lock, so an edit that lands after review turns the approval into a 409 (proved with threads and under live PostgreSQL row locks). A rule that cannot be evaluated here never activates (checked at create, update, approve and every evaluation). All write permissions are human-only, so no AI or service principal can create, edit, approve, disable or schedule maintenance, whatever role it carries (AGENTS.md: AI may not alter monitoring configuration). A maintenance window suppresses notifications, so it is bounded (<= 30 days, must not have ended, <= 1 year ahead) and either an organisation scope or `evaluation: disable` (at any scope) needs `maintenance:write-organisation` (administrators) — a site-scope `disable` window stops all evaluation and is gated the same way. **Residual:** "Scoped" roles are not scoped (no ABAC): a Network Engineer or Security Analyst can disable any rule and schedule a window for any non-organisation scope, which is the main abuse path for silencing alerts; there is no four-eyes rule (the creator may approve; decided 2026-10-10 to keep it). Step-up authentication was decided for incident resolve/reopen only, not for rule approval (see the Step 3 delta).
- **Server-side request forgery (webhook sender).** Layered and tested with an injected resolver and transport (no real network): https only; no userinfo, backslash, control character, IP literal or numeric host spelling (decimal, hex, octal, short forms); deny-by-default host allow-list (`NETSIGHT_WEBHOOK_ALLOWED_HOSTS`, exact hosts or `*.domain`) and port allow-list; the name is resolved once and every answer must be a globally routable unicast address (loopback, private, link-local including 169.254.169.254 and fd00:ec2::254, CGNAT, special-purpose, multicast, reserved; IPv4-mapped, NAT64, 6to4, Teredo and IPv4-compatible forms are unwrapped or blocked; non-canonical answers are refused); the connection goes to the validated address while SNI and the `Host` header carry the name (certificate verified, DNS rebinding cannot swap the target between check and connect, a rebound second lookup is refused); redirects are never followed and proxy environment variables are ignored; connect/read timeouts plus a total deadline; at most the configured response bytes are read and discarded, never logged or stored. There is deliberately no setting that permits private targets. **Residual:** the OS name lookup (`system_resolver`) has no timeout of its own; a compromised allow-listed host, or a wildcard entry exposed to subdomain takeover, is trusted to receive notifications; the allow-list is the trust boundary and must be reviewed like a firewall rule.
- **Information disclosure.** Webhook URLs and header values are `Secret` objects (no repr/str/log/pickle/exception text; delivery records and audit lines carry only a hash or host label and static codes); notifications carry enough context to act and a link to authenticated Netsight, not raw telemetry. **Open:** once destinations are persisted the URLs must live in the secret store, not in the rules database.
- **Injection and untrusted text.** Rule names, labels, exception entries, entity names and observation text are untrusted: stored and returned verbatim as data under `application/json`; webhook bodies are JSON (ASCII on the wire); email subjects are a single sanitised line (no header injection, bidi overrides removed) and bodies are plain text, never HTML; nothing is interpreted as markup or as an instruction to an AI. The `matches` operator is a glob evaluated by a bit-parallel matcher (no regular-expression backtracking), with the pattern <= 256 and the text <= 4096 characters.
- **Repudiation (improved, not closed).** Every mutation and every refusal is audited with actor, target id, version and action from the worker thread; free-form values are logged as a length and short hash. This closes the S6-2 gate item that rule edits and disables carry an actor. The sink is still an operational log, not a tamper-evident store, and reads are not audited.
- **CSRF.** Reuses the S6-2 token and origin guards for every write, and also for the dry-run (a cookie POST that costs CPU); a refusal is audited and consumes no rate-limit budget; authorisation is judged before CSRF so the token is not an oracle for unauthorised callers.
- **Denial of service.** The dry-run is bounded (200 observations, 20 windows, text 4096, pattern 256, linear matcher; worst case measured at about 0.3 s) and rate limited per identity; writes share a per-identity limit; the delivery queue is bounded (overflow dropped and recorded), retries are capped at 5 attempts with delays <= 60 s, and the delivery log is a ring buffer. **Open:** no request body size cap, per-worker in-memory limiters, no read rate limit.
- **Other open items.** Escalation, routing and delivery were not yet connected to alert state, delivery attempts were not durable and production email/push senders did not exist (the first three are closed by the S6 step 2 delta below; escalation levels remain unwired); timezone data is a declared dependency (`tzdata>=2024.1`; without it scheduled rules fail closed and cannot be saved or approved).

### S5/S6 hardening pass (2026-10-10) - threat-model delta
Closes the S5 review follow-ups (M1-M4, L1-L5) and the S6-2 carry-overs for request size and read rate limiting. Status:

- **Information disclosure / spoofing (Wazuh credentials, M1).** The indexer client refuses to send Basic credentials over plain http (typed `unavailable`, no request made, so the endpoint degrades to `unknown`). The only bypass is `WAZUH_INDEXER_ALLOW_HTTP=true` and it is honoured only when `NETSIGHT_ENV=development`. A CA bundle (`WAZUH_INDEXER_CA_BUNDLE`) is loaded as an `ssl.SSLContext`; an unreadable bundle fails closed to `unavailable` without echoing the path.
- **Tampering / over-broad reads (L4).** `WAZUH_ALERTS_INDEX` must start with `wazuh-`; `_all`, `*`, `.security` and other-vendor indices are a misconfiguration, so a typo cannot widen the read-only identity's reach.
- **Denial of service (L3, body cap, read limits).** Indexer responses are streamed with an 8 MiB cap (declared length and bytes read); over the cap is `invalid-source-data`. Every POST/PUT/PATCH/DELETE body is capped at 1 MiB (declared `Content-Length` checked first; any other body is buffered up to the cap before the handler runs, so an overflow is answered 413 with the handler never invoked and never sees a truncated body; malformed lengths fall back to counted bytes), answered 413 `PAYLOAD_TOO_LARGE` in the standard envelope with the correlation id; GETs are unaffected. Device, alert, alert-rule, maintenance-window, incident, security and traffic reads are limited to 300 per minute per identity per family (a single-operator assumption: a dashboard page issues a handful of reads, so 300/min leaves large headroom while still bounding scraping; revisit if polling UIs or automation share one identity) (429 `RATE_LIMITED` with `Retry-After`), judged after authorisation so 401/403 never reveal limiter state. Same in-memory, per-worker limitation as the write limiter (a shared store is still needed before more than one worker). Residual: the diagnostics routes (`diagnostics:read`, own permission dependency) are not yet behind the read limiter; the body cap is app-level, so a reverse-proxy limit (`client_max_body_size`) should still be set at the edge.
- **Repudiation / operability (L1).** A failed security source read now logs the typed adapter status (`adapter_status`: unavailable, forbidden, invalid-source-data) next to the error type; never the detail text or credentials.
- **Integrity of the contract (M3, M4).** OpenAPI `SecurityEventsResponse` now carries the same non-ok => no-rows rule as the JSON schema, and a diff test keeps the component and its event schema equal to `security.schema.json`. Whitespace-only optional fields are treated as absent (stripped before the empty check), so one padded field no longer degrades the whole read to `unknown`.
- **Still open.** Read auditing, site scoping, shared (multi-worker) rate-limit store, `partial` state for malformed hits, live Wazuh integration test.

### Evaluation service: observations, incidents and notifications (S6 step 2) - threat-model delta
Adds the first background writer (it creates incidents and sends mail), the first outbound email and the first durable delivery
data. Off unless `NETSIGHT_EVALUATION_ENABLED` is set; enabled, it refuses to start without `DATABASE_URL` or with any invalid
channel setting. Status:

- **Spoofing / elevation of privilege (controlled).** The evaluator acts as `service:alert-evaluator`, a `PrincipalKind.SERVICE`
  with no roles, so it holds no permission and the human-only ones (resolve, reopen, rule and window changes) are denied twice.
  Its code path can create an incident, append `alert-linked`/`comment` notes and claim links; a static test fails the build if
  the `evaluation` package ever references a transition, assignment, evidence, rule or window mutation, if a route module imports
  a sender, or if anything but `evaluation/wiring.py` wires the SMTP or push senders. A recovered alert deliberately leaves its
  incident open: resolution records a human judgement and is never automatic. The evaluator reaches the incident store through a
  narrow `EvaluatorIncidents` Protocol (create, append note, get) and, when a human resolves an incident while the alert still
  fires, it opens no replacement until the alert has recovered (durable `recovered_at` mark), also across restarts. **Residual:** the application database role gained
  `INSERT` (and `UPDATE (incident_id, linked_at, recovered_at)`) on `alert_incident_links` and `INSERT` on `notification_delivery_attempts`; SQL
  executed as that role (a bug or an injection) could repoint a link, causing a duplicate or a suppressed incident, the same class
  of residual as the column-level `UPDATE` on `incidents`. Delivery attempts are append-only (grants plus `ENABLE ALWAYS`
  triggers), but the owner/migrator role can still disable the triggers: keep that credential out of the running service.
- **Tampering / spoofed telemetry (inherent).** A compromised or misbehaving LibreNMS can make the platform raise or withhold
  alerts. Only numeric values and canonical device ids enter the engine; device names and alert titles are never copied into an
  observation. A failed, refused, timed-out, oversized (> 5000 entities) or unparsable read is `unknown` and neither fires nor
  recovers an alert, an unconfigured source is `not-connected`, and a reading the source cannot state is no data: nothing is
  fabricated. A rule whose metric no source supports is reported `unsupported` and never receives data.
- **Silencing abuse (narrowed).** Maintenance windows now reach only availability metrics (`device.status`,
  `interface.oper_status`, `availability.*`; a closed list in `evaluation/source.py`), so a window cannot silence a traffic,
  security or count-based rule. Within availability, the earlier residual stands (scoped roles can schedule non-organisation
  `retain` windows for any scope).
- **Denial of service / alert flooding (bounded).** Cycle interval >= 30 s; per cycle at most 500 rules, 200 000 evaluations, 100
  incident actions, 50 notifications (the rest wait in a backlog of 1000; overflow is counted and audited as failed), 4 concurrent
  source reads with a 30 s timeout; tracked state <= 50 000 and pending or firing state is never evicted, so a flood cannot reset
  debounce or cooldown. Overlapping cycles do not queue. Incident creation is idempotent per key (compare-and-set link), so a
  sustained alert is one incident, not one per cycle. **Residual:** policy `create` opens one incident per alert, so a mass
  outage on N devices opens N incidents (up to 100 per cycle); the `group` policy exists for that and choosing it is the rule
  author's call. A slow relay is bounded: each send has an overall 60 s timeout (`SEND_TIMEOUT`, final) and the notification phase
  has a 60 s per-cycle deadline, the remainder waiting in the (severity-ordered) backlog; a hung send leaves one abandoned
  worker thread until its socket timeout fires. The OS name lookup still has no timeout (carried over from S6-3). The
  evaluation budget is shared fairly between rules and entities are visited round-robin, so one large rule cannot starve the rest.
- **Information disclosure (controlled).** SMTP password, push gateway URL and token, and push device references are `Secret`
  values (no repr, str, log, pickle or exception text; configuration errors never echo values). TLS is mandatory for email
  (STARTTLS or implicit TLS, TLS 1.2 minimum, certificate and host-name verification on, no plaintext setting, no fallback after
  a failed STARTTLS, credentials sent only after TLS). Notifications carry the rule name, entity id, severity and a link to
  authenticated Netsight, not telemetry. Audit lines and the delivery table hold a keyed hash or host, static codes and ids;
  never addresses, tokens, payload text or provider replies. **Residual:** email passes through the configured relay in plain text
  inside TLS hops (no end-to-end encryption), so the relay is trusted with rule names and device ids.
- **Server-side request forgery.** The push gateway reuses the webhook defences unchanged (https, allow-list, public addresses
  only, pinned connection, no redirects, bounded time and size). **Residual:** the gateway host shares `NETSIGHT_WEBHOOK_ALLOWED_HOSTS`
  with webhooks; the SMTP relay host is operator configuration and is not subject to the allow-list.
- **Injection and untrusted text.** Rule names and entity ids reach incident titles, timeline notes, email subjects and push text
  only through `sanitize_line` (control and bidi characters removed, one line, length bounded) and are stored and rendered as data;
  email is plain text, push is bounded plain text, nothing is interpreted as markup or as an instruction to an AI.
- **Repudiation (improved, not closed).** `incident.auto_create`, `incident.auto_attach` and `notification.send` are audited with the
  service actor and the cycle's correlation id, plus the durable `notification_delivery_attempts` table and the append-only incident
  timeline (each automatic note is written by `service:alert-evaluator`). The audit sink is still an operational log; reads are
  still not audited.
- **Fail-closed behaviour.** Rule store unreadable: nothing is evaluated. Source unknown or not connected: nothing fires, nothing
  recovers, pending debounce restarts. Durable delivery store down: the attempt stays in the in-memory ring and delivery goes on
  (counted, logged by type). Ledger unreadable for the cooldown check: the page is sent rather than muted. No public base URL: no
  notification is sent and the refusal is audited. A failed incident step does not stop the page, and a failed page does not
  undo the incident.
- **Single evaluator (enforced).** A PostgreSQL advisory lock on a dedicated, keepalive-enabled connection gates the scheduler;
  others idle and retry, and losing the lock stops evaluation and drops engine state. A lock backend error means not leader.
  **Residual:** the lock is per database, not per schema; a half-open TCP connection is noticed only at the next check or
  keepalive timeout (about a minute), during which two evaluators could overlap; the incident-link compare-and-set still prevents
  duplicate incidents, but a repeat page is then possible (the cooldown ledger limits it).
- **Open.** Engine state is per process, so after a restart a repeat page is prevented only by a non-zero
  `cooldown_seconds` and the durable ledger; destinations come from the environment (managing them in the database, and keeping
  secrets in the secret store, is a follow-up); there is no operator-facing evaluator status endpoint yet (logs and audit only);
  the `webhook` channel is unreachable from rule `actions`; there is **no delivery-attempt prune path** (the append-only triggers also stop the owner; an audited
  disable-trigger/delete/re-enable migrator step is undesigned), so the table grows without bound until one exists; SMTP trust is
  the system roots plus the optional bundle; a recovered alert whose recovery was missed (evaluator down for the whole recovery and
  re-fire) is attributed to the old resolved incident.

### UI write actions, step-up authentication and the Management summary view (Step 3, 2026-10-10) - threat-model delta
Turns the S6-4 read-only UI into the first browser-driven writes (incident acknowledge/advance/assign/comment/resolve/reopen, alert-rule
create/edit/approve/disable, maintenance-window create/cancel) and records three human decisions: step-up for resolve/reopen, a
summary-only incident view for Management, and creators may approve their own rules. Status:

- **CSRF / cross-site writes (controlled).** The browser never holds the session CSRF token or the API credentials. Writes are Next.js
  server actions (`incidents/[incidentId]/actions.ts`, `alerts/actions.ts`): each asserts that the browser's Origin/Referer host equals the
  host the request was addressed to (`sameOrigin`, on top of the framework's own check), validates the payload (ids against the contract
  patterns, bodies rebuilt field by field with the contract bounds, `planIncidentRequest` / `planAlertingRequest`), then calls the API
  through `apiPost`, which reads the HttpOnly session cookie server-side, fetches the CSRF token with it and sends both to the loopback
  API. The API's own origin allow-list, CSRF, authorisation, rate limit and audit are unchanged and still decide every write; a server
  action is a public POST, so none of the UI checks is relied on.
- **Elevation of privilege via the UI (controlled; advisory only).** Button availability comes from `permissions` on `GET /auth/session`
  (derived from the same `is_allowed` the routes use) and the incident state. It only explains: a forged call, a stale page or a role
  change still meets the API's 403/409, which the UI shows. A role without a permission gets a disabled control with a plain-text reason
  (permission is explained before state, so a role learns nothing about state rules it cannot use).
- **Step-up authentication (new; closes the S6-2 follow-up).** `incidents:resolve` and `incidents:reopen` require a second factor proven
  within `NETSIGHT_STEP_UP_MAX_AGE_SECONDS` (default 900). The session carries `mfa_verified_at` on the store clock, set from the token's own
  `auth_time` (never session creation time) and only when the token asserts `mfa` in `amr` with a numeric, non-future, in-window `auth_time`
  that, for a step-up, is later than the request (replay of an older token is refused and audited `auth.mfa`/`step-up-replay`); local
  sign-in stamps age 0 after TOTP/recovery code; unknown fails closed with `403 STEP_UP_REQUIRED`,
  audited as `denied`/`step-up`, decided after authorisation and CSRF and before the rate limit. The UI offers "Sign in again", which
  starts a provider sign-in with `step_up=true` (`prompt=login`, `max_age=0`) or the local password + TOTP flow, then returns to the page
  (`safeNextPath` rejects anything but a same-origin path; the auth proxy forwards only `redirect_to` and `step_up`, never `state`).
  **Residual:** `auth_time` is trusted as the provider reports it (a provider that ignores `prompt=login` and reuses its session returns an
  old `auth_time`, which is then refused as stale or a replay); a provider that never emits `amr` (Google) cannot satisfy step-up through OIDC at all (resolve/reopen are then unavailable to
  that sign-in route, which fails closed); the superseded session is revoked by the re-login (see the review delta below); the stamp lives in the
  per-worker in-memory session store; the dev identity bridge is exempt (no session, development only); a step-up redirect discards a
  half-typed resolve form (the dialog says so).
- **Information disclosure - Management (controlled; partly closes the S6-2 open item).** Management loses `incidents:read` and holds
  `incidents:read-summary`: `GET /incidents/summary` returns only id, title, severity, state, timestamps, `assigned` (boolean) and
  `resolved_at`; no evidence ids, resolution text, timeline, comments or assignee identity, and no assignee filter (it would be an
  ownership oracle). Detail and timeline answer 403 for that role. The projection happens in the route, so the response model cannot carry
  the omitted fields; JSON Schema, OpenAPI, pydantic and the TS parser reject any of them (shared vectors). **Residual:** `title` is
  operator/alert-authored text and can name assets; the summary read shares the per-identity read rate limit and is not audited (read
  auditing is still open); `permissions` on `/auth/session` discloses only the caller's own grants.
- **Tampering / integrity - alerting (controlled).** Approve and edit send the `expected_version` the operator saw (a concurrent edit is a
  409, shown as "the record changed; reload"); the approval dialog restates the exact version, scope and condition. Creators may approve
  their own rules (human decision; no four-eyes), which the dialog states and the audit record attributes to the approver. Disable and
  cancel carry no version (they are state transitions the API answers 409 to when already applied). Operator text (names, labels,
  patterns, reasons, comments, assignees) is only ever placed in controls and text nodes (`no-raw-html.test.ts` still passes).
- **Repudiation / lost updates.** A write whose answer is lost (timeout, network, unparseable response) is reported as "result could not
  be confirmed; reload before repeating", never as success or as a plain failure; every control is single-flight (a ref guard, so two
  clicks in one tick send one request) and a dialog cannot be dismissed while a request is in flight. Comments are still not idempotent
  (a retry after a lost answer can duplicate one; the dialog says to reload first).
- **Still open.** Read auditing; surfacing MFA recency in the session so the UI can prompt before a long form is filled; per-site scoping of the "Scoped" roles; a draft-preserving step-up round trip; Close (resolved -> closed) is not in the UI.

### Step 3 review fix pass (2026-10-10) - threat-model delta
Closes the independent code and security review of the Step 3 UI write actions. Status:

- **Open redirect (controlled).** The sign-in destination (`redirect_to` on the API, `next` on the web) is accepted only as a same-origin
  absolute path whose first segment is a dashboard area (`overview`, `network`, `devices`, `traffic`, `security`, `diagnostics`, `incidents`,
  `alerts`), checked as written **and** after percent-decoding. Rejected: `//`, a backslash, control characters (so a tab after the first
  slash, `/` followed by a backslash and `/%09/` all fall back to `/overview`), bidi and zero-width characters, `/api`, `/auth`, `/login`, more
  than 512 characters. The same rules are implemented twice and tested on both sides (`auth/redirects.py`, `sign-in-redirect.ts`).
- **Cross-site server actions (tightened).** `sameOrigin` now requires the Origin header when present and consults Referer only when Origin is
  absent (a present-but-unusable Origin, e.g. `null`, is a rejection and never falls back); scheme **and** host (with port) must match, with
  https required in production except on loopback. `X-Forwarded-Host` / `X-Forwarded-Proto` are client-controllable, so they are honoured only
  when `NETSIGHT_TRUST_PROXY_HEADERS=true` is set explicitly (exact value; default off). Turn it on only behind a reverse proxy that
  **overwrites** both headers; with it off, the proxy must pass the public name in `Host`. A misconfiguration fails closed (writes are refused
  as "not from this site"), never open. Diagnostics and the write actions share one implementation (`fromSameOrigin`).
- **Session fixation / stale sessions (closed).** Completing an OIDC callback or a local MFA verification revokes the session the browser
  presented (`SessionManager.revoke_cookie`; a missing or forged cookie revokes nothing) before the new cookie is set. This removes the
  previously recorded residual that a superseded session aged out on its own.
- **Audit (tightened).** A denied `auth.mfa` record carries `identity_fingerprint` (a short SHA-256 of the provider-qualified identity), so
  repeated denials correlate without recording who was refused. The step-up replay check allows `STEP_UP_REPLAY_TOLERANCE_SECONDS` = 5 s
  (provider clock skew and second-granularity `auth_time`); a token older than the request by more than that is still a replay.
- **Dev identity bridge (pinned).** Tests assert it cannot be enabled when `NETSIGHT_ENV` is anything other than exactly `development`
  (production, staging, test, empty, other casing or spacing) even with `NETSIGHT_ENABLE_DEV_IDENTITY=true`, and that both flags are required.
- **ReDoS (confirmed not applicable).** The `matches` operator is a glob evaluated by a bit-parallel NFA simulation
  (`alerting/matching.py`); no regular-expression engine, `fnmatch` or backtracking is used on rule patterns. Tests pin this by source
  inspection, a catastrophic `*a*a*...b` pattern against 4000 characters, and a linear-growth check; text over 4096 characters never matches.
- **Management summary schema (pinned).** The summary item and list models forbid extra fields (a test per omitted field), so a future change
  that adds assignee identity or evidence ids to the projection fails at validation.
- **UI write safety (tightened).** An unconfirmed result (no usable answer) now **locks** the control: nothing more is sent until the operator
  clicks "Reload current state" (closing the dialog also reloads), so a lost answer can no longer lead to a second comment or rule. A definite
  refusal (409, 422, 503, 429, 403) does not lock. The dialog is a real focus trap (Tab and Shift+Tab wrap; Tab with nothing focusable stays
  on the dialog; keys are handled on the document so a submit button disabled mid-request cannot drop keyboard focus out of the modal), cannot
  be dismissed while a request is in flight, and focuses its first field on open. The 401 advice links to `/login?next=<current path>` through
  `safeNextPath`. Icon-only labels were replaced by visually-hidden text with `aria-hidden` icons. Component tests (jsdom + Testing Library,
  `apps/web/scripts/run-component-tests.mjs`) pin all of this, including the double-click single-flight guard and the per-role disabled reasons.
- **Alert-rule approve/disable are outside step-up** by decision (recorded in RBAC-MATRIX); the audit record and `expected_version` binding
  are the controls.
- **Still open.** Idempotency keys (the lock prevents a resend from this page but not from a second tab or another client); step-up for rule
  approval if the product decides it; a Playwright run of the write flows against a real stack (component tests use jsdom and stubbed server
  actions); the proxy-trust setting is read from the process environment per request and is not validated against the actual proxy; read
  auditing; the per-worker in-memory session store (a revoked session is only revoked in that worker).

## AI-specific threats
- prompt injection in logs/hostnames/knowledge;
- tool injection;
- data exfiltration through model;
- hallucinated operational state;
- unsafe remediation;
- poisoned baselines.

Mitigate with:
- telemetry-as-data isolation;
- schema tools;
- policy outside LLM;
- data minimisation;
- evidence citations;
- no direct write tools in MVP;
- baseline governance.
