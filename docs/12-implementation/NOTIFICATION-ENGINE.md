# Notification Engine

## Channels
- in-app;
- email;
- push;
- webhook;
- optional Teams/Slack/SMS/WhatsApp.

## Routing
Rule based on severity, site, team, service and schedule.

## Delivery metadata
Track:
- notification ID;
- alert/incident;
- channel;
- destination policy;
- attempt;
- status;
- timestamp;
- error.

## Escalation
Escalation starts when alert meets policy and stops when acknowledged/resolved according to rule.

## Sensitive content
Email/push notifications should contain enough context to act but avoid unnecessary sensitive telemetry. Link to authenticated Netsight for details.

## Implementation (S6-3)

Code: `apps/api/src/netsight_api/notifications/`. The routes never send (a static test enforces it); the evaluation
service (`evaluation/notify.py`, see ALERT-ENGINE.md) is the only caller. Channels are email, push and webhook behind the
`NotificationSender` Protocol. Production senders: SMTP email (`smtp.py`), a push gateway (`push.py`) and webhook
(`webhook.py`); the engine reaches email and push only, because rule `actions` name `create_alert`, `email` and `push`.

- Credentials (webhook URL, header values, push device references) are `Secret` values: never in `repr`, `str`, logs,
  delivery records or exception messages. A destination shows a hash (email, push) or the host (webhook).
- Payloads carry untrusted text as data only: JSON-encoded (ASCII on the wire) for webhooks, a single sanitised line for
  email subjects (no header injection), plain text bodies (never HTML), length-bounded push strings. They link to
  authenticated Netsight rather than embedding telemetry.
- Webhook SSRF defence, in layers: https only, no userinfo, no backslashes or control characters, no IP literals or
  numeric host spellings, allow-list (`NETSIGHT_WEBHOOK_ALLOWED_HOSTS`, deny by default; exact hosts or `*.example.com`),
  port allow-list (default 443), resolve once through an injectable resolver and require every answer to be globally
  routable (IPv4-mapped, NAT64, 6to4, Teredo and IPv4-compatible forms are unwrapped or blocked; loopback, private,
  link-local and metadata, CGNAT, special-purpose, multicast and reserved ranges are refused), connect to the pinned
  address with the original name for SNI and `Host` (so DNS rebinding cannot swap it and certificates are still verified),
  no redirects, no proxy environment, connect/read timeouts plus a total deadline, response read capped and discarded.
  There is intentionally no setting that allows private targets.
- Delivery: bounded queue (`NETSIGHT_NOTIFY_QUEUE_LIMIT`, overflow dropped and recorded), retry with deterministic
  exponential backoff (at most 5 attempts, each delay at most 60 s), every attempt recorded (notification id, alert ref,
  channel, destination label, attempt, status, static code, time) in a bounded in-memory ring **and** durably in PostgreSQL
  (migration 0003 `notification_delivery_attempts`, append-only: the application role has SELECT and INSERT only and
  triggers reject UPDATE, DELETE and TRUNCATE). `DurableDeliveryRecorder` writes the ring first and the database best
  effort: a database failure is counted (`durable_failures`, exported through `EvaluationService` and logged by the
  scheduler whenever it grows), the attempt stays in the ring and delivery goes on. A
  recorder failure of any kind never stops the dispatcher. Rows hold identifiers and static codes only (the schema
  constraints repeat the validation); pruning is a migrator/owner job, there is no application delete path.
- Routing: severity threshold, label match (site, team, service) and schedule select destinations; an unevaluable
  schedule routes nowhere. Escalation levels become due after a delay and stop once the alert is acknowledged or resolved.

### Production senders (S6 step 2)

- **SMTP email** (`smtp.py`). `NETSIGHT_SMTP_HOST`, `_PORT`, `_TLS` (`starttls` default, port 587, or `tls`, port 465; no
  plaintext value exists), `_FROM` (required), `_USERNAME` and `_PASSWORD` (both or neither; `Secret`), `_TIMEOUT_SECONDS`
  (1-60), `_CA_BUNDLE` (a PEM file **added to** the system trust roots, not replacing them). TLS 1.2 minimum, certificate and host-name verification always on. STARTTLS is mandatory: a server
  that does not offer it is `STARTTLS_UNSUPPORTED` (final), a failed STARTTLS never falls back to plaintext, and the login
  happens only after TLS is established. Mail is plain text, one sanitised subject line, one validated recipient, no
  Bcc/Cc, `Auto-Submitted: auto-generated`. Failures are static codes (`AUTH_FAILED`, `RECIPIENT_REFUSED`, `SENDER_REFUSED`,
  `SMTP_4XX` retryable, `SMTP_5XX`, `TLS_FAILED`, `TLS_CONFIG`, `CONNECTION_FAILED`, `TIMEOUT`, `SMTP_ERROR`,
  `SENDER_ERROR`); relay replies, addresses and credentials never reach a result, log or exception text.
- **Push gateway** (`push.py`). Provider-agnostic: one JSON document per notification (`device`, `title`, `body`, `link`,
  `notification_id`, `severity`; bounded plain text) is POSTed to `NETSIGHT_PUSH_GATEWAY_URL` (`Secret`, https, no userinfo)
  with an optional `Authorization: Bearer` token (`NETSIGHT_PUSH_GATEWAY_TOKEN`, `Secret`). It uses the webhook defences
  unchanged (allow-list `NETSIGHT_WEBHOOK_ALLOWED_HOSTS` must include the gateway host, public addresses only, pinned
  connection, no redirects, bounded time and response). The provider (FCM, APNs, Web Push, ntfy...) sits behind the gateway;
  choosing it is an open decision.
- **Routing table** (`routing_config.py`). `NETSIGHT_NOTIFY_EMAIL_TO`, `NETSIGHT_NOTIFY_PUSH_DEVICES` (comma lists, at most 50
  each; device references are `Secret`) and `NETSIGHT_NOTIFY_MIN_SEVERITY` (default `high`). Unset means nobody is
  notified; invalid values fail start-up without echoing them. `RoutingRule` itself still supports label and schedule
  routing and escalation levels; managing destinations in the database is a follow-up.
- **Engine -> routing** (`evaluation/notify.py`). When the engine releases a notification the notifier selects destinations
  with `route()`, keeps only the channels named in the rule's `actions`, builds a payload (title = rule name, summary =
  severity, entity id and metric; link = `<NETSIGHT_PUBLIC_BASE_URL>/incidents/<id>` or `/alerts/<fingerprint>`), submits it
  to the bounded dispatcher queue and drains it one notification at a time (so an error while handling one never hides the
  outcomes already delivered; the one lost is audited `NOT_DELIVERED`). Without `NETSIGHT_PUBLIC_BASE_URL` nothing is sent (`no-public-url`, audited).
  Every outcome is audited as `notification.send` (success or failure) with the notification id, channel, destination label
  (a hash or host), static code and attempt count. A successful send within the rule's `cooldown_seconds` (read from the
  durable ledger) suppresses a repeat after a restart; with `cooldown_seconds = 0` a restart can repeat a page.
- **Time bounds.** Every send is bounded overall (`SEND_TIMEOUT`, 60 s by default, final - not retried, because the message
  may have gone out and a retry would only stack up hung workers); socket timeouts alone bound single operations, not a
  slow-drip relay. The runner's notification phase has a 60 s wall-clock deadline per cycle: notifications not started by then
  wait in the backlog (most severe first) for the next cycle. A page that cannot be kept (backlog full) is audited
  `notification.send` / `BACKLOG_FULL`. `sanitize_line` also strips all format (Cf) characters (zero-width, BOM, tag
  characters), so hidden text cannot ride along in a subject or title.
