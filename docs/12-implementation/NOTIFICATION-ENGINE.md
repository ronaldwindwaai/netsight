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

Code: `apps/api/src/netsight_api/notifications/`. Nothing here is wired to the alert engine or the routes yet; the
routes never send. Channels are email, push and webhook behind the `NotificationSender` Protocol; only the webhook sender
and a test fake exist (production SMTP and push senders need infrastructure decisions).

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
  channel, destination label, attempt, status, static code, time) in a bounded in-memory ring. Durable storage of delivery
  attempts is a follow-up.
- Routing: severity threshold, label match (site, team, service) and schedule select destinations; an unevaluable
  schedule routes nowhere. Escalation levels become due after a delay and stop once the alert is acknowledged or resolved.
