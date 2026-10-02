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
