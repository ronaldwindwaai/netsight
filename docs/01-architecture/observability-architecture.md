# Observability of Netsight

Netsight must monitor itself.

Track:
- web/API availability;
- API latency/error rate;
- adapter latency/errors;
- poll/ingestion freshness;
- queue depth;
- background-job failure;
- DB health;
- storage capacity;
- ClickHouse query performance;
- authentication errors;
- notification delivery;
- AI tool failure;
- action execution failure;
- audit pipeline health.

Every request/workflow should carry a correlation ID.

Do not log:
- access tokens;
- refresh tokens;
- SNMP credentials;
- secrets;
- sensitive message bodies unless explicitly required and protected.
