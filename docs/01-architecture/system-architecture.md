# System Architecture

## Architectural style

Netsight is a modular platform with:
- Next.js AdminLTE web/PWA;
- Platform API;
- asynchronous workers;
- integration adapters;
- incident/alert/correlation services;
- AI gateway/tool broker;
- PostgreSQL platform database;
- Redis for queues/cache where appropriate;
- existing specialised telemetry stores.

## Core rule

The Netsight database stores **platform state** — identities, correlations, incidents, rules, permissions, action requests, user preferences and references to evidence.

It should not blindly duplicate high-volume raw telemetry already held by ClickHouse, Wazuh/OpenSearch, LibreNMS RRD/time-series stores or other source systems.

## Logical view

```text
Users
  |
  v
Reverse Proxy / WAF / Zero-Trust Access
  |
  v
Next.js Web/PWA
  |
  v
Platform API  <----> Identity / RBAC / Audit
  |
  +--> Incident / Alert / Correlation
  +--> Root Cause / Diagnostics
  +--> Reporting
  +--> Action Approval/Execution
  +--> AI Tool Broker
  |
  +--> Adapter Layer
        +--> LibreNMS
        +--> NetBox
        +--> Akvorado/ClickHouse
        +--> Wazuh
        +--> Suricata
        +--> Grafana/Alertmanager
        +--> Oxidized
        +--> Blackbox
        +--> DNS/DHCP/RADIUS/IdP
```

## Trust boundaries

1. Public/remote user zone
2. Application zone
3. Integration/service zone
4. Management network
5. Monitored production networks
6. External SaaS identity providers
7. Optional AI provider boundary

No single credential spans all boundaries.

## Availability principle

Monitoring/management must remain useful during partial failures. The UI must degrade gracefully when one source is unavailable.

## Future scalability

Adapters and high-volume query services may be split into independent services as scale requires. Do not prematurely decompose every module into microservices.
