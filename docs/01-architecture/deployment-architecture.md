# Deployment Architecture

## Recommended production pattern

- Public/remote entry: hardened reverse proxy / WAF / Zero-Trust gateway.
- Web/API: application network segment.
- Integration workers: private service network.
- Monitoring engines: management network, not public.
- Database: private.
- Secrets manager: private.
- Optional out-of-band LTE/5G path for critical infrastructure.

## Remote access

Remote operators access Netsight, not the raw LibreNMS/Wazuh/NetBox/Grafana administrative interfaces.

## Outbound-first integration

Where practical, collectors and agents send or expose data over controlled private channels. Avoid inbound Internet exposure to management protocols.

## Environments

- local dev
- integration/lab
- staging
- production
- optional DR

No production secrets/data should be copied into development.

## High availability

Production design should eventually provide redundancy for:
- reverse proxy;
- API;
- platform database;
- queues;
- identity integration;
- critical collectors.

The management application must not become a network data-plane dependency.
