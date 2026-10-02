# Canonical Data Model

Core entities:
- Organisation
- Site
- Identity
- Account
- Device
- Interface
- IPAddressAssignment
- MACAddress
- VLAN
- Prefix
- Circuit
- Service
- FlowSummary
- Application
- Destination
- Evidence
- Alert
- Incident
- Anomaly
- ConfigurationVersion
- ProbeResult
- DiagnosticRun
- ActionRequest
- Approval
- AuditEntry
- Report
- IntegrationSource

## Identity rules

A Device has one Netsight canonical ID and many source aliases.

`DeviceSourceAlias` examples:
- libreNMS device ID;
- NetBox device ID;
- Wazuh agent ID;
- DHCP client identifier.

Never join identities solely by display name.

## Evidence model

Evidence is immutable-by-convention and source/time stamped. Incidents and AI investigations reference evidence IDs.

## Confidence

Identity correlations and root-cause inferences have confidence separate from raw facts.

## High-volume telemetry

Flow rows and raw SIEM events are queried from source systems. Store references/aggregates needed for incidents and reproducibility.
