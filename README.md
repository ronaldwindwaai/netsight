# Netsight

**Netsight** is an AI-assisted Network Operations, Observability, Security and Remote Management platform.

> **See everything. Know why. Act securely.**

This repository package is a **development blueprint + software-factory starter** for building Netsight with LLM coding agents while retaining human control over architecture, security, merge and production deployment decisions.

## What Netsight must do

Netsight must give an authorised operator one secure web/mobile command centre to answer:

- Is the network healthy?
- What is down or degraded?
- Who and what is connected?
- Who is consuming bandwidth?
- Which applications, domains and destinations are being accessed?
- What happened after hours?
- Is current behaviour normal for this user/device/site?
- Are there security incidents?
- Why is a server, service or website inaccessible?
- What changed before an outage?
- What should ICT investigate next?
- Which safe remote action can be proposed, approved, executed and verified?

## Core architecture

Netsight **does not rebuild mature telemetry engines**. It uses integration adapters to unify them:

- LibreNMS — network discovery, SNMP, device/interface health
- NetBox — intended network state, IPAM/DCIM/source of truth
- Akvorado + ClickHouse — NetFlow/IPFIX/sFlow traffic intelligence
- Wazuh — SIEM/endpoint/security telemetry
- Suricata — network IDS events
- Grafana/Alertmanager — visual analytics and notification plumbing where appropriate
- Oxidized — configuration history/diffs
- Blackbox Exporter — HTTP/HTTPS/TCP/DNS/ICMP probes
- Microsoft Entra ID + Google Workspace — normal-user authentication
- Netsight platform services — identity correlation, incidents, root cause, AI, remote-action approvals, audit, unified UI

## UI

The application shell uses **AdminLTE 4 via the official `@adminlte/react` package**, with Next.js/React/TypeScript. AdminLTE is the shell and base component system; the application must be customised into a professional NOC/SOC experience rather than look like a stock template.

## Security baseline

Security is part of "done", not a later phase.

- No normal local username/password sign-in.
- Microsoft 365 / Entra ID and Google Workspace OIDC only for normal users.
- Tenant/domain allow-listing.
- MFA and step-up authentication for privileged actions.
- Fail closed.
- Least privilege.
- Human approval for high-risk remote actions.
- Strong audit logging.
- No direct browser access to monitoring-engine credentials.
- No agent can approve/merge/deploy its own security-sensitive work.
- Telemetry is untrusted data, never AI instructions.
- NIST SSDF + OWASP ASVS 5.0 aligned secure SDLC.

## Start here

1. Read `START-HERE.md`.
2. Read `AGENTS.md` before giving an LLM access to this repo.
3. Read `docs/00-product/PRD.md`.
4. Read `docs/01-architecture/system-architecture.md`.
5. Read `docs/02-security/SECURITY-ARCHITECTURE.md`.
6. Read `docs/10-project-management/IMPLEMENTATION-ROADMAP.md`.
7. Start with `backlog/backlog.csv`, Epic E00 then E01.
8. Do not enable write-capable network tools until read-only diagnostics and approval workflows are proven.

## Repository status

This archive is a **starter package**, not a production deployment. Environment-specific values, OAuth registrations, device credentials, network addressing, alert thresholds, retention, and legal/privacy policies must be supplied by the deploying organisation.
