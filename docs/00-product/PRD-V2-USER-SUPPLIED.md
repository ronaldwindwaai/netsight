# NETSIGHT

## Comprehensive Product Requirements Document

**Product Name:** Netsight  
**Product Category:** AI-powered Network Operations, Observability, Security and Remote Management Platform  
**Primary Tagline:** **See everything. Know why. Act securely.**  
**Document Version:** 2.0  
**Primary UI Framework:** AdminLTE 4 / `@adminlte/react`  
**Frontend:** Next.js / React / TypeScript  
**Primary Interfaces:** Desktop Web, Tablet, Mobile/PWA  
**Authentication:** Microsoft 365 / Microsoft Entra ID and Google Workspace  
**Deployment Model:** Hybrid — on-premises collectors and monitoring engines with secure remote access  
**Development Model:** Secure SDLC, LLM/agent-assisted development, strict human approval for high-risk changes

---

# 1. EXECUTIVE SUMMARY

Netsight is a unified Network Operations, Observability, Security, AI and Remote Management platform.

Its purpose is to give ICT administrators one secure application from which they can understand, monitor, diagnose and manage the complete network environment.

Netsight must answer questions such as:

- Is the network healthy?
- Is the Internet operating normally?
- Which devices are online, offline or degraded?
- Which server is inaccessible and why?
- Which endpoint is consuming the most bandwidth?
- Which user is associated with that endpoint?
- What applications or destinations are consuming bandwidth?
- What traffic occurred outside normal working hours?
- Is that behaviour normal for that user or device?
- Are there unusual uploads or downloads?
- Are unknown devices joining the network?
- Are security incidents occurring?
- What happened immediately before an outage?
- Did a firewall, switch or application configuration change cause the problem?
- Are switches, access points and servers approaching capacity?
- Are certificates or storage approaching expiry/exhaustion?
- What happened overnight?
- What should ICT investigate first?
- Can ICT safely manage the network remotely from anywhere?

Netsight must provide answers through both traditional dashboards and a natural-language AI assistant.

The system must not simply state:

> WEB-SRV02 is down.

It should attempt to establish:

> WEB-SRV02 is reachable and responding to ICMP and SSH. HTTPS is unavailable because nginx stopped at 10:42 after a configuration reload. TCP/443 is currently failing while the server itself remains healthy.

The central Netsight principle is:

# DETECT → CORRELATE → EXPLAIN → RECOMMEND → APPROVE → ACT → VERIFY → LEARN

---

# 2. PRODUCT VISION

Create a single intelligent Network Command Centre capable of combining:

- infrastructure monitoring;
- device discovery;
- network topology;
- Internet/WAN monitoring;
- traffic analytics;
- user/device identity;
- security monitoring;
- anomaly detection;
- incident management;
- root-cause diagnostics;
- configuration history;
- alert automation;
- reporting;
- AI-assisted investigation;
- controlled remote actions.

Netsight must eliminate the need for everyday ICT operators to switch between multiple disconnected products.

LibreNMS, Wazuh, Suricata, Akvorado, NetBox, Grafana, ClickHouse, Oxidized and related systems may operate behind Netsight, but the user experience must remain Netsight.

---

# 3. PRODUCT OBJECTIVES

## 3.1 Primary Objectives

Netsight must:

1. Provide immediate visibility into network health.
2. Identify users and devices consuming bandwidth.
3. Correlate network identities with users where evidence exists.
4. Provide traffic, destination and application visibility.
5. Detect anomalous behaviour.
6. Detect suspicious after-hours activity.
7. Consolidate security telemetry.
8. Reduce alert noise through correlation.
9. Explain root causes.
10. Correlate outages with recent changes.
11. Allow administrators to manage and diagnose the environment remotely.
12. Provide AI-assisted investigation.
13. Keep destructive actions behind explicit security controls.
14. Produce management and technical reports.
15. Remain modular enough to replace backend products in future.

---

# 4. PRODUCT NON-GOALS

Netsight is initially NOT intended to:

- replace the organisation's firewall;
- replace endpoint antivirus/EDR;
- rebuild SNMP monitoring from scratch;
- build a SIEM from scratch;
- rebuild NetFlow/IPFIX collectors from scratch;
- decrypt all TLS traffic by default;
- allow unrestricted AI administration;
- automatically change critical infrastructure without policy and approval;
- expose internal monitoring products directly to the Internet;
- treat an IP address as definitive proof of user identity.

---

# 5. CORE PRODUCT PRINCIPLES

## 5.1 One Application

The user should see:

- one login;
- one sidebar;
- one search;
- one notification system;
- one incident system;
- one design language;
- one AI interface;
- one permissions model.

---

## 5.2 Evidence Before Conclusion

AI-generated statements must distinguish between:

**Observed**

Directly supported by telemetry.

**Inferred**

Reasonably inferred from multiple data sources.

**Unknown**

Evidence is unavailable or insufficient.

Netsight must never fabricate operational state.

---

## 5.3 Open Source First

Use mature systems as backend engines whenever practical.

Preferred baseline:

| Capability | Preferred Engine |
|---|---|
| Network monitoring | LibreNMS |
| Network source of truth/IPAM | NetBox |
| Flow analytics | Akvorado + ClickHouse |
| SIEM / endpoint telemetry | Wazuh |
| Network IDS | Suricata |
| Analytics | Grafana |
| Network config history | Oxidized |
| Active probes | Prometheus Blackbox Exporter |
| Identity broker if needed | Authentik / Keycloak |

---

# 6. USER PERSONAS

## 6.1 ICT Administrator

Full operational control.

Needs:

- overall health;
- users;
- devices;
- alerts;
- traffic;
- incidents;
- integrations;
- remote actions;
- permissions;
- reports;
- AI;
- configuration.

---

## 6.2 Network Engineer

Focus:

- routers;
- switches;
- interfaces;
- topology;
- routing;
- VLANs;
- bandwidth;
- Wi-Fi;
- configuration;
- WAN;
- network troubleshooting.

---

## 6.3 Security Officer

Focus:

- security findings;
- endpoint telemetry;
- IDS events;
- unusual behaviour;
- authentication;
- incidents;
- isolation;
- investigations.

---

## 6.4 ICT Technician

Needs:

- device health;
- alerts;
- diagnostic tests;
- assigned incidents;
- basic approved actions.

---

## 6.5 Management

Requires simplified views:

- network availability;
- Internet availability;
- major outages;
- security posture;
- trends;
- risks;
- monthly reports.

Management should not see unnecessary technical noise.

---

## 6.6 Auditor

Read-only access to:

- authentication;
- incidents;
- alert history;
- admin actions;
- configuration changes;
- audit logs;
- security records.

---

# 7. DESIGN AND UX REQUIREMENTS

## 7.1 Design Source of Truth

The repository folder:

`/designs/`

is the approved visual reference for Netsight.

Implementation agents must inspect the appropriate design before creating a screen.

Approved designs define:

- layout;
- information density;
- navigation;
- card hierarchy;
- spacing;
- typography;
- colour usage;
- tables;
- status chips;
- charts;
- topology presentation;
- incidents;
- alert rules;
- diagnostics;
- AI presentation.

The production UI must not embed the screenshots as UI.

Each design must be recreated semantically in React.

---

# 8. FRONTEND DESIGN SYSTEM

Netsight will use:

- Next.js;
- React;
- TypeScript;
- AdminLTE 4;
- `@adminlte/react`;
- Bootstrap 5.3;
- Netsight-specific custom components.

AdminLTE provides:

- sidebar;
- topbar;
- responsive shell;
- cards;
- tabs;
- form controls;
- standard admin primitives.

Netsight custom components provide:

- live topology;
- traffic visualisation;
- incident timelines;
- diagnostic paths;
- security evidence;
- AI assessment;
- remote action approval;
- user/device correlation.

---

# 9. GLOBAL APPLICATION LAYOUT

## Desktop

```text
┌─────────────────────────────────────────────────────────────┐
│ Sidebar │ Header / Search / Ask AI / Alerts / User         │
│         ├───────────────────────────────────────────────────┤
│         │                                                   │
│         │                Main Content                       │
│         │                                                   │
└─────────────────────────────────────────────────────────────┘
```

---

# 10. GLOBAL SIDEBAR

Primary navigation:

### Overview

- Network Overview

### Network

- Network Map
- Devices
- Users
- Traffic
- Internet / WAN
- Wi-Fi

### Security

- Security Centre
- Incidents
- Alerts

### Operations

- Diagnostics
- Configuration & Changes
- Inventory / IPAM

### Intelligence

- Ask AI
- Anomalies
- Recommendations

### Analytics

- Reports

### Administration

- Users & Roles
- Integrations
- Notifications
- AI Settings
- Audit
- System Settings

---

# 11. GLOBAL HEADER

The global header includes:

- page title;
- breadcrumbs;
- global search;
- site selector;
- Ask AI;
- health indicator;
- critical-alert indicator;
- notifications;
- user menu;
- optional dark/light selector.

Example:

```text
Network Overview

[ Search users, IPs, devices... ] [Ask AI] [2 Critical] [RW ▼]
```

---

# 12. GLOBAL SEARCH

Search must recognise:

- hostname;
- IP;
- MAC address;
- person;
- username;
- email;
- VLAN;
- switch;
- switch port;
- incident;
- alert;
- site;
- server;
- application;
- destination;
- domain;
- ASN.

Example search:

`10.20.10.84`

Result may show:

- FINANCE-PC04;
- user J. Smith;
- switch port;
- VLAN;
- current traffic;
- recent incidents;
- security state.

---

# 13. COMPLETE PAGE / SCREEN INVENTORY

Netsight should contain the following primary routes.

| Route | Screen |
|---|---|
| `/login` | Secure Login |
| `/` | Network Overview |
| `/network/map` | Network Map |
| `/devices` | Device Inventory |
| `/devices/[id]` | Device Detail |
| `/users` | Users |
| `/users/[id]` | User Detail |
| `/traffic` | Traffic Intelligence |
| `/traffic/flows` | Flow Explorer |
| `/traffic/applications` | Application Traffic |
| `/traffic/destinations` | Destinations |
| `/traffic/anomalies` | Traffic Anomalies |
| `/security` | Security Centre |
| `/security/findings/[id]` | Security Finding Detail |
| `/incidents` | Incident List |
| `/incidents/[id]` | Incident Investigation |
| `/alerts` | Alerts & Automation |
| `/alerts/new` | Alert Builder |
| `/alerts/[id]` | Alert Rule Detail |
| `/diagnostics` | Diagnostics |
| `/diagnostics/[id]` | Diagnostic Session |
| `/internet` | Internet / WAN |
| `/wifi` | Wi-Fi |
| `/inventory` | Inventory |
| `/ipam` | IP Address Management |
| `/config` | Configuration |
| `/config/changes` | Change History |
| `/ai` | Ask Netsight AI |
| `/ai/investigations/[id]` | AI Investigation |
| `/recommendations` | Recommendations |
| `/reports` | Reports |
| `/reports/[id]` | Report Viewer |
| `/admin/users` | User Administration |
| `/admin/roles` | Roles & Permissions |
| `/admin/integrations` | Integrations |
| `/admin/notifications` | Notification Channels |
| `/admin/sites` | Site Administration |
| `/admin/ai` | AI Configuration |
| `/admin/audit` | Audit Log |
| `/settings` | System Settings |

---

# 14. SCREEN: SECURE LOGIN

## Purpose

Allow authorised organisation users to securely sign in.

## Authentication Options

Only normal login mechanisms:

- Continue with Microsoft 365;
- Continue with Google Workspace.

No normal local username/password form.

## Requirements

Display:

- Netsight branding;
- Secure Network Operations Platform;
- Microsoft login;
- Google Workspace login;
- MFA notice;
- security/policy notice.

## Authentication Logic

Validate:

- issuer;
- audience;
- state;
- nonce;
- tenant;
- organisation/domain;
- expiration.

Use server-side session management where practical.

---

# 15. SCREEN: NETWORK OVERVIEW

## Purpose

Provide an immediate picture of overall operational state.

## KPI Cards

### Network Health

Example:

- 98.7%;
- 82 healthy;
- 2 degraded.

### Internet

- 312 Mbps;
- 62% WAN utilisation.

### Security

- 2 Critical;
- 5 High;
- 11 Medium.

### Users

- 74 online;
- 3 guest;
- 4 VPN.

---

## Network Map Preview

Show:

- Internet;
- firewall;
- core switch;
- distribution/access switches;
- departments/server groups.

Status indicators:

- healthy;
- degraded;
- critical;
- offline;
- unknown.

---

## Active Incidents

Show:

- severity;
- incident title;
- affected device;
- age;
- summary.

Click opens incident.

---

## Top Bandwidth Users

Show:

- device/user;
- current throughput;
- percentage.

---

## Application Mix

Examples:

- Microsoft 365;
- YouTube;
- OneDrive;
- Teams;
- Other.

---

# 16. SCREEN: NETWORK MAP

## Purpose

Visualise live topology and dependencies.

## Features

- pan;
- zoom;
- fullscreen;
- search;
- site filtering;
- device filtering;
- healthy/degraded/critical colouring;
- bandwidth overlays;
- dependency paths.

## Node Types

- Internet;
- firewall;
- router;
- switch;
- AP;
- server;
- workstation;
- storage;
- CCTV;
- printer;
- IoT.

## Node Interaction

Selecting a node opens context panel showing:

- status;
- IP;
- site;
- uptime;
- CPU;
- memory;
- bandwidth;
- incidents;
- alerts;
- dependencies.

Actions:

- Open Device;
- Diagnose;
- View Traffic;
- View Configuration.

---

# 17. SCREEN: DEVICES

## Purpose

Provide complete network/device inventory.

## Header

Example:

> 84 devices discovered

Include:

- Add / Import;
- Run Discovery;
- Discovery Settings.

## Filters

- site;
- status;
- device type;
- VLAN;
- owner;
- managed/unmanaged;
- known/unknown;
- risk.

## Table Columns

- Device;
- IP;
- Type;
- User/Owner;
- Site;
- Traffic;
- Status;
- Risk;
- Last Seen.

## Example States

- Healthy;
- Degraded;
- High Risk;
- Unknown;
- Offline.

---

# 18. SCREEN: DEVICE DETAIL

## Tabs

### Overview

- hostname;
- IP;
- MAC;
- type;
- model;
- OS;
- owner;
- user;
- VLAN;
- site;
- switch;
- port.

### Health

- uptime;
- CPU;
- memory;
- temperature;
- disk;
- errors.

### Interfaces

- port;
- status;
- speed;
- traffic;
- error rate.

### Traffic

- bandwidth;
- applications;
- destinations;
- flows.

### Security

- findings;
- vulnerabilities;
- Wazuh state;
- Suricata events.

### Configuration

- current configuration;
- history;
- differences.

### Events

Chronological activity.

### Incidents

Related incidents.

---

# 19. SCREEN: USERS

## Purpose

Provide identity-focused network visibility.

## Table

- User;
- Username;
- Department;
- Active devices;
- IPs;
- Traffic;
- Current site;
- Last login;
- Security state.

---

# 20. SCREEN: USER DETAIL

## Profile

- name;
- account;
- department;
- role;
- identity provider;
- authentication state;
- MFA.

## Current Sessions

- device;
- IP;
- MAC;
- VLAN;
- switch/AP;
- VPN.

## Traffic

- download;
- upload;
- applications;
- destinations.

## Behaviour

- normal work hours;
- traffic baseline;
- unusual activities.

## Security

- incidents;
- login anomalies;
- risky endpoints.

---

# 21. SCREEN: TRAFFIC INTELLIGENCE

## Purpose

Answer:

> Who is using bandwidth?

## Major Widgets

### Top Users / Devices

Examples:

- FINANCE-PC04;
- DESIGN-PC03;
- CCTV-NVR;
- BOARDROOM-TV.

### Top Applications

Examples:

- Microsoft 365;
- YouTube;
- OneDrive;
- Teams.

### Recent High-Volume Flows

Columns:

- Source;
- User;
- Application;
- Destination;
- Direction;
- Volume.

---

# 22. SCREEN: FLOW EXPLORER

Advanced traffic investigation.

Filters:

- source IP;
- destination IP;
- user;
- device;
- VLAN;
- application;
- protocol;
- port;
- country;
- ASN;
- upload/download;
- date/time.

Visualisations:

- timeline;
- volume;
- connections;
- application mix;
- destinations.

---

# 23. APPLICATION TRAFFIC PAGE

Display:

- application name;
- category;
- total traffic;
- users;
- devices;
- trend;
- risk;
- business/approved status.

Applications may include:

- Microsoft 365;
- Teams;
- OneDrive;
- Google;
- YouTube;
- WhatsApp;
- TikTok;
- GitHub;
- ChatGPT;
- cloud backup.

---

# 24. DESTINATIONS PAGE

Display:

- domain/IP;
- ASN;
- location;
- reputation;
- first seen;
- last seen;
- users;
- volume;
- risk classification.

---

# 25. TRAFFIC ANOMALIES PAGE

Examples:

- upload 120× baseline;
- unusual destination;
- first-seen ASN;
- abnormal application use;
- traffic outside normal hours;
- data-volume anomaly.

Each anomaly should show:

- baseline;
- observed;
- difference;
- confidence;
- context.

---

# 26. SECURITY CENTRE

## KPI Cards

- Critical Findings;
- High Findings;
- Monitored Endpoints;
- Unknown Devices.

## Security Findings Table

Columns:

- Severity;
- Finding;
- Device;
- User;
- Time;
- Status.

Example findings:

- Possible data exfiltration;
- Suspicious TLS destination;
- Repeated failed logins;
- Suspicious PowerShell activity;
- Unknown device detected;
- Internal scanning;
- Agent offline;
- unusual DNS.

---

# 27. SECURITY FINDING DETAIL

Show:

- severity;
- finding type;
- time;
- evidence;
- device;
- identity;
- source;
- destination;
- security engines;
- recommended actions;
- related incidents.

---

# 28. INCIDENT LIST

Columns:

- Incident ID;
- severity;
- title;
- affected assets;
- owner;
- status;
- opened;
- updated;
- SLA.

Statuses:

- Open;
- Acknowledged;
- Investigating;
- Contained;
- Resolved;
- False Positive.

---

# 29. INCIDENT INVESTIGATION

## Header

Example:

**Possible Data Exfiltration**

`INC-2026-0184`

Status:

- Critical;
- Investigating.

Actions:

- Assign;
- Investigate;
- Isolate Device;
- Create Ticket;
- More.

---

## Device Panel

- hostname;
- IP;
- MAC;
- device type;
- department;
- location;
- last seen.

---

## User Panel

- user;
- username;
- email;
- department;
- role;
- manager;
- last login;
- MFA;
- account state.

---

## AI Assessment

Show:

- conclusion;
- risk;
- confidence;
- evidence.

Example:

> High likelihood of data exfiltration based on unusual outbound volume, timing, destination reputation and behavioural deviation.

---

## Evidence

Possible evidence:

- PCAP;
- suspicious file list;
- process activity;
- DNS logs;
- firewall logs;
- flow records.

---

## Timeline

Automatically correlate:

- login;
- process launch;
- DNS;
- flow;
- IDS;
- incident generation;
- actions.

---

## Context Panel

Show:

- normal upload range;
- observed upload;
- destination;
- ASN;
- reputation;
- first seen;
- related alerts.

---

## Recommendations

Rank actions:

- isolate device;
- collect disk image;
- inspect file access;
- investigate related devices;
- block destination;
- reset credentials.

Recommendations are suggestions until approved.

---

# 30. ALERTS & AUTOMATION

## Hero

Explain:

> A smarter way to stay ahead.

## Active Rules

Examples:

- After-hours staff traffic;
- WAN > 90% for 10 minutes;
- Unknown device joins Staff VLAN;
- Certificate expires within 14 days;
- Large upload deviates from baseline.

Columns:

- Rule;
- Status;
- Severity;
- Last Triggered;
- Actions.

---

# 31. NATURAL-LANGUAGE ALERT CREATOR

User enters:

> Alert me if a staff user uploads a large amount of data after 7 PM or before 6 AM. Ignore approved backup systems.

Netsight AI converts this to:

### Scope

Staff devices/users.

### Condition

Upload exceeds specified threshold relative to baseline.

### Schedule

Outside working hours.

### Exceptions

Known backup infrastructure.

### Severity

High.

### Actions

- email;
- push;
- create incident.

Before activation user selects:

**Review & Activate**

---

# 32. ALERT RULE BUILDER

Advanced manual mode.

Fields:

- name;
- entity;
- metric;
- operator;
- threshold;
- baseline;
- time range;
- duration;
- schedule;
- exclusions;
- severity;
- notification;
- escalation;
- auto-action policy.

---

# 33. CUSTOM ALERT FRAMEWORK

Rule definition:

```text
WHO
+
WHAT
+
CONDITION
+
TIME
+
DURATION
+
CONTEXT
+
BASELINE
+
EXCEPTIONS
+
SEVERITY
+
ACTION
```

---

# 34. AFTER-HOURS MONITORING

Do not assume after-hours activity is malicious.

Common legitimate patterns:

- backup;
- software updates;
- cloud synchronisation;
- CCTV upload;
- patch management;
- remote work;
- replication.

Netsight uses:

- policy;
- historical baseline;
- user/device context;
- destination/application context.

---

# 35. DIAGNOSTICS

## Purpose

Answer:

> Why is this service inaccessible?

## Input

User selects:

- device;
- server;
- website;
- service;
- endpoint.

---

# 36. DIAGNOSTIC SESSION

Example:

**Why is WEB-SRV02 inaccessible?**

Run:

1. DNS;
2. gateway;
3. ICMP;
4. TCP/22;
5. TCP/443;
6. Wazuh agent;
7. CPU;
8. memory;
9. disk;
10. application/service;
11. firewall;
12. route;
13. dependencies;
14. recent changes.

---

# 37. PROBABLE CAUSE PANEL

Example:

**nginx service stopped**

Confidence: High.

Evidence:

- DNS passes;
- ICMP passes;
- SSH passes;
- HTTPS fails;
- nginx stopped;
- server resources healthy.

Recommendation:

> Review nginx logs and prepare a controlled restart.

---

# 38. RECENT CHANGES PANEL

Examples:

- nginx stopped;
- package upgrade;
- config changed;
- firewall rule changed;
- switch config changed;
- maintenance task.

Root-cause engine must correlate failure time with changes.

---

# 39. MULTI-LOCATION PROBES

Probe types:

- cloud/external;
- user LAN;
- server VLAN;
- branch;
- Wi-Fi;
- remote site.

This helps determine:

> available internally but not externally

versus:

> service itself is unavailable.

---

# 40. PATH VISUALISATION

Show:

```text
User
 ↓
AP
 ↓
Access Switch
 ↓
Core
 ↓
Firewall
 ↓
Server
```

Highlight failing hop/service.

---

# 41. INTERNET / WAN

## Metrics

- status;
- ISP;
- capacity;
- throughput;
- latency;
- jitter;
- packet loss;
- uptime;
- outage duration;
- public IP;
- gateway;
- DNS.

## Multi-WAN

Display:

- Primary WAN;
- Backup WAN;
- failover status.

---

# 42. INTERNET SLA

Track:

- monthly uptime;
- downtime;
- degraded periods;
- latency;
- packet loss;
- SLA violations.

Generate evidence for ISP disputes.

---

# 43. WI-FI PAGE

## AP Summary

- online/offline;
- clients;
- traffic;
- channel;
- load.

## Wi-Fi Metrics

- signal strength;
- retransmissions;
- client distribution;
- utilisation;
- roaming;
- authentication failures.

## AI Suggestions

Example:

> AP-07 has 47 clients while AP-08 has 6. Review power levels or AP placement.

---

# 44. INVENTORY

Track:

- network devices;
- servers;
- APs;
- endpoints;
- CCTV;
- printers;
- IoT;
- unknown assets.

Source:

NetBox + discovered telemetry.

---

# 45. IPAM

Show:

- prefixes;
- subnets;
- VLANs;
- IP usage;
- reserved ranges;
- active addresses;
- stale addresses.

NetBox remains authoritative source of intended addressing where deployed.

---

# 46. UNKNOWN DEVICE WORKFLOW

When new MAC/device appears:

1. detect;
2. identify IP;
3. identify MAC;
4. identify AP/switch;
5. identify port;
6. identify VLAN;
7. compare against NetBox;
8. alert;
9. investigate;
10. optionally quarantine after approval.

---

# 47. CONFIGURATION PAGE

Show managed devices and configuration state.

Display:

- current config;
- backup time;
- version;
- compliance;
- drift.

---

# 48. CONFIGURATION CHANGE HISTORY

For every change:

- device;
- timestamp;
- user where available;
- before;
- after;
- diff;
- related incidents.

---

# 49. CHANGE CORRELATION

Example:

```text
14:36 Firewall configuration changed
14:37 Routing changed
14:38 Internet unavailable
```

Netsight displays:

> Outage may correlate with firewall change at 14:36.

---

# 50. CONFIGURATION ROLLBACK

Where supported:

- view previous;
- compare;
- prepare rollback;
- risk analysis;
- approve;
- step-up authentication;
- execute;
- verify;
- audit.

Never direct AI-controlled rollback without policy.

---

# 51. ASK NETSIGHT AI

## Primary Interface

Natural-language chat with network data.

Suggested questions:

- What happened overnight?
- Who used the most bandwidth today?
- Why is WEB-SRV02 inaccessible?
- Which devices are new this week?
- What changed before the outage?
- Were there unusual activities last night?
- Which server is likely to run out of disk?
- Who accessed YouTube today?
- Which users logged in after 20:00?
- Why is the first-floor Wi-Fi slow?

---

# 52. AI ANSWER STRUCTURE

Responses should normally contain:

### Answer

Concise finding.

### Evidence

Telemetry supporting the answer.

### Confidence

Where appropriate.

### Recommendation

Suggested next step.

### Missing Data

If some evidence is unavailable.

---

# 53. AI SECURITY ANALYST

AI correlates:

- Wazuh;
- Suricata;
- flow;
- DNS;
- identity;
- NetBox;
- device history;
- configurations.

AI may create investigation summaries.

---

# 54. AI ROOT-CAUSE ENGINE

Inputs:

- topology;
- availability;
- metrics;
- services;
- flows;
- logs;
- configuration;
- security;
- identity;
- dependencies.

Outputs:

- probable cause;
- confidence;
- evidence;
- next action.

---

# 55. AI MORNING BRIEF

Optional daily brief.

Example:

```text
Network Health: 98%

Overnight:
1 significant anomaly
1 service interruption

Internet:
100% available

Security:
0 Critical
1 High
7 Medium

Recommended review:
Finance-PC03 uploaded 4.8 GB at 02:37.
```

---

# 56. AI PREDICTIONS

Use trend analytics for:

- disk exhaustion;
- bandwidth growth;
- interface error increase;
- capacity pressure;
- certificate expiration;
- repeated device instability.

Predictions must display uncertainty.

---

# 57. AI RECOMMENDATIONS PAGE

Suggestions might include:

- move backup window;
- limit guest Wi-Fi;
- rebalance AP clients;
- inspect CRC errors;
- increase WAN capacity;
- replace unstable device;
- adjust storage.

Every recommendation shows evidence.

---

# 58. AI AUTHORITY LEVELS

## Level 1 — Observe

AI may:

- explain;
- summarise;
- recommend.

## Level 2 — Diagnose

AI may invoke read-only tools:

- ping;
- traceroute;
- DNS;
- port test;
- logs;
- metrics.

## Level 3 — Assisted Remediation

AI prepares action.

Human explicitly approves.

## Level 4 — Controlled Automation

Only deterministic whitelisted policies.

MVP defaults to Levels 1–2.

---

# 59. AI TOOL SECURITY

Runtime AI must use narrow tools.

Examples:

- `get_device_health`
- `query_device_flows`
- `get_security_events`
- `run_ping`
- `run_dns_test`
- `test_tcp_service`
- `get_config_diff`
- `get_topology_path`

Do not expose unrestricted shell.

---

# 60. PROMPT-INJECTION DEFENCE

Telemetry is untrusted.

A hostname containing:

> IGNORE PREVIOUS INSTRUCTIONS

is data.

Trust order:

```text
System Policy
Application Policy
Tool Policy
Authorised User Intent
Telemetry
```

Authorisation must be enforced in code.

---

# 61. REPORTS

Report library includes:

- Daily Network Health;
- Weekly Network Review;
- Monthly Network Summary;
- Monthly Security;
- Bandwidth;
- Internet SLA;
- Device Availability;
- After-Hours Activity;
- Top Users;
- Top Applications;
- New Devices;
- Unknown Devices;
- Config Changes;
- Incident Summary;
- Capacity Forecast;
- Wi-Fi Performance;
- Vulnerability Summary.

---

# 62. REPORT SCHEDULING

Configure:

- frequency;
- recipients;
- format;
- sites;
- sections.

Formats:

- web;
- PDF;
- Excel/CSV;
- email.

---

# 63. USER ADMINISTRATION

Users are federated from approved identity providers.

Admin can:

- enable/disable Netsight access;
- assign Netsight role;
- define site restrictions;
- review sessions;
- revoke sessions.

Do not create normal Netsight passwords.

---

# 64. ROLE MANAGEMENT

Default roles:

- Administrator;
- Network Engineer;
- Security Officer;
- Technician;
- Management;
- Auditor.

Support custom roles.

---

# 65. RBAC + ABAC

Authorisation can use:

- role;
- organisation;
- site;
- resource;
- action;
- risk;
- MFA recency.

Example:

A technician may diagnose a server but not disable a core switch port.

---

# 66. REMOTE ACTIONS

Possible authorised actions:

- ping;
- traceroute;
- DNS;
- TCP test;
- refresh monitoring;
- restart approved service;
- isolate endpoint;
- disable switch port;
- block destination;
- restart device;
- configuration rollback.

---

# 67. REMOTE ACTION RISK MODEL

## Read Only

Automatic for authorised user.

## Low Risk

Confirmation.

## High Risk

Step-up authentication + reason.

## Critical

Step-up MFA + reason + approval, possibly second person.

---

# 68. ACTION APPROVAL SCREEN

Display:

- requested action;
- device;
- user;
- estimated impact;
- risk;
- affected dependencies;
- reason;
- evidence;
- requester;
- approvals.

Buttons:

- Reject;
- Approve.

---

# 69. AUDIT LOG

Record:

- user;
- source IP;
- timestamp;
- action;
- target;
- reason;
- before state;
- after state;
- result;
- approval;
- AI recommendation if applicable.

Audit logs must not be editable by normal administrators.

---

# 70. NOTIFICATIONS

Channels:

- in-app;
- mobile push;
- email;
- webhooks;
- optional Teams;
- optional Slack;
- optional SMS;
- optional WhatsApp.

---

# 71. SEVERITY MODEL

### Critical

Immediate operational/security risk.

### High

Requires urgent investigation.

### Medium

Requires attention.

### Low

Low-priority issue.

### Informational

No immediate action.

---

# 72. ESCALATION

Example:

```text
0 min → ICT Technician
5 min → ICT Officer
15 min → ICT Manager
30 min → Executive escalation
```

Configurable by severity/site/service.

---

# 73. MAINTENANCE WINDOWS

Support planned maintenance.

Suppress:

- expected availability alerts.

Continue:

- security events;
- unusual identity activity.

---

# 74. IDENTITY CORRELATION

Netsight must correlate where evidence allows:

```text
Person
 ↓
Account
 ↓
Device
 ↓
IP
 ↓
MAC
 ↓
Switch / AP
 ↓
Port
 ↓
VLAN
```

Sources:

- Entra ID;
- Google Workspace;
- Active Directory;
- LDAP;
- RADIUS;
- DHCP;
- DNS;
- VPN;
- Wi-Fi controllers;
- Wazuh.

---

# 75. IMPORTANT IDENTITY EDGE CASES

Account for:

- shared PCs;
- multiple devices;
- dynamic DHCP;
- NAT;
- VPN;
- guest devices;
- BYOD;
- expired sessions.

Do not present uncertain correlation as fact.

---

# 76. BACKEND ARCHITECTURE

```text
                         Netsight
                 Web / PWA / Mobile
                          │
                          ▼
                     API Gateway
                          │
         ┌────────────────┼────────────────┐
         │                │                │
      Network          Security          Traffic
         │                │                │
     LibreNMS          Wazuh          Akvorado
     NetBox            Suricata       ClickHouse
         │
     Oxidized
         │
 Blackbox Probes
```

---

# 77. INTEGRATION ABSTRACTION

Required:

```text
Frontend
   │
Netsight API
   │
Domain Services
   │
Adapters
   ├ LibreNMS
   ├ NetBox
   ├ Wazuh
   ├ Suricata
   ├ Akvorado
   ├ ClickHouse
   ├ Oxidized
   └ Blackbox
```

Frontend does not consume vendor APIs.

---

# 78. CANONICAL ENTITIES

- Organisation
- Site
- User
- Identity
- Device
- Interface
- IPAddress
- MACAddress
- Network
- VLAN
- Application
- Destination
- Flow
- Metric
- Alert
- Incident
- Event
- ConfigurationChange
- SecurityFinding
- ProbeResult
- AIInvestigation
- ActionRequest
- Approval
- Report
- AuditEntry

---

# 79. DATA OWNERSHIP

## PostgreSQL

Own:

- Netsight application state;
- incidents;
- alert definitions;
- roles;
- action approvals;
- correlations;
- report settings.

## ClickHouse

Own:

- flow telemetry;
- high-volume traffic history.

## Wazuh/OpenSearch

Own:

- security telemetry/logs.

## LibreNMS

Own:

- network monitoring metrics.

## NetBox

Own:

- intended network state/IPAM.

Do not copy everything into one database.

---

# 80. MULTI-SITE SUPPORT

Support:

- Head Office;
- branches;
- data centres;
- remote sites.

Global dashboard can aggregate all.

Each site page shows:

- health;
- WAN;
- devices;
- users;
- incidents.

---

# 81. MOBILE/PWA

Mobile prioritises:

- critical health;
- alerts;
- incidents;
- Internet;
- traffic;
- diagnostics;
- Ask AI;
- approvals.

Mobile should not simply shrink desktop tables.

Use mobile cards and drill-down patterns.

---

# 82. OUT-OF-BAND MANAGEMENT

Critical sites may include independent LTE/5G connectivity.

Useful for:

- firewall failure;
- WAN failure;
- core-routing failure.

Do not expose device management ports publicly.

---

# 83. SECURITY DEVELOPMENT REQUIREMENTS

Secure development is mandatory.

Align with:

- NIST Secure Software Development Framework;
- OWASP ASVS;
- least privilege;
- secure coding;
- human approval;
- fail-closed behaviour.

---

# 84. SOURCE CONTROL SECURITY

Agents/developers must not:

- push directly to main;
- self-approve;
- merge their own PR;
- disable tests;
- lower security requirements;
- deploy to production without approval.

---

# 85. CI/CD GATES

Where applicable:

- formatting;
- lint;
- type checking;
- unit tests;
- integration tests;
- contract tests;
- E2E tests;
- secret scanning;
- SAST;
- dependency scanning;
- container scanning;
- IaC scanning;
- SBOM.

Security gate failure blocks release.

---

# 86. SECRETS

Never store secrets in:

- Git;
- prompts;
- logs;
- frontend code;
- committed `.env`.

Use a secure secrets system.

---

# 87. FAILURE BEHAVIOUR

Security systems fail closed.

Examples:

Unknown permission:

> DENY

Identity service unavailable for high-risk action:

> DENY

Telemetry missing:

> UNKNOWN

Do not silently treat missing telemetry as healthy.

---

# 88. PERFORMANCE TARGETS

Indicative targets:

- dashboard initial load < 3 seconds under normal conditions;
- common API response < 1 second where source permits;
- global search < 2 seconds;
- critical alerts delivered within seconds;
- historical heavy queries handled asynchronously;
- responsive mobile performance.

---

# 89. AVAILABILITY

Netsight itself must be monitored.

Monitor:

- frontend;
- API;
- workers;
- database;
- Redis;
- adapters;
- telemetry ingestion;
- AI gateway;
- notification service.

---

# 90. SELF-OBSERVABILITY SCREEN

Provide administration health page showing:

- LibreNMS connection;
- NetBox connection;
- Wazuh ingestion;
- Suricata;
- flow ingestion;
- ClickHouse;
- email;
- push;
- AI provider;
- queues;
- DB storage.

---

# 91. DATA RETENTION

Retention configurable separately for:

- raw flow;
- metrics;
- logs;
- security events;
- audit;
- incidents;
- AI investigations;
- reports.

---

# 92. PRIVACY

Because Netsight can reveal user activity:

- role restrictions are mandatory;
- access must be logged;
- management reports should aggregate where appropriate;
- retention must be defined;
- detailed user browsing data should only be exposed where justified.

---

# 93. ERROR STATES

Every screen must support:

- loading;
- empty;
- source unavailable;
- permission denied;
- partial data;
- stale data;
- network error.

Example:

> Flow telemetry has been unavailable since 12:43.

---

# 94. VISUAL DESIGN REQUIREMENTS

Approved design characteristics:

- dark navy sidebar;
- clean light content canvas;
- blue primary actions;
- cyan secondary accents;
- green healthy;
- amber warning;
- red critical;
- grey unknown.

Avoid:

- excessive decorative gradients;
- overly futuristic AI visuals;
- generic neon SOC styling;
- unnecessary white space;
- colourful cards without meaning.

---

# 95. DARK MODE

Netsight should support:

- Light;
- Dark;
- System.

All status colours and visualisations must be tested for both.

---

# 96. ACCESSIBILITY

Target:

- keyboard navigation;
- focus states;
- accessible labels;
- usable contrast;
- colour not being the sole status indicator;
- responsive font sizing;
- screen-reader semantics where practical.

---

# 97. IMPLEMENTATION PHASES

## Phase 0 — Foundation

- repository;
- architecture;
- contracts;
- CI;
- secure development baseline.

## Phase 1 — Authentication & Shell

- Microsoft login;
- Google login;
- sessions;
- RBAC;
- AdminLTE;
- navigation.

## Phase 2 — Network Monitoring

- LibreNMS;
- overview;
- devices;
- health;
- network map.

## Phase 3 — Source of Truth

- NetBox;
- IPAM;
- unknown devices;
- drift.

## Phase 4 — Traffic Intelligence

- Akvorado;
- ClickHouse;
- top users;
- applications;
- destinations.

## Phase 5 — Identity Correlation

- identity;
- DHCP;
- DNS;
- RADIUS;
- Entra/Google.

## Phase 6 — Security

- Wazuh;
- Suricata;
- findings;
- incidents.

## Phase 7 — Alerts

- rules;
- notifications;
- schedules;
- escalations;
- anomaly policies.

## Phase 8 — Diagnostics

- Blackbox;
- service tests;
- path diagnostics;
- root cause.

## Phase 9 — Configuration

- Oxidized;
- changes;
- diffs;
- change correlation.

## Phase 10 — AI

- Ask Netsight;
- evidence;
- RAG;
- AI incident analysis;
- anomaly explanations.

## Phase 11 — Remote Operations

- action requests;
- MFA step-up;
- approval;
- execution;
- verification.

## Phase 12 — Predictive Operations

- forecasts;
- capacity planning;
- controlled automation.

---

# 98. MVP

MVP must include:

- Microsoft/Google login;
- secure session;
- RBAC;
- network overview;
- device inventory;
- device detail;
- topology;
- Internet status;
- LibreNMS integration;
- traffic intelligence;
- security findings;
- customizable alerts;
- email notifications;
- incidents;
- root-cause diagnostics;
- Ask Netsight AI;
- PWA/mobile;
- audit.

Autonomous high-risk actions are excluded from MVP.

---

# 99. MVP ACCEPTANCE TEST

Within approximately 30 seconds an administrator should be able to determine:

1. Is the network healthy?
2. Is Internet connectivity healthy?
3. Which devices are offline?
4. Which devices are degraded?
5. Which endpoint is consuming the most bandwidth?
6. Which user is associated with that endpoint?
7. Which applications are consuming the bandwidth?
8. Are there unusual activities?
9. Are there critical security findings?
10. Why is a monitored server inaccessible?

---

# 100. DESIGN ACCEPTANCE

For every approved screen:

- implementation must be rendered;
- screenshot must be captured;
- comparison must be made with `/designs`;
- major deviations must be corrected.

A UI story is not complete just because it compiles.

---

# 101. DEFINITION OF DONE

A product story is complete only when:

- functional requirements pass;
- design requirements pass;
- architecture is respected;
- error states exist;
- loading states exist;
- RBAC works;
- tests exist;
- tests pass;
- lint passes;
- types pass;
- security gates pass;
- secrets are not introduced;
- audit requirements pass;
- relevant documentation is updated;
- independent review is completed.

---

# 102. FUTURE MODULES

Potential later additions:

- NAC;
- Zero Trust access;
- automated network digital twin;
- topology failure simulation;
- configuration compliance engine;
- patch orchestration;
- change simulation;
- MSP multi-tenancy;
- voice AI;
- full mobile native app;
- automated service restoration;
- procurement/capacity recommendations;
- ISP commercial analytics.

---

# 103. PRIMARY DIFFERENTIATOR

The most important question Netsight must answer is:

# WHY?

Every important operational state should move beyond:

> What is down?

toward:

> Why is it down?

For example:

> Internet is slow because DESIGN-PC03 is uploading a 67 GB OneDrive synchronisation and currently accounts for 54% of outbound WAN traffic.

or:

> WEB-SRV02 is accessible internally but TCP/443 fails externally after firewall ACL 204 was modified.

or:

> SW-ICT is degraded because interface Gi1/0/18 has generated increasing CRC errors for 47 minutes.

---

# 104. FINAL PRODUCT EXPERIENCE

An administrator opens Netsight from anywhere.

They immediately see:

- network health;
- Internet health;
- security;
- users;
- traffic;
- critical incidents.

A warning appears:

> WEB-SRV02 unavailable.

The administrator selects:

**Diagnose**

Netsight checks:

- DNS;
- path;
- gateway;
- ICMP;
- TCP;
- server;
- application;
- configuration.

It returns:

> The network path and server are healthy. nginx is stopped.

The administrator selects:

**Prepare Restart**

Netsight displays:

- target;
- impact;
- risk;
- evidence;
- required authentication.

The administrator approves.

Netsight performs the authorised action.

Then Netsight verifies:

> HTTPS restored.

The incident timeline records:

- detection;
- diagnosis;
- approval;
- action;
- recovery.

This is the intended end-to-end Netsight experience.

---

# 105. PRODUCT PROMISE

Netsight should become the organisation's single operational interface for understanding:

**what is happening, where it is happening, who or what is involved, whether it is normal, why it happened, what evidence supports that conclusion, what should happen next, and whether the action taken resolved the problem.**

**NETSIGHT**

**See everything. Know why. Act securely.**