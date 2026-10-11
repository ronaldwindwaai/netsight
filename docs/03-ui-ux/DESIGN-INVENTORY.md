# Design Asset Inventory

Status: approved visual source of truth. Source directory: `/designs`.
Rule: these images define layout, information architecture, component choice and
visual language. They do **not** define data. All values inside the mockups are
illustrative (note inconsistent dates Oct 2024 / Apr 2025 / May 2024 and hostname
drift FIN-PC04 vs FINANCE-PC04). Never hardcode mockup values; never ship the
images themselves as UI. Every data surface still obeys `UI-STATES.md`.

## File naming note

Current filenames are ChatGPT export timestamps and are not self-describing.
Recommended rename (do not rename without design-owner approval):

| Current file | Recommended name |
| --- | --- |
| ChatGPT Image Oct 4, 2026, 09_02_39 AM-1.png | overview.png |
| ChatGPT Image Oct 4, 2026, 09_03_53 AM-1.png | (duplicate of overview.png — byte-identical size/content; archive) |
| ChatGPT Image Oct 4, 2026, 09_03_55 AM-2.png | login.png |
| ChatGPT Image Oct 4, 2026, 09_03_56 AM-3.png | network-map.png |
| ChatGPT Image Oct 4, 2026, 09_03_58 AM-4.png | devices.png |
| ChatGPT Image Oct 4, 2026, 09_03_59 AM-5.png | traffic.png |
| ChatGPT Image Oct 4, 2026, 09_04_01 AM-6.png | security-centre.png |
| ChatGPT Image Oct 4, 2026, 09_04_03 AM-7.png | incident-detail.png |
| ChatGPT Image Oct 4, 2026, 09_04_04 AM-8.png | alerts.png |
| ChatGPT Image Oct 4, 2026, 09_04_06 AM-9.png | diagnostics.png |
| ChatGPT Image Oct 4, 2026, 09_04_08 AM-10.png | ask-ai.png |

## Global shell (applies to every authenticated screen)

- Left dark-navy sidebar: NETSIGHT "N" logo + "Network Intelligence & Operations";
  nav: Overview, Network Map, Devices, Traffic, Security Centre, Incidents, Alerts,
  Diagnostics, Ask AI, Reports, Settings; footer "Netsight v1.0.0 / Built for a
  more resilient connected world."
- Top bar: page icon + title + breadcrumb (Home > …), global search (`⌘K`),
  primary "Ask AI" button, critical-count badge button ("2 Critical"), user avatar
  with dropdown.
- Content: light grey-blue background, white rounded cards, dense NOC/SOC spacing
  (per ADMINLTE-DESIGN-SYSTEM.md — high density, no marketing cards).
- Semantic palette: healthy green, degraded amber, critical red, offline/unknown
  grey; severity never by colour alone (ACCESSIBILITY.md).
- Login screen uses the same sidebar with only "Login" active.

## Screen inventory

| # | Screen | Route | Design file(s) | Slice | Key content (visual truth) |
| --- | --- | --- | --- | --- | --- |
| 1 | Login | `/login` | 09_03_55 AM-2 | S1 | Centred card on light-blue globe motif; Netsight logo; "Sign in with your organisation account"; SSO buttons "Continue with Microsoft 365" / "Continue with Google Workspace"; shield divider "MFA and organisation access policies apply."; tagline "See everything. Know why. Act securely." No local password form — ever (ADR 0002). |
| 2 | Network Overview | `/overview` | 09_02_39 AM-1; 09_03_53 AM-1 (identical duplicate) | S1 | 4 KPI cards with icon/value/sub-line/sparkline/drill chevron: Network Health (%, healthy/degraded counts), Internet (Mbps, WAN utilisation), Security (critical count, high/medium), Users (online, guest/VPN). Live Network Map panel (mini topology + Healthy/Degraded/Critical legend). Active Incidents list (severity pill, relative time, title, summary, View all). Top Bandwidth Users (labelled progress bars). Application Mix (donut + legend with Mbps). |
| 3 | Network Map | `/network/map` | 09_03_56 AM-3 | S3 | Full-width Live Topology canvas; toolbar (search nodes, All Nodes filter, Topology view selector, overflow menu); vertical tree Internet → Firewall-01 → Core-SW01 → SW-Finance/SW-ICT/SW-Servers → endpoints; per-node: icon, status dot, name, throughput, CPU, status word; legend incl. Offline; zoom controls (−, %, +, fit, fullscreen). |
| 4 | Devices | `/devices` | 09_03_58 AM-4 | S2 | Discovery header ("84 devices discovered", online/offline counts, last scan; Add/Import, Run Discovery, Discovery Settings). Device Inventory card: search, Filters, Export, overflow. Table: DEVICE (icon, name, OS), IP (+MAC), TYPE (pill), USER/OWNER (name + dept), TRAFFIC (value + sparkline), STATUS (pill + detail line e.g. "High CPU (78%)"); pagination "Showing 1–10 of 84". |
| 5 | Traffic Intelligence | `/traffic` | 09_03_59 AM-5 | S4 | Header card "Who is using bandwidth?" + time-range picker (Last 24 hours). Top Users / Devices (bars, Mbps, %). Top Applications (brand icons, bars). Recent High-Volume Flows table: SOURCE (IP + device), USER (id + name), APPLICATION (icon + name), DESTINATION (IP + host), DIRECTION (Outbound/Inbound pill), VOLUME. |
| 6 | Security Centre | `/security` | 09_04_01 AM-6 | S5 | 4 KPI cards with 24h deltas: Critical Findings, High Findings, Monitored Endpoints, Unknown Devices. Security Findings card with time-range picker; table: SEVERITY (pill), FINDING (title + description), DEVICE (icon + name + IP), USER (name + dept), TIME (relative + absolute), STATUS (Open / Investigating / In Progress / Monitoring / Resolved pills); pagination. |
| 7 | Incident Detail | `/incidents/[incidentId]` | 09_04_03 AM-7 | S6 | Header: title, Critical + Investigating pills, detected time; action bar: Assign, Investigate, Isolate Device (high-risk — approval-gated), Create Ticket, overflow. Device card (hostname/IP/MAC/type/dept/location/last seen). User card (avatar, At Risk badge, username/email/dept/role/manager/last login/MFA/account status). AI Assessment (risk badge, confidence %, narrative). Evidence file cards (type, size, time, download). Timeline (vertical; category pills: Detection/Anomaly/Process/Authentication). Right rail: Context (outbound traffic chart normal-vs-current, stat boxes, destination IP intel: location/ASN/reputation/related alerts), Recommended Next Steps (numbered, priority pills, "Ask AI to investigate"). |
| 8 | Alerts & Automation | `/alerts` | 09_04_04 AM-8 | S6 | Hero banner "A smarter way to stay ahead" + Flexible rules / Context-aware / Automate action blurbs. Active Rules table (rule name + description, enable toggle, severity pill, last triggered + incident count, overflow) + Create Alert Rule button. Create with AI panel: request textarea (char counter), Netsight interpretation (Scope / Condition / Schedule / Exceptions / Action rows, Edit), Review & Activate button. |
| 9 | Diagnostics | `/diagnostics` | 09_04_06 AM-9 | S7 | Hero "ROOT CAUSE ANALYSIS — Why is WEB-SRV02 inaccessible?" + End-to-end testing / Correlate insights / AI-assisted analysis blurbs. Automated Diagnostic: numbered check list (DNS Resolution, Gateway Reachability, ICMP Ping, TCP Port 22/443, Wazuh Agent, CPU, Memory, nginx Service) each with PASS/FAIL pill, latency/result, expandable row; completion time + run-at. Probable Cause card (confidence badge, narrative, Recommendation callout, View Logs + Prepare Restart — Prepare Restart is approval-gated). Recent Changes timeline. |
| 10 | Ask Netsight AI | `/ask` | 09_04_08 AM-10 | S9 | Chat thread: user bubble (avatar, timestamp); AI answer with bolded conclusion, Evidence list (severity/status dot + statement + time-range chip), Suggestion callout, Helpful / Not helpful + save/export/overflow; composer (attachment, input, send); disclaimer "Netsight AI can access your network data, devices, users, traffic, incidents and more." Right rail: "Try asking" example prompts. |

## Screens with no approved design (design gap — do not improvise visuals)

Incidents list/board, Reports, Settings/Administration, Users & Identity, Device
detail (tab structure exists in SCREEN-SPECS.md), Configuration/Change history,
Internet / WAN (`/internet`, Step 5: only the overview "Internet" KPI card is
designed; the page follows SCREEN-SPECS.md "Internet card and `/internet`"),
Users & Identity (`/users`, `/users/[userId]`, Step 6: no design exists; built from SCREEN-SPECS.md "Users"
and the key/value user card of the Incident Detail design, using only fields a source provides; the
"At Risk" badge, department, manager and MFA fields of that card are not data and are not shown).
For these screens: derive layout only from SCREEN-SPECS.md + the global shell
above, and request approved designs before polishing. Do not create alternative
visual concepts.
