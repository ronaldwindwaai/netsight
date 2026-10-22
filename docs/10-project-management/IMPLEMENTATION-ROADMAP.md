# Implementation Roadmap

## E00 — Foundation
Repo, CI, security gates, Docker, platform skeleton, contracts.

## E01 — Identity & Shell
Microsoft/Google OIDC, sessions, RBAC, AdminLTE shell, audit foundation.

## E02 — Network Monitoring
LibreNMS adapter, devices, interfaces, health, source freshness.

## E03 — Source of Truth & Topology
NetBox, reconciliation, topology and dependencies.

## E04 — Traffic Intelligence
Akvorado/ClickHouse, top talkers, traffic drill-down, baselines.

## E05 — Security
Wazuh + Suricata, security centre, correlated evidence.

## E06 — Alerts & Incidents
Custom rules, schedules, notifications, grouping, escalation, maintenance.

## E07 — Diagnostics
Blackbox, multi-vantage probes, "Why?" workflows, path evidence.

## E08 — Configuration Intelligence
Oxidized, diffs, drift, change correlation.

## E09 — AI Read-Only Copilot
Tool broker, evidence bundles, RAG, evals.

## E10 — Mobile/PWA
Push, mobile incident/diagnostics/approvals.

## E11 — Controlled Remote Actions
Action requests, step-up, approvals, restricted executors, verification.

## E12 — Forecasting/Optimisation
Capacity, predictive warnings and safe recommendations.
Design doc: `docs/12-implementation/FORECASTING.md`. Built as Step 13 (organisation traffic volume; WAN utilisation and inventory growth wait for a history source).
