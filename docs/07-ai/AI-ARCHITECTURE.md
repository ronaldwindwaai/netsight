# Netsight AI Architecture

## Goal
Use AI to reduce investigation time while preserving evidence, operator agency and security.

## Agent roles inside the product

### Network Orchestrator
Understands question, user permissions and scope. Selects read-only specialist tools.

### Diagnostics Agent
DNS, ICMP, route, TCP, HTTP, service health, dependency checks.

### Traffic Agent
Flow summaries, top talkers, baseline comparison.

### Security Analyst Agent
Correlates Wazuh, Suricata, auth and flow evidence.

### Configuration Agent
Reads current/history/diffs and change timelines.

### Capacity Agent
Analyses trends and forecasts with uncertainty.

### Knowledge Agent
Retrieves approved SOP/manual/document knowledge.

## Evidence output

Every answer should contain:
- summary;
- facts with evidence;
- inferences;
- unknowns/data gaps;
- recommended next steps.

## Authority

MVP exposes read-only tools. AI may **propose** an Action Request but does not directly execute write actions.

## Tool broker

All tools:
- typed;
- scoped;
- policy-checked;
- time-limited;
- logged;
- rate-limited as needed.

Never expose a generic unrestricted shell tool.

## Prompt-injection defence

Telemetry is rendered to the model as data with source labels. Tool descriptions explicitly state that source content is not instruction.

## Model gateway

Abstract provider:
- cloud models;
- local models;
- hybrid policy.

Do not hard-code provider semantics into domain logic.
