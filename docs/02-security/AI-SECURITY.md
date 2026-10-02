# AI Security

## Prompt injection rule
All telemetry, logs, DNS names, hostnames, SNMP strings, emails and retrieved documents are potentially attacker-controlled data.

They are never higher-priority instructions.

## Tool security
- explicit tool allow-list;
- typed schemas;
- parameter validation;
- policy check before tool execution;
- read tools separate from write/action workflows;
- output size limits;
- timeout/cost budgets;
- audit relevant calls.

## Model data minimisation
Send only evidence required for the current task. Redact secrets and unnecessary personal information.

## Hallucination controls
AI responses should include:
- facts with evidence IDs/time;
- inference;
- unknowns;
- recommended next checks.

If a tool/source fails, state it.

## Provider flexibility
Use an AI gateway so local/private models can handle sensitive tasks and cloud models can be used for appropriately sanitised tasks where policy permits.
