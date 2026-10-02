# AI Architecture Overview

See `docs/07-ai/AI-ARCHITECTURE.md` for the detailed specification.

Core pattern:

```text
User Question
   |
   v
AI Orchestrator
   |
Policy + Identity Context
   |
   +--> Read-only Tool Broker
   |      + diagnostics
   |      + traffic
   |      + security
   |      + topology
   |      + config
   |      + knowledge
   |
   v
Evidence Bundle
   |
   v
Answer: Facts / Inference / Unknowns / Recommendations
```

Write/remediation tools are not directly available to the reasoning model in MVP. The model may create a proposed Action Request. Backend policy and human approval control execution.
