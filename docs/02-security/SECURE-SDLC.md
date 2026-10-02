# Secure SDLC

Netsight development aligns with:
- NIST SP 800-218 Secure Software Development Framework (SSDF);
- OWASP ASVS 5.0 as application-security verification guidance.

## Pipeline gates

Requirement -> threat model -> design -> code -> unit -> type/lint -> SAST -> dependency scan -> secret scan -> IaC/container scan -> integration -> DAST where appropriate -> security review -> staging -> acceptance -> approved production release.

A required security check failing blocks merge/release.

## Required practices

### Requirements
Security acceptance criteria are added before implementation.

### Design
Threat model new trust boundaries, auth changes, remote actions, new data classes and AI tools.

### Implementation
- typed validation;
- secure defaults;
- least privilege;
- no secrets in repo;
- no insecure TLS bypass;
- no shell command composition from untrusted text;
- output encoding;
- parameterised DB access.

### Verification
- unit;
- integration;
- contract;
- auth/RBAC negative tests;
- E2E;
- SAST;
- dependency/vulnerability;
- secret;
- container/IaC;
- manual review for critical flows.

### Release
- immutable artifact;
- SBOM;
- provenance where supported;
- signed release/tag where practical;
- change record;
- rollback plan.

### Operations
- vulnerability intake;
- patch SLA;
- incident response;
- dependency updates;
- key/token rotation;
- security logging.

## Minimum patch targets

Organisation must define exact SLAs. Suggested:
- actively exploited/critical reachable issue: emergency;
- critical: days, not weeks;
- high: short fixed SLA;
- medium/low: scheduled according to risk.

Never let an LLM invent an acceptance exception.
