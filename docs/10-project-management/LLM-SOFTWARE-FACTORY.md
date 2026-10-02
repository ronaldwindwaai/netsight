# LLM Software Factory

## Manager model

One Orchestrator delegates bounded work to specialist agents.

Agents:
- Product/Orchestrator
- Solution Architect
- Network Domain
- Backend
- Frontend
- Integration
- Data
- AI
- DevOps
- Security
- QA
- Reviewer

## Workflow

Issue -> plan -> architecture/contracts -> implementation -> tests -> security -> independent review -> PR -> human approval -> merge -> staging -> acceptance -> controlled production release.

## Branch discipline

An agent never merges its own PR.

## Task contract

Every agent task specifies:
- role;
- input files;
- allowed directories;
- forbidden directories;
- output;
- tests;
- definition of done.

## Parallelism

Parallelise only when contracts are already stable. Do not let frontend/backend agents independently invent conflicting schemas.

## Critique loop

Implementation agent and reviewer/security agent must be separate contexts where practical.

## Human gates

Required for:
- architecture change;
- auth/RBAC;
- high-risk action framework;
- production infrastructure;
- database destructive migration;
- secret management;
- release to production.
