# Skill: Secure Feature Development

## Trigger
Use for any new or changed application feature.

## Process
1. Read task and relevant PRD/ADR/security docs.
2. Identify assets/trust boundaries affected.
3. Confirm API/data contract.
4. Add acceptance + negative-security tests first where practical.
5. Implement minimal change.
6. Run lint/type/unit/integration/security.
7. Document observability and rollback.

## Guardrails
Never weaken RBAC/auth/security gates to pass tests.
