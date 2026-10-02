# Security Review Checklist

- [ ] Threat model updated if trust boundary changed
- [ ] Authentication impact reviewed
- [ ] Authorization enforced server-side
- [ ] Negative authorization tests
- [ ] Input schemas/limits
- [ ] Output encoding
- [ ] Parameterised DB access
- [ ] No arbitrary command execution
- [ ] No new public management surface
- [ ] Secrets not logged/committed
- [ ] Dependency review complete
- [ ] Audit event defined for sensitive action
- [ ] Rate limits/abuse controls
- [ ] Error responses do not leak secrets
- [ ] AI data/tool boundary reviewed
- [ ] Step-up/approval requirements correct
- [ ] Rollback plan
