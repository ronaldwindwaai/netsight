# Production Deployment Checklist

- [ ] Threat model reviewed
- [ ] OIDC tenant/domain allow-lists correct
- [ ] MFA/conditional access enabled
- [ ] Session settings reviewed
- [ ] RBAC roles assigned
- [ ] Secrets in secrets manager
- [ ] No dev credentials
- [ ] TLS valid
- [ ] Reverse proxy/WAF configured
- [ ] Monitoring engines not publicly exposed
- [ ] DB backups tested
- [ ] Audit pipeline verified
- [ ] Notification delivery tested
- [ ] Source freshness alarms tested
- [ ] High-risk actions disabled until separately approved
- [ ] SBOM generated
- [ ] Security scans green
- [ ] Rollback plan
