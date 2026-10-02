# Backup & Disaster Recovery

Back up:
- PostgreSQL platform state;
- NetBox if locally operated;
- Netsight configuration;
- alert rules;
- policies;
- incident data;
- audit configuration;
- AI knowledge index metadata;
- encryption/key references according to secrets policy.

Do not assume high-volume telemetry needs the same backup method as platform state.

Define:
- RPO;
- RTO;
- restore owner;
- offsite copy;
- encryption;
- restore test schedule;
- break-glass procedure.
