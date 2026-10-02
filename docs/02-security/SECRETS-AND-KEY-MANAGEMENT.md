# Secrets and Key Management

Do not store secrets in:
- git;
- prompts;
- screenshots;
- client bundles;
- source maps;
- test fixtures;
- logs.

Use an approved secret manager.

Separate:
- dev/staging/prod;
- read/write integrations;
- per-service identities.

Prefer short-lived tokens/workload identity where available.

Rotate:
- after suspected exposure;
- after break-glass use;
- on staff/offboarding policy;
- according to provider capability and organisation schedule.

`.env.example` contains names only, never real values.
