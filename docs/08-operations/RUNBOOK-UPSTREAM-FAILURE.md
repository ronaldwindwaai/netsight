# Runbook — Upstream Source Failure

When an integration is unavailable:
1. mark source unhealthy;
2. retain last-known data with explicit stale status;
3. do not represent stale data as current;
4. disable dependent AI conclusions where evidence is required;
5. create operational alert after configured grace period;
6. recover automatically when source returns;
7. reconcile missed data where source supports it.

Never replace an upstream failure with an empty "healthy" dataset.
