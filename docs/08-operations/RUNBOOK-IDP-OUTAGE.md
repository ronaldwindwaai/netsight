# Runbook — Identity Provider Outage

1. Determine whether Microsoft, Google or local DNS/network is the fault domain.
2. Existing sessions follow configured lifetime; do not silently extend indefinitely.
3. Do not enable ordinary local password login as a workaround.
4. If emergency access is required, follow controlled break-glass process.
5. Alert on break-glass use.
6. Rotate break-glass credentials after use.
7. Perform post-incident review.
