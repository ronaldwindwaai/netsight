# Multi-Site Support

MVP is one organisation with multiple sites.

Every relevant entity may have `site_id`.

Site-level scope applies to:
- dashboards;
- devices;
- incidents;
- alert policies;
- users/identity evidence;
- reports;
- permissions where configured.

Future MSP/multi-tenant mode requires a separate threat model and stronger tenant-isolation validation; do not assume simple `organisation_id` filters are sufficient without dedicated tests.
