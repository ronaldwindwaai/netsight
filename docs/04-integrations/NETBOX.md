# NetBox Integration

Purpose: intended network state / source of truth.

Use REST API for sites, devices, racks, interfaces, IPAM, VLANs, circuits and tenancy metadata as required.

Key feature: reconciliation between intended NetBox objects and discovered LibreNMS/network state.

Do not let discovered telemetry silently overwrite source-of-truth records.
