# FS-001 — LibreNMS Device Vertical Slice

## Objective
After federated login, an authorised operator can view canonical LibreNMS-monitored devices in Netsight and open device detail.

## Scope
- source health;
- device list;
- device detail;
- status mapping;
- freshness;
- RBAC;
- AdminLTE UI.

## Non-scope
- topology;
- traffic;
- write actions;
- AI.

## Acceptance
- upstream healthy -> real canonical devices;
- upstream failed -> source-unavailable state;
- stale cached data visibly stale;
- unauthorised user denied at API;
- no LibreNMS token reaches browser;
- device response validates schema;
- tests include error fixture.
