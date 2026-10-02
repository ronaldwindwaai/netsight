# Skill: Integration Adapter

## Trigger
New/changed external system integration.

## Process
- define canonical interface;
- define source auth/least privilege;
- add timeout/retry/rate-limit;
- map IDs and freshness;
- create recorded/synthetic fixtures;
- contract-test mapping/error states;
- expose no source secret to clients.

## Done
Healthy, partial, stale, unavailable and forbidden states are tested.
