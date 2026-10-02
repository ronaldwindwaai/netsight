# ADR 0006 — Do Not Duplicate Raw Telemetry
Status: Accepted

## Decision
Netsight stores platform state and references to evidence, while specialised engines remain authoritative for high-volume raw telemetry.

## Consequence
Source availability/freshness must be exposed and queries may span multiple backends.
