# ADR 0001 — Vendor Adapter Boundaries
Status: Accepted

## Decision
All external monitoring/security systems are accessed through dedicated adapter modules exposing canonical Netsight contracts.

## Why
Prevents UI/domain coupling to vendor APIs, supports version changes and enables replacement/testing.

## Consequence
Adapters require mapping and contract tests, but platform code remains stable.
