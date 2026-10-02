# Identity Correlation

## Problem
IP addresses change; devices are shared; users have multiple devices; NAT/VPN obscures identity.

## Evidence sources
- IdP directory/account
- device management/endpoint agent
- DHCP lease
- RADIUS/802.1X
- VPN session
- Wi-Fi association
- DNS
- switch MAC table
- asset register

## Model
Each assertion:
- subject identity/device;
- relation;
- source;
- valid_from;
- valid_to;
- observed_at;
- confidence;
- source_native_id.

## Rules
- Never use email as immutable identity ID.
- Never say "user X did Y" if evidence only shows an IP with weak correlation.
- UI should display confidence/ambiguity where relevant.
- Preserve historical correlation for incident reconstruction.
