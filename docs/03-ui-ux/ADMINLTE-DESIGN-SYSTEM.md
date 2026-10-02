# AdminLTE Design System for Netsight

## Base
- Next.js App Router
- React
- TypeScript strict
- AdminLTE 4 via official `@adminlte/react`
- Bootstrap 5.3
- Bootstrap Icons
- optional specialised libraries only when justified

## Rule
AdminLTE is the **shell**, not the visual identity.

Use it for:
- DashboardLayout
- sidebar/topbar
- cards
- info/small boxes
- forms
- badges
- tabs
- standard tables/forms where suitable
- dark/light mode infrastructure
- command palette foundation

Build Netsight-specific components for:
- topology map;
- network path;
- flow analytics;
- incident timeline;
- AI evidence;
- dependency impact;
- diagnostics;
- configuration diff;
- action approval.

## Information density
NOC/SOC screens need high information density. Avoid excessive whitespace and oversized marketing cards.

## Semantic states
- healthy
- info
- warning
- high
- critical
- unknown
- maintenance
- stale

Never use colour as the only signal.

## Themes
Support:
- light
- dark
- auto/system

Validate charts/maps in both.

## Global top bar
- menu toggle;
- global search;
- Ask Netsight;
- site selector;
- health summary;
- alert count;
- notifications;
- theme;
- profile.

## Sidebar
- Overview
- Network
  - Map
  - Devices
  - Users
  - Traffic
- Security
  - Security Centre
  - Incidents
  - Alerts
- Operations
  - Diagnostics
  - Configuration
  - Changes
- Infrastructure
  - Inventory/IPAM
  - WAN
  - Wi-Fi
- Intelligence
  - Ask Netsight
  - Anomalies
  - Recommendations
- Analytics
  - Reports
- Administration

## UX anti-patterns
Do not:
- render every KPI as a bright box;
- use random gradients;
- use generic "AI brain" imagery;
- use endless modal dialogs;
- bury evidence behind hover-only UI;
- make critical remote actions one-click;
- copy raw vendor UIs into iframes as the product.

## Responsive design
Mobile prioritises:
1. current health;
2. active incidents;
3. alerts;
4. device/user lookup;
5. traffic;
6. diagnostics;
7. approvals;
8. Ask Netsight.
