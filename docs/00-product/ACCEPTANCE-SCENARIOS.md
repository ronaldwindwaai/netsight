# Product Acceptance Scenarios

## A. Identify bandwidth consumer
Given flow telemetry is healthy, an operator can identify the top endpoint, associated identity confidence, VLAN/site, application/service, upload/download volume and historical comparison.

## B. After-hours anomaly
A Finance endpoint normally produces <50 MB 00:00–05:00 but uploads >5 GB to a first-seen destination. Netsight generates a high-priority anomaly with baseline evidence and excludes approved backup/update destinations.

## C. Server inaccessible externally
Internal probe succeeds, host agent healthy, external TCP/443 fails and a recent firewall rule changed. Netsight identifies firewall path as probable fault domain without claiming definitive causality.

## D. Core switch outage
One core device outage causes many downstream symptoms. Netsight creates one root incident and lists affected downstream assets instead of flooding operators.

## E. High-risk remote action
Operator selects "Disable Port." Netsight displays impact, requires reason and step-up auth, verifies permission, creates action request, executes through a restricted connector only after approval, verifies state and audits the result.

## F. Missing telemetry
Akvorado is unavailable. Netsight displays traffic data as stale/unavailable. AI states that current flow evidence is unavailable rather than estimating it.
