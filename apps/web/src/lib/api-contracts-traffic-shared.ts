/**
 * Shared vocabulary and primitives of the Step 7 traffic parsers (flows, lists, anomalies). Every
 * parser built on them is fail-closed: anything that does not satisfy the exact contract returns null.
 */

export const TRAFFIC_STATES = ['not-connected', 'ok', 'unknown'] as const;
export const FILTER_NAMES = [
  'source_ip',
  'destination_ip',
  'device',
  'vlan',
  'application',
  'protocol',
  'port',
  'country',
  'asn',
  'direction',
] as const;
export const FLOW_PROTOCOLS = ['tcp', 'udp', 'icmp', 'other'] as const;
export const FLOW_DIRECTIONS = ['inbound', 'outbound', 'internal', 'unknown'] as const;
export const IDENTITY_BASES = ['observed', 'inferred', 'unknown'] as const;
export const INFERRED_REASONS = [
  'declared-assignment',
  'indirect-evidence',
  'low-confidence',
  'name-match',
  'conflicting-evidence',
] as const;
export const UNKNOWN_REASONS = [
  'no-evidence',
  'expired',
  'conflicting-evidence',
  'multiple-candidates',
  'shared-address',
  'vpn-no-session',
  'guest-network',
  'ip-only',
  'source-unavailable',
  'restricted',
] as const;
export const ATTRIBUTION_LEVELS = ['person', 'endpoint', 'none'] as const;
export const ATTRIBUTION_STATES = [
  'ok',
  'not-connected',
  'unknown',
  'withheld',
  'not-evaluated',
] as const;
export const COHORT_STATES = ['not-applied', 'sufficient', 'too-few-sources'] as const;
export const ROW_VISIBILITIES = ['shown', 'withheld'] as const;
export const COHORT_MIN = 2;
export const COHORT_MAX = 1000;
export const DESTINATION_SCOPES = ['external', 'internal'] as const;
export const DAYLIGHT_SAVING = ['not-applicable', 'none', 'crossed'] as const;
export const POLICY_STATES = ['not-configured', 'configured', 'invalid'] as const;
export const TREND_STATES = ['up', 'down', 'flat', 'new', 'unknown'] as const;
export const RISK_LEVELS = ['low', 'medium', 'high', 'unknown'] as const;
export const APPROVALS = ['approved', 'unapproved', 'unknown'] as const;
export const REPUTATIONS = ['allow-listed', 'deny-listed', 'unknown'] as const;
export const EVALUATION_STATUSES = [
  'evaluated',
  'partial',
  'insufficient-baseline',
  'no-data',
] as const;
export const HISTORY_STATES = ['sufficient', 'insufficient', 'unknown'] as const;
export const LEGITIMATE_PATTERNS = [
  'backup',
  'cloud-sync',
  'cctv-or-nvr',
  'patching-or-updates',
  'replication',
  'scheduled-maintenance',
  'antivirus-update',
  'authorised-remote-work',
] as const;
export const CONFIDENCES = ['low', 'medium', 'high'] as const;

export type FilterName = (typeof FILTER_NAMES)[number];
export type FlowProtocol = (typeof FLOW_PROTOCOLS)[number];
export type FlowDirection = (typeof FLOW_DIRECTIONS)[number];
export type IdentityBasis = (typeof IDENTITY_BASES)[number];
export type AttributionLevel = (typeof ATTRIBUTION_LEVELS)[number];
export type AttributionState = (typeof ATTRIBUTION_STATES)[number];
export type CohortState = (typeof COHORT_STATES)[number];
export type RowVisibility = (typeof ROW_VISIBILITIES)[number];
export type DestinationScope = (typeof DESTINATION_SCOPES)[number];
export type DaylightSaving = (typeof DAYLIGHT_SAVING)[number];
export type PolicyState = (typeof POLICY_STATES)[number];
export type TrendState = (typeof TREND_STATES)[number];
export type RiskLevel = (typeof RISK_LEVELS)[number];
export type Approval = (typeof APPROVALS)[number];
export type Reputation = (typeof REPUTATIONS)[number];
export type EvaluationStatus = (typeof EVALUATION_STATUSES)[number];
export type HistoryState = (typeof HISTORY_STATES)[number];
export type LegitimatePattern = (typeof LEGITIMATE_PATTERNS)[number];
export type Confidence = (typeof CONFIDENCES)[number];
