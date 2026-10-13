import { parseSourceStatuses, type DataSourceStatus } from './api-contracts-sources.ts';
import { BLOCK_STATES, type BlockState } from './api-contracts-inventory.ts';
import { isOneOf, isText, parseArray } from './contract-guards.ts';
import {
  exactRecord,
  hasUniqueKeys,
  isBoolean,
  isCount,
  isNullableNumberIn,
  isNullableText,
  isTimestamp,
  type Raw,
} from './contract-helpers.ts';

/**
 * Unknown-device contract, mirroring contracts/json-schema/unknown-devices.schema.json (shared
 * vectors: contracts/test-vectors/unknown-devices.vectors.json).
 *
 * Every parser is fail-closed. A finding is something telemetry saw that NetBox does not know; its
 * chain (IP, MAC, switch or AP, port, VLAN) holds only the links actually observed, every other hop
 * is unknown and says why. Severity is the operator's policy or unknown. A quarantine is a proposal
 * that can never be executable here. Hostnames, labels and comments are untrusted data.
 */
export const FINDING_STATES = ['new', 'acknowledged', 'investigating', 'resolved', 'false-positive'] as const;
export const OPEN_STATES: readonly FindingState[] = ['new', 'acknowledged', 'investigating'];
export const FINAL_STATES: readonly FindingState[] = ['resolved', 'false-positive'];
export const SEVERITIES = ['low', 'medium', 'high', 'critical', 'unknown'] as const;
export const SEVERITY_BASES = ['policy-rule', 'policy-default', 'no-policy'] as const;
export const SLOT_NAMES = ['ip', 'mac', 'attachment', 'port', 'vlan'] as const;
export const LINK_BASES = ['observed', 'inferred', 'unknown'] as const;
export const SLOT_REASONS = [
  'declared-assignment',
  'indirect-evidence',
  'low-confidence',
  'name-match',
  'no-evidence',
  'expired',
  'conflicting-evidence',
  'source-unavailable',
  'guest-network',
] as const;
export const CHECK_FIELDS = ['ip', 'mac', 'hostname'] as const;
export const CHECK_RESULTS = ['match', 'no-match', 'not-checked'] as const;
export const EVENT_KINDS = [
  'detected',
  'evidence-updated',
  'action-proposed',
  'state-changed',
  'assignee-changed',
  'comment',
  'suppressed-sighting',
] as const;
export const COMPARISON_REASONS = ['no-match', 'name-matches-mac-does-not'] as const;
export const SCAN_SOURCES = ['netbox', 'librenms', 'wazuh'] as const;
export const MAX_EVIDENCE_VERSION = 1_000_000;

export type FindingState = (typeof FINDING_STATES)[number];
export type Severity = (typeof SEVERITIES)[number];
export type SeverityBasis = (typeof SEVERITY_BASES)[number];
export type SlotName = (typeof SLOT_NAMES)[number];
export type LinkBasis = (typeof LINK_BASES)[number];
export type SlotReason = (typeof SLOT_REASONS)[number];
export type CheckField = (typeof CHECK_FIELDS)[number];
export type CheckResult = (typeof CHECK_RESULTS)[number];
export type EventKind = (typeof EVENT_KINDS)[number];
export type ComparisonReason = (typeof COMPARISON_REASONS)[number];
export type ScanSource = (typeof SCAN_SOURCES)[number];

/** The lifecycle: resolved and false-positive are final. Mirrors schemas_unknown_devices.py. */
export const ALLOWED_TRANSITIONS: Record<FindingState, readonly FindingState[]> = {
  new: ['acknowledged', 'resolved', 'false-positive'],
  acknowledged: ['investigating', 'resolved', 'false-positive'],
  investigating: ['resolved', 'false-positive'],
  resolved: [],
  'false-positive': [],
};

export const MAX_PAGE_SIZE = 50;
export const MAX_TIMELINE_PAGE = 200;
const INFERRED_CEILING = 0.7;
const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
export const FINDING_ID = new RegExp(`^unknown-device-${UUID}$`);
const EVENT_ID = new RegExp(`^unknown-device-event-${UUID}$`);
const MAC = /^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/;
const SOURCE = /^[a-z0-9][a-z0-9_.-]{0,31}$/;
const KIND = /^[a-z0-9][a-z0-9-]{0,39}$/;

export interface UnknownDeviceEvidenceRef {
  id: string;
  source: string;
  kind: string;
  observed_at: string;
  confidence: number | null;
}

export interface UnknownDeviceLinkSlot {
  slot: SlotName;
  basis: LinkBasis;
  value: string | null;
  label: string | null;
  attachment_kind: 'switch' | 'ap' | null;
  confidence: number | null;
  reason: SlotReason | null;
  evidence: UnknownDeviceEvidenceRef[];
}

export interface UnknownDeviceEndpoint {
  ip: string | null;
  mac: string | null;
  hostname: string | null;
}

export interface UnknownDeviceCheck {
  field: CheckField;
  result: CheckResult;
  detail: string | null;
}

export interface UnknownDeviceComparison {
  checks: UnknownDeviceCheck[];
  checked_at: string;
  reason: ComparisonReason;
}

export interface UnknownDeviceProposedAction {
  action_type: 'endpoint.isolate';
  state: 'proposed';
  risk: 'C';
  executable: false;
  awaiting: 'action-engine';
  rationale: string;
}

export interface UnknownDeviceFinding {
  id: string;
  state: FindingState;
  severity: Severity;
  severity_basis: SeverityBasis;
  evidence_version: number;
  assignee_id: string | null;
  first_seen_at: string;
  last_seen_at: string;
  seen_count: number;
  recurrence_of: string | null;
  endpoint: UnknownDeviceEndpoint;
  chain: UnknownDeviceLinkSlot[];
  comparison: UnknownDeviceComparison;
  proposed_action: UnknownDeviceProposedAction | null;
}

export interface UnknownDeviceStateCount {
  state: FindingState;
  count: number;
}

export interface UnknownDeviceSeverityCount {
  severity: Severity;
  count: number;
}

export interface UnknownDeviceCounts {
  open: number;
  by_state: UnknownDeviceStateCount[];
  by_severity: UnknownDeviceSeverityCount[];
}

export interface UnknownDeviceEvent {
  id: string;
  finding_id: string;
  seq: number;
  occurred_at: string;
  actor_id: string;
  kind: EventKind;
  state_from: FindingState | null;
  state_to: FindingState | null;
  reason: string | null;
  message: string | null;
  subject_id: string | null;
}

export interface UnknownDeviceList {
  state: BlockState;
  generated_at: string;
  page: number;
  page_size: number;
  total: number;
  items: UnknownDeviceFinding[];
}

export interface UnknownDeviceDetail {
  state: BlockState;
  generated_at: string;
  item: UnknownDeviceFinding | null;
}

export interface UnknownDeviceSummary {
  state: BlockState;
  generated_at: string;
  counts: UnknownDeviceCounts | null;
}

export interface UnknownDeviceTimeline {
  state: BlockState;
  generated_at: string;
  finding_id: string;
  events: UnknownDeviceEvent[];
  after_seq: number;
  next_after_seq: number | null;
}

export interface UnknownDeviceScan {
  state: BlockState;
  generated_at: string;
  sources: DataSourceStatus[];
  created: number;
  refreshed: number;
  suppressed: number;
  unverified: number;
  truncated: boolean;
  incomplete_sources: ScanSource[];
}

const EVIDENCE_KEYS = ['id', 'source', 'kind', 'observed_at', 'confidence'] as const;
const SLOT_KEYS = [
  'slot',
  'basis',
  'value',
  'label',
  'attachment_kind',
  'confidence',
  'reason',
  'evidence',
] as const;
const ENDPOINT_KEYS = ['ip', 'mac', 'hostname'] as const;
const CHECK_KEYS = ['field', 'result', 'detail'] as const;
const COMPARISON_KEYS = ['checks', 'checked_at', 'reason'] as const;
const ACTION_KEYS = ['action_type', 'state', 'risk', 'executable', 'awaiting', 'rationale'] as const;
const FINDING_KEYS = [
  'id',
  'state',
  'severity',
  'severity_basis',
  'evidence_version',
  'assignee_id',
  'first_seen_at',
  'last_seen_at',
  'seen_count',
  'recurrence_of',
  'endpoint',
  'chain',
  'comparison',
  'proposed_action',
] as const;
const COUNTS_KEYS = ['open', 'by_state', 'by_severity'] as const;
const EVENT_KEYS = [
  'id',
  'finding_id',
  'seq',
  'occurred_at',
  'actor_id',
  'kind',
  'state_from',
  'state_to',
  'reason',
  'message',
  'subject_id',
] as const;

// --- leaves ----------------------------------------------------------------------------------------------

export function parseUnknownDeviceEvidenceRef(value: unknown): UnknownDeviceEvidenceRef | null {
  const record = exactRecord(value, EVIDENCE_KEYS);
  if (
    record === null ||
    !isText(record.id, 1, 128) ||
    typeof record.source !== 'string' ||
    !SOURCE.test(record.source) ||
    typeof record.kind !== 'string' ||
    !KIND.test(record.kind) ||
    !isTimestamp(record.observed_at) ||
    !isNullableNumberIn(record.confidence, 0, 1)
  ) {
    return null;
  }
  return {
    id: record.id,
    source: record.source,
    kind: record.kind,
    observed_at: record.observed_at,
    confidence: record.confidence,
  };
}

export function parseUnknownDeviceLinkSlot(value: unknown): UnknownDeviceLinkSlot | null {
  const record = exactRecord(value, SLOT_KEYS);
  if (
    record === null ||
    !isOneOf(record.slot, SLOT_NAMES) ||
    !isOneOf(record.basis, LINK_BASES) ||
    !isNullableText(record.value, 128) ||
    !isNullableText(record.label, 128) ||
    !(record.attachment_kind === null || isOneOf(record.attachment_kind, ['switch', 'ap'] as const)) ||
    !isNullableNumberIn(record.confidence, 0, 1) ||
    !(record.reason === null || isOneOf(record.reason, SLOT_REASONS))
  ) {
    return null;
  }
  const evidence = parseArray(record.evidence, 0, 16, parseUnknownDeviceEvidenceRef);
  if (evidence === null) return null;
  const slot: UnknownDeviceLinkSlot = {
    slot: record.slot,
    basis: record.basis,
    value: record.value,
    label: record.label,
    attachment_kind: record.attachment_kind as 'switch' | 'ap' | null,
    confidence: record.confidence,
    reason: record.reason as SlotReason | null,
    evidence,
  };
  return slotFollowsItsBasis(slot) ? slot : null;
}

function slotFollowsItsBasis(slot: UnknownDeviceLinkSlot): boolean {
  if (slot.basis === 'unknown') {
    return (
      slot.value === null &&
      slot.label === null &&
      slot.attachment_kind === null &&
      slot.confidence === null &&
      slot.evidence.length === 0 &&
      slot.reason !== null
    );
  }
  if (slot.value === null || slot.evidence.length === 0) return false;
  if (slot.basis === 'observed' && slot.reason !== null) return false;
  if (
    slot.basis === 'inferred' &&
    (slot.reason === null || slot.confidence === null || slot.confidence > INFERRED_CEILING)
  ) {
    return false;
  }
  return (slot.slot === 'attachment') === (slot.attachment_kind !== null);
}

export function parseUnknownDeviceEndpoint(value: unknown): UnknownDeviceEndpoint | null {
  const record = exactRecord(value, ENDPOINT_KEYS);
  if (
    record === null ||
    !(record.ip === null || (isText(record.ip, 2, 45) && isCanonicalIp(record.ip))) ||
    !(record.mac === null || (typeof record.mac === 'string' && MAC.test(record.mac))) ||
    !isNullableText(record.hostname, 255) ||
    (record.ip === null && record.mac === null && record.hostname === null)
  ) {
    return null;
  }
  return { ip: record.ip, mac: record.mac, hostname: record.hostname };
}

/** True for a dotted-quad IPv4 or a lower-case IPv6 literal; canonical spelling is the API's job. */
function isCanonicalIp(text: string): boolean {
  const v4 = /^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$/.test(text);
  if (v4) return text.split('.').every((part) => Number(part) <= 255);
  return /^[0-9a-f:.]+$/.test(text) && text.includes(':') && !text.includes(':::');
}

export function parseUnknownDeviceCheck(value: unknown): UnknownDeviceCheck | null {
  const record = exactRecord(value, CHECK_KEYS);
  if (
    record === null ||
    !isOneOf(record.field, CHECK_FIELDS) ||
    !isOneOf(record.result, CHECK_RESULTS) ||
    !isNullableText(record.detail, 255)
  ) {
    return null;
  }
  return { field: record.field, result: record.result, detail: record.detail };
}

export function parseUnknownDeviceComparison(value: unknown): UnknownDeviceComparison | null {
  const record = exactRecord(value, COMPARISON_KEYS);
  if (record === null || !isTimestamp(record.checked_at)) return null;
  const checks = parseArray(record.checks, 3, 3, parseUnknownDeviceCheck);
  if (checks === null || checks.some((check, index) => check.field !== CHECK_FIELDS[index])) {
    return null;
  }
  if (!isOneOf(record.reason, COMPARISON_REASONS)) return null;
  const result = (field: CheckField): CheckResult => checks[CHECK_FIELDS.indexOf(field)].result;
  if (record.reason === 'name-matches-mac-does-not') {
    // The one comparison that carries a match: the name corroborates, but the MAC was asked and differs.
    if (result('ip') === 'match' || result('mac') !== 'no-match' || result('hostname') !== 'match') {
      return null;
    }
  } else if (
    // Otherwise a finding exists only when NetBox matched nothing, and "nothing could be checked"
    // proves nothing.
    checks.some((c) => c.result === 'match') ||
    checks.every((c) => c.result === 'not-checked')
  ) {
    return null;
  }
  return { checks, checked_at: record.checked_at, reason: record.reason };
}

export function parseUnknownDeviceProposedAction(
  value: unknown,
): UnknownDeviceProposedAction | null {
  const record = exactRecord(value, ACTION_KEYS);
  if (
    record === null ||
    record.action_type !== 'endpoint.isolate' ||
    record.state !== 'proposed' ||
    record.risk !== 'C' ||
    record.executable !== false ||
    record.awaiting !== 'action-engine' ||
    !isText(record.rationale, 1, 255)
  ) {
    return null;
  }
  return {
    action_type: 'endpoint.isolate',
    state: 'proposed',
    risk: 'C',
    executable: false,
    awaiting: 'action-engine',
    rationale: record.rationale,
  };
}

// --- finding -----------------------------------------------------------------------------------------------

export function isEvidenceVersion(value: unknown): value is number {
  return (
    typeof value === 'number' &&
    Number.isInteger(value) &&
    value >= 1 &&
    value <= MAX_EVIDENCE_VERSION
  );
}

function isFindingId(value: unknown): value is string {
  return typeof value === 'string' && FINDING_ID.test(value);
}

export function parseUnknownDeviceFinding(value: unknown): UnknownDeviceFinding | null {
  const record = exactRecord(value, FINDING_KEYS);
  if (
    record === null ||
    !isFindingId(record.id) ||
    !isOneOf(record.state, FINDING_STATES) ||
    !isOneOf(record.severity, SEVERITIES) ||
    !isOneOf(record.severity_basis, SEVERITY_BASES) ||
    !isEvidenceVersion(record.evidence_version) ||
    !isNullableText(record.assignee_id, 255) ||
    !isTimestamp(record.first_seen_at) ||
    !isTimestamp(record.last_seen_at) ||
    !isCount(record.seen_count) ||
    record.seen_count < 1 ||
    !(record.recurrence_of === null || isFindingId(record.recurrence_of)) ||
    record.recurrence_of === record.id ||
    (record.severity === 'unknown') !== (record.severity_basis === 'no-policy') ||
    Date.parse(record.last_seen_at) < Date.parse(record.first_seen_at)
  ) {
    return null;
  }
  const endpoint = parseUnknownDeviceEndpoint(record.endpoint);
  const chain = parseArray(record.chain, 5, 5, parseUnknownDeviceLinkSlot);
  const comparison = parseUnknownDeviceComparison(record.comparison);
  const action =
    record.proposed_action === null ? null : parseUnknownDeviceProposedAction(record.proposed_action);
  if (
    endpoint === null ||
    chain === null ||
    comparison === null ||
    (record.proposed_action !== null && action === null) ||
    chain.some((slot, index) => slot.slot !== SLOT_NAMES[index]) ||
    chain[0].value !== endpoint.ip ||
    chain[1].value !== endpoint.mac
  ) {
    return null;
  }
  return {
    id: record.id,
    state: record.state,
    severity: record.severity,
    severity_basis: record.severity_basis,
    evidence_version: record.evidence_version,
    assignee_id: record.assignee_id,
    first_seen_at: record.first_seen_at,
    last_seen_at: record.last_seen_at,
    seen_count: record.seen_count,
    recurrence_of: record.recurrence_of,
    endpoint,
    chain,
    comparison,
    proposed_action: action,
  };
}

// --- counts / events ---------------------------------------------------------------------------------------

export function parseUnknownDeviceStateCount(value: unknown): UnknownDeviceStateCount | null {
  const record = exactRecord(value, ['state', 'count']);
  if (record === null || !isOneOf(record.state, FINDING_STATES) || !isCount(record.count)) return null;
  return { state: record.state, count: record.count };
}

export function parseUnknownDeviceSeverityCount(
  value: unknown,
): UnknownDeviceSeverityCount | null {
  const record = exactRecord(value, ['severity', 'count']);
  if (record === null || !isOneOf(record.severity, SEVERITIES) || !isCount(record.count)) return null;
  return { severity: record.severity, count: record.count };
}

const total = (rows: ReadonlyArray<{ count: number }>): number =>
  rows.reduce((sum, row) => sum + row.count, 0);

export function parseUnknownDeviceCounts(value: unknown): UnknownDeviceCounts | null {
  const record = exactRecord(value, COUNTS_KEYS);
  if (record === null || !isCount(record.open)) return null;
  const byState = parseArray(record.by_state, 0, 5, parseUnknownDeviceStateCount);
  const bySeverity = parseArray(record.by_severity, 0, 5, parseUnknownDeviceSeverityCount);
  if (
    byState === null ||
    bySeverity === null ||
    !hasUniqueKeys(byState, (row) => row.state) ||
    !hasUniqueKeys(bySeverity, (row) => row.severity) ||
    total(byState) !== total(bySeverity) ||
    record.open !== total(byState.filter((row) => OPEN_STATES.includes(row.state)))
  ) {
    return null;
  }
  return { open: record.open, by_state: byState, by_severity: bySeverity };
}

export function parseUnknownDeviceEvent(value: unknown): UnknownDeviceEvent | null {
  const record = exactRecord(value, EVENT_KEYS);
  if (
    record === null ||
    typeof record.id !== 'string' ||
    !EVENT_ID.test(record.id) ||
    !isFindingId(record.finding_id) ||
    typeof record.seq !== 'number' ||
    !Number.isInteger(record.seq) ||
    record.seq < 1 ||
    record.seq > 1_000_000 ||
    !isTimestamp(record.occurred_at) ||
    !isText(record.actor_id, 1, 255) ||
    !isOneOf(record.kind, EVENT_KINDS) ||
    !(record.state_from === null || isOneOf(record.state_from, FINDING_STATES)) ||
    !(record.state_to === null || isOneOf(record.state_to, FINDING_STATES)) ||
    !isNullableText(record.reason, 1000) ||
    !isNullableText(record.message, 4000) ||
    !isNullableText(record.subject_id, 128)
  ) {
    return null;
  }
  const changed = record.kind === 'state-changed';
  const from = record.state_from as FindingState | null;
  const to = record.state_to as FindingState | null;
  if (changed !== (from !== null && to !== null)) return null;
  if (!changed && (from !== null || to !== null)) return null;
  if (changed && from !== null && to !== null) {
    if (!ALLOWED_TRANSITIONS[from].includes(to)) return null;
    if (FINAL_STATES.includes(to) && record.reason === null) return null;
  }
  if (record.kind === 'comment' && record.message === null) return null;
  return {
    id: record.id,
    finding_id: record.finding_id,
    seq: record.seq,
    occurred_at: record.occurred_at,
    actor_id: record.actor_id,
    kind: record.kind,
    state_from: from,
    state_to: to,
    reason: record.reason,
    message: record.message,
    subject_id: record.subject_id,
  };
}

// --- responses -------------------------------------------------------------------------------------------

function frame(record: Raw): { state: BlockState; generated_at: string } | null {
  if (!isOneOf(record.state, BLOCK_STATES) || !isTimestamp(record.generated_at)) return null;
  return { state: record.state, generated_at: record.generated_at };
}

export function parseUnknownDeviceList(value: unknown): UnknownDeviceList | null {
  const record = exactRecord(value, ['state', 'generated_at', 'page', 'page_size', 'total', 'items']);
  const head = record === null ? null : frame(record);
  if (
    record === null ||
    head === null ||
    typeof record.page !== 'number' ||
    !Number.isInteger(record.page) ||
    record.page < 1 ||
    record.page > 100_000 ||
    typeof record.page_size !== 'number' ||
    !Number.isInteger(record.page_size) ||
    record.page_size < 1 ||
    record.page_size > MAX_PAGE_SIZE ||
    !isCount(record.total)
  ) {
    return null;
  }
  const items = parseArray(record.items, 0, MAX_PAGE_SIZE, parseUnknownDeviceFinding);
  if (items === null) return null;
  if (head.state !== 'ok') {
    if (items.length > 0 || record.total !== 0) return null;
  } else if (
    items.length > record.page_size ||
    items.length > record.total ||
    !hasUniqueKeys(items, (item) => item.id)
  ) {
    return null;
  }
  return { ...head, page: record.page, page_size: record.page_size, total: record.total, items };
}

export function parseUnknownDeviceDetail(value: unknown): UnknownDeviceDetail | null {
  const record = exactRecord(value, ['state', 'generated_at', 'item']);
  const head = record === null ? null : frame(record);
  if (record === null || head === null) return null;
  const item = record.item === null ? null : parseUnknownDeviceFinding(record.item);
  if ((record.item !== null && item === null) || (head.state === 'ok') !== (item !== null)) return null;
  return { ...head, item };
}

export function parseUnknownDeviceSummary(value: unknown): UnknownDeviceSummary | null {
  const record = exactRecord(value, ['state', 'generated_at', 'counts']);
  const head = record === null ? null : frame(record);
  if (record === null || head === null) return null;
  const counts = record.counts === null ? null : parseUnknownDeviceCounts(record.counts);
  if ((record.counts !== null && counts === null) || (head.state === 'ok') !== (counts !== null)) {
    return null;
  }
  return { ...head, counts };
}

export function parseUnknownDeviceTimeline(value: unknown): UnknownDeviceTimeline | null {
  const record = exactRecord(value, [
    'state',
    'generated_at',
    'finding_id',
    'events',
    'after_seq',
    'next_after_seq',
  ]);
  const head = record === null ? null : frame(record);
  if (
    record === null ||
    head === null ||
    !isFindingId(record.finding_id) ||
    !isCount(record.after_seq) ||
    !(record.next_after_seq === null || (isCount(record.next_after_seq) && record.next_after_seq >= 1))
  ) {
    return null;
  }
  const events = parseArray(record.events, 0, MAX_TIMELINE_PAGE, parseUnknownDeviceEvent);
  if (events === null) return null;
  if (head.state !== 'ok') {
    if (events.length > 0 || record.next_after_seq !== null) return null;
  } else {
    const seqs = events.map((event) => event.seq);
    const ordered = seqs.every((seq, index) => index === 0 || seq > seqs[index - 1]);
    if (
      !ordered ||
      events.some((event) => event.finding_id !== record.finding_id) ||
      (seqs.length > 0 && seqs[0] <= record.after_seq) ||
      (record.next_after_seq !== null &&
        (seqs.length === 0 || record.next_after_seq !== seqs[seqs.length - 1]))
    ) {
      return null;
    }
  }
  return {
    ...head,
    finding_id: record.finding_id,
    events,
    after_seq: record.after_seq,
    next_after_seq: record.next_after_seq,
  };
}

function parseScanSource(value: unknown): ScanSource | null {
  return isOneOf(value, SCAN_SOURCES) ? value : null;
}

export function parseUnknownDeviceScan(value: unknown): UnknownDeviceScan | null {
  const record = exactRecord(value, [
    'state',
    'generated_at',
    'sources',
    'created',
    'refreshed',
    'suppressed',
    'unverified',
    'truncated',
    'incomplete_sources',
  ]);
  const head = record === null ? null : frame(record);
  if (
    record === null ||
    head === null ||
    !isCount(record.created) ||
    !isCount(record.refreshed) ||
    !isCount(record.suppressed) ||
    !isCount(record.unverified) ||
    !isBoolean(record.truncated)
  ) {
    return null;
  }
  const sources = parseSourceStatuses(record.sources, 'netbox');
  const incomplete = parseArray(record.incomplete_sources, 0, 3, parseScanSource);
  if (sources === null || incomplete === null || new Set(incomplete).size !== incomplete.length) {
    return null;
  }
  const netbox = sources.find((source) => source.source === 'netbox');
  if ((head.state === 'ok') !== (netbox?.state === 'ok')) return null;
  if (
    head.state !== 'ok' &&
    (record.created > 0 || record.refreshed > 0 || record.suppressed > 0 ||
      record.unverified > 0 ||
      incomplete.length > 0)
  ) {
    return null;
  }
  return {
    ...head,
    sources,
    created: record.created,
    refreshed: record.refreshed,
    suppressed: record.suppressed,
    unverified: record.unverified,
    truncated: record.truncated,
    incomplete_sources: incomplete,
  };
}
