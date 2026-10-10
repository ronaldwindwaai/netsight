import { isRfc3339 } from './api-contracts.ts';
import { INCIDENT_SEVERITIES, type IncidentSeverity } from './api-contracts-incident.ts';
import {
  PROBE_LOCATIONS,
  parseDiagnosticRun,
  type DiagnosticConfidence,
  type DiagnosticProbeResult,
  type DiagnosticRun,
  type FaultDomain,
  type ProbeLocation,
} from './api-contracts-diagnostic.ts';
import {
  hasExactKeys,
  isIntegerInRange,
  isNonBlankText,
  isNullableNonBlankText,
  isOneOf,
  isPlainRecord,
  isText,
  parseArray,
  textItem,
} from './contract-guards.ts';

/**
 * Diagnostic session contract, mirroring contracts/json-schema/diagnostic-session.schema.json and the
 * session parts of diagnostic-api.schema.json. Every parser is fail-closed: anything that does not
 * satisfy the exact contract (including the cross-field rules JSON Schema cannot express) returns
 * null and the caller renders an explicit error state. Free text (target, titles, device names,
 * statements) is untrusted data and is never interpreted as an instruction.
 */

export const LOCATION_STATES = ['observed', 'unknown', 'not-connected'] as const;
export const LOCATION_STATUSES = ['pass', 'fail'] as const;
export const EVIDENCE_BASES = ['observed', 'inferred', 'unknown'] as const;
export const CAUSE_BASES = ['inferred', 'unknown'] as const;
export const CAUSE_PATTERNS = ['external-only-failure', 'service-failure', 'other', 'none'] as const;
export const STORE_STATES = ['not-connected', 'ok', 'unknown'] as const;
export const CHANGE_SOURCES = ['incidents', 'alerts', 'configuration-changes'] as const;
export const CHANGE_KINDS = ['incident', 'alert'] as const;
export const CHANGE_SCOPES = ['target', 'time-window'] as const;
export const PATH_TIERS = [
  'user',
  'access-point',
  'access-switch',
  'core',
  'firewall',
  'server',
] as const;
export const HOP_STATES = ['known', 'unknown'] as const;

export type LocationState = (typeof LOCATION_STATES)[number];
export type LocationStatus = (typeof LOCATION_STATUSES)[number];
export type EvidenceBasis = (typeof EVIDENCE_BASES)[number];
export type CausePattern = (typeof CAUSE_PATTERNS)[number];
export type StoreState = (typeof STORE_STATES)[number];
export type ChangeSourceName = (typeof CHANGE_SOURCES)[number];
export type ChangeKind = (typeof CHANGE_KINDS)[number];
export type PathTier = (typeof PATH_TIERS)[number];
export type HopState = (typeof HOP_STATES)[number];

export const MAX_LOCATION_CHECKS = 64;
export const MAX_CAUSE_EVIDENCE = 32;
export const MAX_CHANGE_ITEMS = 20;
export const MAX_SESSION_PAGE_SIZE = 100;
export const MAX_SESSION_LIST_OFFSET = 10_000;

export interface DiagnosticLocationResult {
  location: ProbeLocation;
  state: LocationState;
  status: LocationStatus | null;
  passed: number;
  failed: number;
  unknown_checks: number;
  check_ids: string[];
}

export interface DiagnosticEvidenceItem {
  basis: EvidenceBasis;
  statement: string;
  check_ids: string[];
}

export interface DiagnosticProbableCause {
  domain: FaultDomain | null;
  confidence: DiagnosticConfidence;
  basis: 'inferred' | 'unknown';
  pattern: CausePattern;
  summary: string;
  evidence: DiagnosticEvidenceItem[];
}

export interface DiagnosticChangeSource {
  source: ChangeSourceName;
  state: StoreState;
}

export interface DiagnosticChangeItem {
  kind: ChangeKind;
  ref_id: string;
  /** An incident carries its severity; an alert has none (null). */
  severity: IncidentSeverity | null;
  /**
   * An incident's title is never stored with the session: it is the API's placeholder and
   * `title_redacted` is true unless the caller holds incidents:read. An alert's title is stored.
   */
  title: string;
  title_redacted: boolean;
  occurred_at: string;
  scope: 'target' | 'time-window';
  relation: 'may-correlate';
}

export interface DiagnosticRecentChanges {
  state: StoreState;
  window_start: string;
  window_end: string;
  sources: DiagnosticChangeSource[];
  items: DiagnosticChangeItem[];
}

export interface DiagnosticPathHop {
  tier: PathTier;
  state: HopState;
  device_id: string | null;
  name: string | null;
  highlight: 'suspected' | null;
}

export interface DiagnosticPathLink {
  from_tier: PathTier;
  to_tier: PathTier;
  state: HopState;
}

export interface DiagnosticPath {
  state: StoreState;
  observed_at: string | null;
  hops: DiagnosticPathHop[];
  links: DiagnosticPathLink[];
}

export interface DiagnosticSession {
  run: DiagnosticRun;
  locations: DiagnosticLocationResult[];
  probable_cause: DiagnosticProbableCause;
  recent_changes: DiagnosticRecentChanges;
  path: DiagnosticPath;
}

export interface DiagnosticSessionSummary {
  id: string;
  target: string;
  started_at: string;
  completed_at: string;
  probable_fault_domain: FaultDomain | null;
  confidence: DiagnosticConfidence;
}

export interface DiagnosticSessionResponse {
  state: StoreState;
  session: DiagnosticSession | null;
}

export interface DiagnosticSessionListResponse {
  state: StoreState;
  sessions: DiagnosticSessionSummary[];
  limit: number;
  offset: number;
  next_offset: number | null;
}

const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
const DIAGNOSTIC_ID = new RegExp(`^diagnostic-${UUID}$`);
const DEVICE_ID = new RegExp(`^device-${UUID}$`);

const FAULT_DOMAIN_VALUES: readonly FaultDomain[] = [
  'target',
  'service',
  'host',
  'interface',
  'access-device',
  'core',
  'firewall',
  'wan-dns-external',
];
const CONFIDENCE_VALUES: readonly DiagnosticConfidence[] = ['low', 'medium', 'high', 'unknown'];

/** The path tier a fault domain points at; null when the domain lies outside the path. */
const SUSPECTED_TIER: Record<FaultDomain, PathTier | null> = {
  target: 'server',
  service: 'server',
  host: 'server',
  interface: 'server',
  'access-device': 'access-switch',
  core: 'core',
  firewall: 'firewall',
  'wan-dns-external': null,
};

export function suspectedTier(domain: FaultDomain | null): PathTier | null {
  return domain === null ? null : SUSPECTED_TIER[domain];
}

export function patternFor(domain: FaultDomain | null): CausePattern {
  if (domain === null) return 'none';
  if (domain === 'firewall') return 'external-only-failure';
  return domain === 'service' ? 'service-failure' : 'other';
}

function isTimestamp(value: unknown): value is string {
  return typeof value === 'string' && isRfc3339(value);
}

function isNullableDomain(value: unknown): value is FaultDomain | null {
  return value === null || isOneOf(value, FAULT_DOMAIN_VALUES);
}

function checkIds(value: unknown): string[] | null {
  return parseArray(value, 0, MAX_LOCATION_CHECKS, textItem(1, 128), true);
}

function sameJson(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

// --- locations --------------------------------------------------------------------------------

const LOCATION_KEYS = [
  'location',
  'state',
  'status',
  'passed',
  'failed',
  'unknown_checks',
  'check_ids',
] as const;

export function parseDiagnosticLocationResult(value: unknown): DiagnosticLocationResult | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, LOCATION_KEYS)) return null;
  const ids = checkIds(value.check_ids);
  if (
    !isOneOf(value.location, PROBE_LOCATIONS) ||
    !isOneOf(value.state, LOCATION_STATES) ||
    !(value.status === null || isOneOf(value.status, LOCATION_STATUSES)) ||
    !isIntegerInRange(value.passed, 0, MAX_LOCATION_CHECKS) ||
    !isIntegerInRange(value.failed, 0, MAX_LOCATION_CHECKS) ||
    !isIntegerInRange(value.unknown_checks, 0, MAX_LOCATION_CHECKS) ||
    ids === null
  ) {
    return null;
  }
  // Cross-field rules JSON Schema cannot express.
  if (value.passed + value.failed + value.unknown_checks !== ids.length) return null;
  if (value.state === 'not-connected' && ids.length > 0) return null;
  if (value.state === 'unknown' && (value.passed > 0 || value.failed > 0 || value.unknown_checks === 0)) {
    return null;
  }
  if (value.state === 'observed' && value.passed + value.failed === 0) return null;
  const expected: LocationStatus | null =
    value.state === 'observed' ? (value.failed > 0 ? 'fail' : 'pass') : null;
  if (value.status !== expected) return null;
  return {
    location: value.location,
    state: value.state,
    status: value.status,
    passed: value.passed,
    failed: value.failed,
    unknown_checks: value.unknown_checks,
    check_ids: ids,
  };
}

/** The six location results a run's checks imply (the same derivation the server uses). */
export function deriveLocationResults(
  checks: readonly DiagnosticProbeResult[],
): DiagnosticLocationResult[] {
  return PROBE_LOCATIONS.map((location) => {
    const mine = checks.filter((check) => check.location === location);
    const passed = mine.filter((check) => check.status === 'pass').length;
    const failed = mine.filter((check) => check.status === 'fail').length;
    const state: LocationState =
      mine.length === 0 ? 'not-connected' : passed + failed > 0 ? 'observed' : 'unknown';
    return {
      location,
      state,
      status: state === 'observed' ? (failed > 0 ? 'fail' : 'pass') : null,
      passed,
      failed,
      unknown_checks: mine.length - passed - failed,
      check_ids: mine.map((check) => check.id),
    };
  });
}

// --- probable cause ---------------------------------------------------------------------------

const EVIDENCE_KEYS = ['basis', 'statement', 'check_ids'] as const;
const CAUSE_KEYS = ['domain', 'confidence', 'basis', 'pattern', 'summary', 'evidence'] as const;

function parseEvidenceItem(value: unknown): DiagnosticEvidenceItem | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, EVIDENCE_KEYS)) return null;
  const ids = checkIds(value.check_ids);
  if (
    !isOneOf(value.basis, EVIDENCE_BASES) ||
    !isNonBlankText(value.statement, 1000) ||
    ids === null
  ) {
    return null;
  }
  return { basis: value.basis, statement: value.statement, check_ids: ids };
}

export function parseDiagnosticProbableCause(value: unknown): DiagnosticProbableCause | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, CAUSE_KEYS)) return null;
  const evidence = parseArray(value.evidence, 0, MAX_CAUSE_EVIDENCE, parseEvidenceItem);
  if (
    !isNullableDomain(value.domain) ||
    !isOneOf(value.confidence, CONFIDENCE_VALUES) ||
    !isOneOf(value.basis, CAUSE_BASES) ||
    !isOneOf(value.pattern, CAUSE_PATTERNS) ||
    !isNonBlankText(value.summary, 1000) ||
    evidence === null
  ) {
    return null;
  }
  const named = value.domain !== null;
  if (
    named !== (value.confidence !== 'unknown') ||
    named !== (value.basis === 'inferred') ||
    named !== (value.pattern !== 'none') ||
    value.pattern !== patternFor(value.domain)
  ) {
    return null;
  }
  return {
    domain: value.domain,
    confidence: value.confidence,
    basis: value.basis,
    pattern: value.pattern,
    summary: value.summary,
    evidence,
  };
}

// --- recent changes ---------------------------------------------------------------------------

const SOURCE_KEYS = ['source', 'state'] as const;
const ITEM_KEYS = [
  'kind',
  'ref_id',
  'severity',
  'title',
  'title_redacted',
  'occurred_at',
  'scope',
  'relation',
] as const;
const CHANGES_KEYS = ['state', 'window_start', 'window_end', 'sources', 'items'] as const;

function parseChangeSource(value: unknown): DiagnosticChangeSource | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, SOURCE_KEYS)) return null;
  if (!isOneOf(value.source, CHANGE_SOURCES) || !isOneOf(value.state, STORE_STATES)) return null;
  return { source: value.source, state: value.state };
}

function parseChangeItem(value: unknown): DiagnosticChangeItem | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, ITEM_KEYS)) return null;
  if (
    !isOneOf(value.kind, CHANGE_KINDS) ||
    !isText(value.ref_id, 1, 128) ||
    !isNonBlankText(value.title, 255) ||
    typeof value.title_redacted !== 'boolean' ||
    !isTimestamp(value.occurred_at) ||
    !isOneOf(value.scope, CHANGE_SCOPES) ||
    value.relation !== 'may-correlate'
  ) {
    return null;
  }
  const severity = value.severity;
  if (value.kind === 'incident') {
    if (!isOneOf(severity, INCIDENT_SEVERITIES)) return null;
  } else if (severity !== null || value.title_redacted) {
    return null;
  }
  return {
    kind: value.kind,
    ref_id: value.ref_id,
    severity: severity as IncidentSeverity | null,
    title: value.title,
    title_redacted: value.title_redacted,
    occurred_at: value.occurred_at,
    scope: value.scope,
    relation: 'may-correlate',
  };
}

function changesState(sources: readonly DiagnosticChangeSource[]): StoreState {
  if (sources.some((source) => source.state === 'ok')) return 'ok';
  return sources.every((source) => source.state === 'not-connected') ? 'not-connected' : 'unknown';
}

export function parseDiagnosticRecentChanges(value: unknown): DiagnosticRecentChanges | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, CHANGES_KEYS)) return null;
  const sources = parseArray(value.sources, 3, 3, parseChangeSource);
  const items = parseArray(value.items, 0, MAX_CHANGE_ITEMS, parseChangeItem);
  if (
    !isOneOf(value.state, STORE_STATES) ||
    !isTimestamp(value.window_start) ||
    !isTimestamp(value.window_end) ||
    sources === null ||
    items === null
  ) {
    return null;
  }
  if (Date.parse(value.window_end) < Date.parse(value.window_start)) return null;
  if (!sameJson(sources.map((source) => source.source), CHANGE_SOURCES)) return null;
  if (value.state !== changesState(sources)) return null;
  if (value.state !== 'ok' && items.length > 0) return null;
  const read = new Set(sources.filter((s) => s.state === 'ok').map((s) => s.source));
  if (items.some((item) => !read.has(item.kind === 'incident' ? 'incidents' : 'alerts'))) return null;
  return {
    state: value.state,
    window_start: value.window_start,
    window_end: value.window_end,
    sources,
    items,
  };
}

// --- path -------------------------------------------------------------------------------------

const HOP_KEYS = ['tier', 'state', 'device_id', 'name', 'highlight'] as const;
const LINK_KEYS = ['from_tier', 'to_tier', 'state'] as const;
const PATH_KEYS = ['state', 'observed_at', 'hops', 'links'] as const;

function parsePathHop(value: unknown): DiagnosticPathHop | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, HOP_KEYS)) return null;
  if (
    !isOneOf(value.tier, PATH_TIERS) ||
    !isOneOf(value.state, HOP_STATES) ||
    !(value.device_id === null || (typeof value.device_id === 'string' && DEVICE_ID.test(value.device_id))) ||
    !isNullableNonBlankText(value.name, 255) ||
    !(value.highlight === null || value.highlight === 'suspected')
  ) {
    return null;
  }
  const known = value.state === 'known';
  if (known !== (value.device_id !== null) || known !== (value.name !== null)) return null;
  return {
    tier: value.tier,
    state: value.state,
    device_id: value.device_id,
    name: value.name,
    highlight: value.highlight,
  };
}

function parsePathLink(value: unknown): DiagnosticPathLink | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, LINK_KEYS)) return null;
  if (
    !isOneOf(value.from_tier, PATH_TIERS) ||
    !isOneOf(value.to_tier, PATH_TIERS) ||
    !isOneOf(value.state, HOP_STATES)
  ) {
    return null;
  }
  return { from_tier: value.from_tier, to_tier: value.to_tier, state: value.state };
}

function pathIsConsistent(hops: DiagnosticPathHop[], links: DiagnosticPathLink[]): boolean {
  if (!sameJson(hops.map((hop) => hop.tier), PATH_TIERS)) return false;
  const pairs = PATH_TIERS.slice(1).map((tier, index) => [PATH_TIERS[index], tier]);
  if (!sameJson(links.map((link) => [link.from_tier, link.to_tier]), pairs)) return false;
  if (hops[hops.length - 1].state !== 'known') return false;
  if (hops.filter((hop) => hop.highlight !== null).length > 1) return false;
  return links.every(
    (link, index) =>
      link.state !== 'known' || (hops[index].state === 'known' && hops[index + 1].state === 'known'),
  );
}

export function parseDiagnosticPath(value: unknown): DiagnosticPath | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, PATH_KEYS)) return null;
  const hops = parseArray(value.hops, 0, PATH_TIERS.length, parsePathHop);
  const links = parseArray(value.links, 0, PATH_TIERS.length - 1, parsePathLink);
  if (
    !isOneOf(value.state, STORE_STATES) ||
    !(value.observed_at === null || isTimestamp(value.observed_at)) ||
    hops === null ||
    links === null
  ) {
    return null;
  }
  if (value.state !== 'ok') {
    if (hops.length > 0 || links.length > 0 || value.observed_at !== null) return null;
  } else if (value.observed_at === null || !pathIsConsistent(hops, links)) {
    return null;
  }
  return { state: value.state, observed_at: value.observed_at, hops, links };
}

// --- session ----------------------------------------------------------------------------------

const SESSION_KEYS = ['run', 'locations', 'probable_cause', 'recent_changes', 'path'] as const;

export function parseDiagnosticSession(value: unknown): DiagnosticSession | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, SESSION_KEYS)) return null;
  const run = parseDiagnosticRun(value.run);
  const locations = parseArray(
    value.locations,
    PROBE_LOCATIONS.length,
    PROBE_LOCATIONS.length,
    parseDiagnosticLocationResult,
  );
  const cause = parseDiagnosticProbableCause(value.probable_cause);
  const changes = parseDiagnosticRecentChanges(value.recent_changes);
  const path = parseDiagnosticPath(value.path);
  if (run === null || locations === null || cause === null || changes === null || path === null) {
    return null;
  }
  if (!sameJson(locations, deriveLocationResults(run.checks))) return null;
  if (cause.domain !== run.probable_fault_domain || cause.confidence !== run.confidence) return null;
  const known = new Set(run.checks.map((check) => check.id));
  if (cause.evidence.some((line) => line.check_ids.some((id) => !known.has(id)))) return null;
  if (path.state === 'ok') {
    const highlighted = path.hops.find((hop) => hop.highlight !== null)?.tier ?? null;
    if (highlighted !== suspectedTier(cause.domain)) return null;
  }
  return { run, locations, probable_cause: cause, recent_changes: changes, path };
}

// --- list and responses -----------------------------------------------------------------------

const SUMMARY_KEYS = [
  'id',
  'target',
  'started_at',
  'completed_at',
  'probable_fault_domain',
  'confidence',
] as const;
const RESPONSE_KEYS = ['state', 'session'] as const;
const LIST_KEYS = ['state', 'sessions', 'limit', 'offset', 'next_offset'] as const;

function parseSummary(value: unknown): DiagnosticSessionSummary | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, SUMMARY_KEYS)) return null;
  if (
    typeof value.id !== 'string' ||
    !DIAGNOSTIC_ID.test(value.id) ||
    !isNonBlankText(value.target, 255) ||
    !isTimestamp(value.started_at) ||
    !isTimestamp(value.completed_at) ||
    !isNullableDomain(value.probable_fault_domain) ||
    !isOneOf(value.confidence, CONFIDENCE_VALUES)
  ) {
    return null;
  }
  if ((value.probable_fault_domain === null) !== (value.confidence === 'unknown')) return null;
  return {
    id: value.id,
    target: value.target,
    started_at: value.started_at,
    completed_at: value.completed_at,
    probable_fault_domain: value.probable_fault_domain,
    confidence: value.confidence,
  };
}

/** Fail-closed parse; the session is present exactly when the state is ok. */
export function parseDiagnosticSessionResponse(value: unknown): DiagnosticSessionResponse | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, RESPONSE_KEYS)) return null;
  if (!isOneOf(value.state, STORE_STATES)) return null;
  const session = value.session === null ? null : parseDiagnosticSession(value.session);
  if (value.session !== null && session === null) return null;
  if ((value.state === 'ok') !== (session !== null)) return null;
  return { state: value.state, session };
}

/** Fail-closed parse; only an ok state carries rows or a following page. */
export function parseDiagnosticSessionListResponse(
  value: unknown,
): DiagnosticSessionListResponse | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, LIST_KEYS)) return null;
  const sessions = parseArray(value.sessions, 0, MAX_SESSION_PAGE_SIZE, parseSummary);
  if (
    !isOneOf(value.state, STORE_STATES) ||
    sessions === null ||
    !isIntegerInRange(value.limit, 1, MAX_SESSION_PAGE_SIZE) ||
    !isIntegerInRange(value.offset, 0, MAX_SESSION_LIST_OFFSET) ||
    !(
      value.next_offset === null ||
      isIntegerInRange(value.next_offset, 1, MAX_SESSION_LIST_OFFSET + MAX_SESSION_PAGE_SIZE)
    )
  ) {
    return null;
  }
  if (value.state !== 'ok' && (sessions.length > 0 || value.next_offset !== null)) return null;
  return {
    state: value.state,
    sessions,
    limit: value.limit,
    offset: value.offset,
    next_offset: value.next_offset,
  };
}
