import { hasContractKeys, isRecord, isRfc3339, parseFreshness, type Freshness } from './api-contracts.ts';
import {
  isIntegerInRange,
  isNullableNonBlankText,
  isNonBlankText,
  isOneOf,
  isText,
  parseArray,
} from './contract-guards.ts';

/**
 * Identity-correlation contract, mirroring contracts/json-schema/identity.schema.json and
 * identity-users.schema.json (shared vectors: contracts/test-vectors/identity.vectors.json).
 *
 * Every parser is fail-closed: anything that does not satisfy the exact contract returns null and
 * the caller must render an explicit error state, never a guess. A correlation is observed,
 * inferred or unknown: an observed link names its target, confidence, window and evidence; an
 * inferred link is capped at 0.7 and says why; an unknown link names no target, and an ambiguous
 * one lists its candidates (nothing is ever silently picked). A non-ok state carries no values.
 * Every label, signature and subject value is untrusted source text, carried as data only.
 */

export const ENTITY_KINDS = [
  'person',
  'account',
  'device',
  'ip',
  'mac',
  'switch',
  'ap',
  'port',
  'vlan',
  'hostname',
] as const;
export const BASES = ['observed', 'inferred', 'unknown'] as const;
export const KNOWN_BASES = ['observed', 'inferred'] as const;
export const SOURCE_STATES = ['not-connected', 'unknown', 'ok'] as const;
export const RELATIONS = [
  'person-account',
  'account-device',
  'person-device',
  'account-mac',
  'account-ip',
  'device-ip',
  'device-mac',
  'ip-mac',
  'mac-switch',
  'mac-ap',
  'mac-port',
  'mac-vlan',
  'port-vlan',
  'hostname-ip',
  'hostname-device',
  'identity',
] as const;
export const EVIDENCE_KINDS = [
  'dhcp-lease',
  'radius-session',
  'vpn-session',
  'wifi-association',
  'switch-mac-table',
  'endpoint-agent',
  'directory-account',
  'idp-signin',
  'dns-record',
  'asset-assignment',
] as const;
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
export const SESSION_KINDS = ['wired', 'wifi', 'vpn', 'network'] as const;
export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const;

export type EntityKind = (typeof ENTITY_KINDS)[number];
export type Basis = (typeof BASES)[number];
export type KnownBasis = (typeof KNOWN_BASES)[number];
export type SourceState = (typeof SOURCE_STATES)[number];
export type Relation = (typeof RELATIONS)[number];
export type EvidenceKind = (typeof EVIDENCE_KINDS)[number];
export type InferredReason = (typeof INFERRED_REASONS)[number];
export type UnknownReason = (typeof UNKNOWN_REASONS)[number];
export type Reason = InferredReason | UnknownReason;
export type SessionKind = (typeof SESSION_KINDS)[number];
export type Severity = (typeof SEVERITIES)[number];

/** No inferred correlation reports more than this, whatever a source claimed. */
export const INFERRED_CEILING = 0.7;
const MAX_EVIDENCE = 16;
const MAX_CANDIDATES = 8;
const MAX_ENDPOINT_LINKS = 64;
const MAX_SESSION_LINKS = 80;
const MAX_WINDOW_MS = 31 * 24 * 60 * 60 * 1000;
const BASIS_RANK: Record<Basis, number> = { observed: 0, inferred: 1, unknown: 2 };

export interface EntityRef {
  type: EntityKind;
  id: string;
  /** Untrusted display text (a hostname, a user name): render as data only. */
  label: string | null;
}

export interface EvidenceRef {
  id: string;
  source: string;
  kind: EvidenceKind;
  observed_at: string;
  valid_from: string;
  /** Null when the source recorded no end (the engine then trusts it only for a bounded time). */
  valid_to: string | null;
  confidence: number;
}

export interface Candidate {
  entity: EntityRef;
  basis: KnownBasis;
  confidence: number;
  evidence: EvidenceRef[];
}

export interface IdentityLink {
  relation: Relation;
  source: EntityRef;
  target: EntityRef | null;
  basis: Basis;
  confidence: number | null;
  valid_from: string | null;
  valid_to: string | null;
  as_of: string;
  reason: Reason | null;
  evidence: EvidenceRef[];
  ambiguous: boolean;
  candidates: Candidate[];
}

export interface IdentitySession {
  kind: SessionKind;
  basis: KnownBasis;
  confidence: number;
  valid_from: string;
  valid_to: string;
  links: IdentityLink[];
}

export interface Attribution {
  basis: Basis;
  reason: Reason | null;
  ambiguous: boolean;
  links: IdentityLink[];
  candidates: Candidate[];
}

export interface SourceStatus {
  source: string;
  state: SourceState;
  record_count: number;
  truncated: boolean;
  freshness: Freshness;
}

export interface TimeWindow {
  from: string;
  to: string;
}

export interface ResolveSubject {
  kind: 'ip' | 'mac' | 'hostname';
  value: string;
}

export type ResolveNote = 'register-is-current-state';

export interface ResolveResponse {
  state: SourceState;
  subject: ResolveSubject;
  as_of: string;
  window: TimeWindow;
  sources: SourceStatus[];
  attribution: Attribution;
  endpoint: IdentityLink[];
  /** Qualifies the answer; `register-is-current-state`: a past-time answer resting on a register. */
  notes: ResolveNote[];
}

// --- shared patterns and guards ---------------------------------------------------------------------

const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
export const PERSON_ID = new RegExp(`^person-${UUID}$`);
const ID_PATTERNS: Partial<Record<EntityKind, RegExp>> = {
  person: PERSON_ID,
  account: new RegExp(`^account-${UUID}$`),
  device: new RegExp(`^device-${UUID}$`),
  switch: new RegExp(`^device-${UUID}$`),
  ap: new RegExp(`^device-${UUID}$`),
  port: new RegExp(`^port-${UUID}$`),
  mac: /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/,
  hostname: /^[a-z0-9]([a-z0-9._-]{0,126}[a-z0-9])?$/,
};
const SOURCE_NAME = /^[a-z0-9][a-z0-9_.-]{0,31}$/;
const EVIDENCE_ID = /^[a-z0-9][a-z0-9_.-]{0,31}:.+$/;
const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const VLAN = /^vlan-([1-9]\d{0,3})$/;

function formatIpv6(words: readonly number[]): string {
  let bestStart = -1;
  let bestLength = 0;
  for (let start = 0; start < 8; ) {
    if (words[start] !== 0) {
      start += 1;
      continue;
    }
    let end = start;
    while (end < 8 && words[end] === 0) end += 1;
    if (end - start > bestLength) {
      bestStart = start;
      bestLength = end - start;
    }
    start = end;
  }
  const hex = words.map((word) => word.toString(16));
  if (bestLength < 2) return hex.join(':');
  return `${hex.slice(0, bestStart).join(':')}::${hex.slice(bestStart + bestLength).join(':')}`;
}

/** True for the one canonical spelling of an IPv4 or IPv6 address (RFC 5952, no zone, no mapped form). */
export function isCanonicalIp(value: string): boolean {
  if (IPV4.test(value)) return true;
  if (!/^[0-9a-f:]+$/.test(value) || !value.includes(':')) return false;
  const halves = value.split('::');
  if (halves.length > 2) return false;
  const split = (part: string): string[] => (part === '' ? [] : part.split(':'));
  const head = split(halves[0]);
  const tail = halves.length === 2 ? split(halves[1]) : [];
  if ([...head, ...tail].some((group) => !/^[0-9a-f]{1,4}$/.test(group))) return false;
  const word = (group: string): number => Number.parseInt(group, 16);
  let words: number[];
  if (halves.length === 2) {
    const missing = 8 - head.length - tail.length;
    if (missing < 1) return false;
    words = [...head.map(word), ...new Array<number>(missing).fill(0), ...tail.map(word)];
  } else {
    if (head.length !== 8) return false;
    words = head.map(word);
  }
  // IPv4-mapped (::ffff:a.b.c.d) is never a canonical endpoint id: it is spelled as the IPv4.
  const mapped = words.slice(0, 5).every((w) => w === 0) && words[5] === 0xffff;
  return !mapped && formatIpv6(words) === value;
}

function isCanonicalId(kind: EntityKind, id: string): boolean {
  if (kind === 'ip') return isCanonicalIp(id);
  if (kind === 'vlan') {
    const match = VLAN.exec(id);
    return match !== null && Number(match[1]) >= 1 && Number(match[1]) <= 4094;
  }
  const pattern = ID_PATTERNS[kind];
  return pattern !== undefined && pattern.test(id);
}

type Raw = Record<string, unknown>;

export function exactRecord(value: unknown, keys: readonly string[]): Raw | null {
  return isRecord(value) && hasContractKeys(value, keys) ? (value as Raw) : null;
}

export function isTimestamp(value: unknown): value is string {
  return typeof value === 'string' && isRfc3339(value);
}

export function isNullableTimestamp(value: unknown): value is string | null {
  return value === null || isTimestamp(value);
}

function isConfidence(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 1;
}

function isNullableConfidence(value: unknown): value is number | null {
  return value === null || isConfidence(value);
}

function before(earlier: string, later: string): boolean {
  return Date.parse(earlier) < Date.parse(later);
}

function entityKey(entity: EntityRef): string {
  return `${entity.type}\u0000${entity.id}`;
}

export function distinct(keys: readonly string[]): boolean {
  return new Set(keys).size === keys.length;
}

// --- entity, evidence, candidate ------------------------------------------------------------------------

const ENTITY_KEYS = ['type', 'id', 'label'] as const;

export function parseEntityRef(value: unknown): EntityRef | null {
  const record = exactRecord(value, ENTITY_KEYS);
  if (
    record === null ||
    !isOneOf(record.type, ENTITY_KINDS) ||
    !isText(record.id, 1, 128) ||
    !isNullableNonBlankText(record.label, 128) ||
    !isCanonicalId(record.type, record.id)
  ) {
    return null;
  }
  return { type: record.type, id: record.id, label: record.label };
}

const EVIDENCE_KEYS = [
  'id',
  'source',
  'kind',
  'observed_at',
  'valid_from',
  'valid_to',
  'confidence',
] as const;

export function parseEvidenceRef(value: unknown): EvidenceRef | null {
  const record = exactRecord(value, EVIDENCE_KEYS);
  if (
    record === null ||
    !isText(record.id, 3, 161) ||
    !EVIDENCE_ID.test(record.id) ||
    typeof record.source !== 'string' ||
    !SOURCE_NAME.test(record.source) ||
    !record.id.startsWith(`${record.source}:`) ||
    !isOneOf(record.kind, EVIDENCE_KINDS) ||
    !isTimestamp(record.observed_at) ||
    !isTimestamp(record.valid_from) ||
    !isNullableTimestamp(record.valid_to) ||
    !isConfidence(record.confidence) ||
    (record.valid_to !== null && !before(record.valid_from, record.valid_to))
  ) {
    return null;
  }
  return {
    id: record.id,
    source: record.source,
    kind: record.kind,
    observed_at: record.observed_at,
    valid_from: record.valid_from,
    valid_to: record.valid_to,
    confidence: record.confidence,
  };
}

const CANDIDATE_KEYS = ['entity', 'basis', 'confidence', 'evidence'] as const;

export function parseCandidate(value: unknown): Candidate | null {
  const record = exactRecord(value, CANDIDATE_KEYS);
  if (record === null) return null;
  const entity = parseEntityRef(record.entity);
  const evidence = parseArray(record.evidence, 0, MAX_EVIDENCE, parseEvidenceRef);
  if (
    entity === null ||
    evidence === null ||
    !isOneOf(record.basis, KNOWN_BASES) ||
    !isConfidence(record.confidence) ||
    (record.basis === 'inferred' && record.confidence > INFERRED_CEILING)
  ) {
    return null;
  }
  return { entity, basis: record.basis, confidence: record.confidence, evidence };
}

// --- link ------------------------------------------------------------------------------------------------

const LINK_KEYS = [
  'relation',
  'source',
  'target',
  'basis',
  'confidence',
  'valid_from',
  'valid_to',
  'as_of',
  'reason',
  'evidence',
  'ambiguous',
  'candidates',
] as const;

const RELATION_TYPES: Record<string, readonly [EntityKind, EntityKind]> = {
  'person-account': ['person', 'account'],
  'account-device': ['account', 'device'],
  'person-device': ['person', 'device'],
  'account-mac': ['account', 'mac'],
  'account-ip': ['account', 'ip'],
  'device-ip': ['device', 'ip'],
  'device-mac': ['device', 'mac'],
  'ip-mac': ['ip', 'mac'],
  'mac-switch': ['mac', 'switch'],
  'mac-ap': ['mac', 'ap'],
  'mac-port': ['mac', 'port'],
  'mac-vlan': ['mac', 'vlan'],
  'port-vlan': ['port', 'vlan'],
  'hostname-ip': ['hostname', 'ip'],
  'hostname-device': ['hostname', 'device'],
};
const IDENTITY_SUBJECTS: readonly EntityKind[] = ['ip', 'mac', 'hostname', 'device'];

function endpointsMatch(relation: Relation, source: EntityRef, target: EntityRef): boolean {
  if (relation === 'identity') {
    return target.type === 'person' && IDENTITY_SUBJECTS.includes(source.type);
  }
  const ends = RELATION_TYPES[relation];
  return (
    (source.type === ends[0] && target.type === ends[1]) ||
    (source.type === ends[1] && target.type === ends[0])
  );
}

function candidatesFitRelation(
  relation: Relation,
  source: EntityRef,
  candidates: readonly Candidate[],
): boolean {
  if (relation === 'identity') return true;
  const ends = RELATION_TYPES[relation];
  if (source.type !== ends[0] && source.type !== ends[1]) return false;
  const other = source.type === ends[0] ? ends[1] : ends[0];
  return candidates.every((candidate) => candidate.entity.type === other);
}

function isUnknownReason(value: unknown): value is UnknownReason {
  return isOneOf(value, UNKNOWN_REASONS);
}

function isInferredReason(value: unknown): value is InferredReason {
  return isOneOf(value, INFERRED_REASONS);
}

interface LinkFields {
  target: EntityRef | null;
  confidence: number | null;
  valid_from: string | null;
  valid_to: string | null;
  reason: Reason | null;
  evidence: EvidenceRef[];
  ambiguous: boolean;
  candidates: Candidate[];
}

function knownLinkIsSound(
  basis: KnownBasis,
  relation: Relation,
  source: EntityRef,
  fields: LinkFields,
): boolean {
  const { target, confidence, valid_from, valid_to, reason } = fields;
  if (
    target === null ||
    confidence === null ||
    valid_from === null ||
    valid_to === null ||
    fields.evidence.length === 0 ||
    fields.ambiguous ||
    fields.candidates.length > 0 ||
    !before(valid_from, valid_to) ||
    !endpointsMatch(relation, source, target) ||
    entityKey(source) === entityKey(target)
  ) {
    return false;
  }
  if (basis === 'observed') return reason === null;
  return isInferredReason(reason) && confidence <= INFERRED_CEILING;
}

function unknownLinkIsSound(relation: Relation, source: EntityRef, fields: LinkFields): boolean {
  if (
    fields.target !== null ||
    fields.confidence !== null ||
    fields.valid_from !== null ||
    fields.valid_to !== null ||
    !isUnknownReason(fields.reason)
  ) {
    return false;
  }
  const count = fields.candidates.length;
  if (fields.ambiguous !== count >= 2 || (!fields.ambiguous && count > 0)) return false;
  return (
    distinct(fields.candidates.map((candidate) => entityKey(candidate.entity))) &&
    candidatesFitRelation(relation, source, fields.candidates)
  );
}

export function parseIdentityLink(value: unknown): IdentityLink | null {
  const record = exactRecord(value, LINK_KEYS);
  if (record === null) return null;
  const source = parseEntityRef(record.source);
  const target = record.target === null ? null : parseEntityRef(record.target);
  const evidence = parseArray(record.evidence, 0, MAX_EVIDENCE, parseEvidenceRef);
  const candidates = parseArray(record.candidates, 0, MAX_CANDIDATES, parseCandidate);
  if (
    source === null ||
    (record.target !== null && target === null) ||
    evidence === null ||
    candidates === null ||
    !isOneOf(record.relation, RELATIONS) ||
    !isOneOf(record.basis, BASES) ||
    !isNullableConfidence(record.confidence) ||
    !isNullableTimestamp(record.valid_from) ||
    !isNullableTimestamp(record.valid_to) ||
    !isTimestamp(record.as_of) ||
    typeof record.ambiguous !== 'boolean' ||
    (record.reason !== null && !isOneOf(record.reason, [...INFERRED_REASONS, ...UNKNOWN_REASONS]))
  ) {
    return null;
  }
  const fields: LinkFields = {
    target,
    confidence: record.confidence,
    valid_from: record.valid_from,
    valid_to: record.valid_to,
    reason: record.reason as Reason | null,
    evidence,
    ambiguous: record.ambiguous,
    candidates,
  };
  const sound =
    record.basis === 'unknown'
      ? unknownLinkIsSound(record.relation, source, fields)
      : knownLinkIsSound(record.basis, record.relation, source, fields);
  if (!sound) return null;
  return {
    relation: record.relation,
    source,
    target,
    basis: record.basis,
    confidence: record.confidence,
    valid_from: record.valid_from,
    valid_to: record.valid_to,
    as_of: record.as_of,
    reason: fields.reason,
    evidence,
    ambiguous: record.ambiguous,
    candidates,
  };
}

// --- session, attribution --------------------------------------------------------------------------------

const SESSION_KEYS = ['kind', 'basis', 'confidence', 'valid_from', 'valid_to', 'links'] as const;

function weakest(bases: readonly Basis[]): Basis {
  return bases.reduce((worst, basis) => (BASIS_RANK[basis] > BASIS_RANK[worst] ? basis : worst));
}

export function parseIdentitySession(value: unknown): IdentitySession | null {
  const record = exactRecord(value, SESSION_KEYS);
  if (record === null) return null;
  const links = parseArray(record.links, 2, MAX_SESSION_LINKS, parseIdentityLink);
  if (
    links === null ||
    !isOneOf(record.kind, SESSION_KINDS) ||
    !isOneOf(record.basis, KNOWN_BASES) ||
    !isConfidence(record.confidence) ||
    !isTimestamp(record.valid_from) ||
    !isTimestamp(record.valid_to) ||
    !before(record.valid_from, record.valid_to)
  ) {
    return null;
  }
  const [first, second] = links;
  if (
    first.relation !== 'person-account' ||
    (second.relation !== 'account-mac' && second.relation !== 'account-ip') ||
    second.source === null ||
    first.target === null ||
    entityKey(second.source) !== entityKey(first.target) ||
    links.some((link) => link.basis === 'unknown') ||
    weakest(links.map((link) => link.basis)) !== record.basis
  ) {
    return null;
  }
  const lowest = Math.min(...links.map((link) => link.confidence as number));
  if (Math.abs(record.confidence - lowest) > 1e-9) return null;
  return {
    kind: record.kind,
    basis: record.basis,
    confidence: record.confidence,
    valid_from: record.valid_from,
    valid_to: record.valid_to,
    links,
  };
}

const ATTRIBUTION_KEYS = ['basis', 'reason', 'ambiguous', 'links', 'candidates'] as const;

function attributionIsSound(
  basis: Basis,
  reason: Reason | null,
  ambiguous: boolean,
  links: readonly IdentityLink[],
  candidates: readonly Candidate[],
): boolean {
  if (links.some((link) => link.relation !== 'identity')) return false;
  if (basis === 'unknown') {
    if (links.length > 0 || !isUnknownReason(reason)) return false;
    const count = candidates.length;
    return (
      ambiguous === count >= 2 &&
      (ambiguous || count === 0) &&
      distinct(candidates.map((candidate) => entityKey(candidate.entity)))
    );
  }
  if (links.length === 0 || ambiguous || candidates.length > 0) return false;
  if (basis === 'observed' ? reason !== null : !isInferredReason(reason)) return false;
  if (links.some((link) => link.basis === 'unknown')) return false;
  const ranks = links.map((link) => BASIS_RANK[link.basis]);
  if (ranks.some((rank, index) => index > 0 && rank < ranks[index - 1])) return false;
  if (links[0].basis !== basis) return false;
  return distinct(links.map((link) => (link.target === null ? '' : entityKey(link.target))));
}

export function parseAttribution(value: unknown): Attribution | null {
  const record = exactRecord(value, ATTRIBUTION_KEYS);
  if (record === null) return null;
  const links = parseArray(record.links, 0, MAX_CANDIDATES, parseIdentityLink);
  const candidates = parseArray(record.candidates, 0, MAX_CANDIDATES, parseCandidate);
  if (
    links === null ||
    candidates === null ||
    !isOneOf(record.basis, BASES) ||
    typeof record.ambiguous !== 'boolean' ||
    (record.reason !== null && !isOneOf(record.reason, [...INFERRED_REASONS, ...UNKNOWN_REASONS]))
  ) {
    return null;
  }
  const reason = record.reason as Reason | null;
  if (!attributionIsSound(record.basis, reason, record.ambiguous, links, candidates)) return null;
  return { basis: record.basis, reason, ambiguous: record.ambiguous, links, candidates };
}

// --- sources, window -----------------------------------------------------------------------------------------

const SOURCE_KEYS = ['source', 'state', 'record_count', 'truncated', 'freshness'] as const;

export function parseSourceStatus(value: unknown): SourceStatus | null {
  const record = exactRecord(value, SOURCE_KEYS);
  if (record === null) return null;
  const freshness = parseFreshness(record.freshness);
  if (
    freshness === null ||
    typeof record.source !== 'string' ||
    !SOURCE_NAME.test(record.source) ||
    !isOneOf(record.state, SOURCE_STATES) ||
    !isIntegerInRange(record.record_count, 0, 5000) ||
    typeof record.truncated !== 'boolean' ||
    (record.state !== 'ok' && (record.record_count !== 0 || record.truncated))
  ) {
    return null;
  }
  return {
    source: record.source,
    state: record.state,
    record_count: record.record_count,
    truncated: record.truncated,
    freshness,
  };
}

const WINDOW_KEYS = ['from', 'to'] as const;

export function parseTimeWindow(value: unknown): TimeWindow | null {
  const record = exactRecord(value, WINDOW_KEYS);
  if (
    record === null ||
    !isTimestamp(record.from) ||
    !isTimestamp(record.to) ||
    !before(record.from, record.to) ||
    Date.parse(record.to) - Date.parse(record.from) > MAX_WINDOW_MS
  ) {
    return null;
  }
  return { from: record.from, to: record.to };
}

/** The state is derived: any source read is ok; else any failure is unknown; else not-connected. */
export function stateMatchesSources(state: SourceState, sources: readonly SourceStatus[]): boolean {
  if (!distinct(sources.map((source) => source.source))) return false;
  const states = new Set(sources.map((source) => source.state));
  const expected: SourceState = states.has('ok')
    ? 'ok'
    : states.has('unknown')
      ? 'unknown'
      : 'not-connected';
  return state === expected;
}

export function parseSources(value: unknown): SourceStatus[] | null {
  return parseArray(value, 0, 8, parseSourceStatus);
}

// --- resolve ----------------------------------------------------------------------------------------------------

const SUBJECT_KEYS = ['kind', 'value'] as const;
const RESOLVE_KEYS = [
  'state',
  'subject',
  'as_of',
  'window',
  'sources',
  'attribution',
  'endpoint',
  'notes',
] as const;
const RESOLVE_NOTES = ['register-is-current-state'] as const;

function parseNotes(value: unknown): ResolveNote[] | null {
  const notes = parseArray(value, 0, 4, (item) => (isOneOf(item, RESOLVE_NOTES) ? item : null));
  return notes !== null && new Set(notes).size === notes.length ? notes : null;
}

function parseSubject(value: unknown): ResolveSubject | null {
  const record = exactRecord(value, SUBJECT_KEYS);
  if (
    record === null ||
    !isOneOf(record.kind, ['ip', 'mac', 'hostname'] as const) ||
    !isText(record.value, 1, 128)
  ) {
    return null;
  }
  return { kind: record.kind, value: record.value };
}

export function parseResolveResponse(value: unknown): ResolveResponse | null {
  const record = exactRecord(value, RESOLVE_KEYS);
  if (record === null) return null;
  const subject = parseSubject(record.subject);
  const window = parseTimeWindow(record.window);
  const sources = parseSources(record.sources);
  const attribution = parseAttribution(record.attribution);
  const endpoint = parseArray(record.endpoint, 0, MAX_ENDPOINT_LINKS, parseIdentityLink);
  const notes = parseNotes(record.notes);
  if (
    notes === null ||
    subject === null ||
    window === null ||
    sources === null ||
    attribution === null ||
    endpoint === null ||
    !isOneOf(record.state, SOURCE_STATES) ||
    !isTimestamp(record.as_of) ||
    !stateMatchesSources(record.state, sources) ||
    (record.state !== 'ok' &&
      (endpoint.length > 0 || attribution.basis !== 'unknown' || attribution.ambiguous))
  ) {
    return null;
  }
  return { state: record.state, subject, as_of: record.as_of, window, sources, attribution, endpoint, notes };
}


// `isNonBlankText` is re-exported for the view helpers that render untrusted names.
export { isNonBlankText };
