import {
  BASES,
  PERSON_ID,
  SEVERITIES,
  SOURCE_STATES,
  distinct,
  exactRecord,
  isCanonicalIp,
  isNullableTimestamp,
  isTimestamp,
  parseIdentityLink,
  parseIdentitySession,
  parseSources,
  parseTimeWindow,
  stateMatchesSources,
  type Basis,
  type IdentityLink,
  type IdentitySession,
  type Severity,
  type SourceState,
  type SourceStatus,
  type TimeWindow,
} from './api-contracts-identity-core.ts';
import { isIntegerInRange, isNullableNonBlankText, isOneOf, isText, parseArray } from './contract-guards.ts';

/**
 * The users surfaces of the identity contract (list, detail, aggregate), mirroring
 * contracts/json-schema/identity-users.schema.json. Same rules as the core module: fail-closed
 * parsers, a non-ok state carries no values, every correlation carries its basis and evidence, and
 * every label or signature is untrusted text carried as data.
 */

export interface UserSummary {
  id: string;
  display_name: string | null;
  account_count: number;
  assigned_device_count: number;
  session_count: number;
  presence: Basis;
  last_evidence_at: string | null;
}

export interface UserTrafficItem {
  address: string;
  bytes: number | null;
  covers_window: boolean;
}

export interface UserTraffic {
  state: SourceState;
  basis: 'inferred' | 'unknown';
  window: TimeWindow | null;
  top_n: number;
  items: UserTrafficItem[];
}

export interface UserSecurityItem {
  event_id: string;
  observed_at: string;
  severity: Severity;
  /** Untrusted source text: render as data only. */
  signature: string;
  address: string;
  link: IdentityLink;
}

export interface UserSecurity {
  state: SourceState;
  window: TimeWindow | null;
  items: UserSecurityItem[];
  truncated: boolean;
}

export interface UserProfile {
  id: string;
  display_name: string | null;
  accounts: IdentityLink[];
  assigned_devices: IdentityLink[];
  sessions: IdentitySession[];
}

export interface UserDetailResponse {
  state: SourceState;
  as_of: string;
  window: TimeWindow;
  sources: SourceStatus[];
  user: UserProfile | null;
  traffic: UserTraffic | null;
  security: UserSecurity | null;
}

export interface UsersAggregateResponse {
  state: SourceState;
  as_of: string;
  window: TimeWindow;
  sources: SourceStatus[];
  people_total: number | null;
  with_observed_session: number | null;
  with_inferred_session: number | null;
  without_session_evidence: number | null;
  vpn_sessions: number | null;
}

export interface UserListResponse {
  state: SourceState;
  as_of: string;
  window: TimeWindow;
  sources: SourceStatus[];
  items: UserSummary[];
  page: number;
  page_size: number;
  total: number;
}

// --- users ------------------------------------------------------------------------------------------------------

const SUMMARY_KEYS = [
  'id',
  'display_name',
  'account_count',
  'assigned_device_count',
  'session_count',
  'presence',
  'last_evidence_at',
] as const;

export function parseUserSummary(value: unknown): UserSummary | null {
  const record = exactRecord(value, SUMMARY_KEYS);
  if (
    record === null ||
    typeof record.id !== 'string' ||
    !PERSON_ID.test(record.id) ||
    !isNullableNonBlankText(record.display_name, 128) ||
    !isIntegerInRange(record.account_count, 0, 1000) ||
    !isIntegerInRange(record.assigned_device_count, 0, 1000) ||
    !isIntegerInRange(record.session_count, 0, 1000) ||
    !isOneOf(record.presence, BASES) ||
    !isNullableTimestamp(record.last_evidence_at) ||
    (record.presence === 'unknown' && record.session_count !== 0)
  ) {
    return null;
  }
  return {
    id: record.id,
    display_name: record.display_name,
    account_count: record.account_count,
    assigned_device_count: record.assigned_device_count,
    session_count: record.session_count,
    presence: record.presence,
    last_evidence_at: record.last_evidence_at,
  };
}

const TRAFFIC_ITEM_KEYS = ['address', 'bytes', 'covers_window'] as const;

const ADDRESS_TEXT = /^[0-9a-f:.]{2,45}$/;

function isAddress(value: unknown): value is string {
  return typeof value === 'string' && ADDRESS_TEXT.test(value) && isCanonicalIp(value);
}

export function parseUserTrafficItem(value: unknown): UserTrafficItem | null {
  const record = exactRecord(value, TRAFFIC_ITEM_KEYS);
  if (
    record === null ||
    !isAddress(record.address) ||
    !(record.bytes === null || isIntegerInRange(record.bytes, 0, Number.MAX_SAFE_INTEGER)) ||
    typeof record.covers_window !== 'boolean' ||
    (!record.covers_window && record.bytes !== null)
  ) {
    return null;
  }
  return { address: record.address, bytes: record.bytes, covers_window: record.covers_window };
}

const TRAFFIC_KEYS = ['state', 'basis', 'window', 'top_n', 'items'] as const;

export function parseUserTraffic(value: unknown): UserTraffic | null {
  const record = exactRecord(value, TRAFFIC_KEYS);
  if (record === null) return null;
  const window = record.window === null ? null : parseTimeWindow(record.window);
  const items = parseArray(record.items, 0, 16, parseUserTrafficItem);
  if (
    items === null ||
    (record.window !== null && window === null) ||
    !isOneOf(record.state, SOURCE_STATES) ||
    !isOneOf(record.basis, ['inferred', 'unknown'] as const) ||
    !isIntegerInRange(record.top_n, 0, 100) ||
    !distinct(items.map((item) => item.address))
  ) {
    return null;
  }
  if (record.state !== 'ok') {
    if (record.basis !== 'unknown' || window !== null || record.top_n !== 0 || items.length > 0) {
      return null;
    }
  } else if (record.basis !== 'inferred' || window === null) {
    return null;
  }
  return { state: record.state, basis: record.basis, window, top_n: record.top_n, items };
}

const SECURITY_ITEM_KEYS = [
  'event_id',
  'observed_at',
  'severity',
  'signature',
  'address',
  'link',
] as const;

export function parseUserSecurityItem(value: unknown): UserSecurityItem | null {
  const record = exactRecord(value, SECURITY_ITEM_KEYS);
  if (record === null) return null;
  const link = parseIdentityLink(record.link);
  if (
    link === null ||
    !isText(record.event_id, 1, 128) ||
    !isTimestamp(record.observed_at) ||
    !isOneOf(record.severity, SEVERITIES) ||
    !isText(record.signature, 1, 512) ||
    !isAddress(record.address) ||
    link.relation !== 'identity' ||
    link.basis === 'unknown' ||
    link.source.type !== 'ip' ||
    link.source.id !== record.address
  ) {
    return null;
  }
  return {
    event_id: record.event_id,
    observed_at: record.observed_at,
    severity: record.severity,
    signature: record.signature,
    address: record.address,
    link,
  };
}

const SECURITY_KEYS = ['state', 'window', 'items', 'truncated'] as const;

export function parseUserSecurity(value: unknown): UserSecurity | null {
  const record = exactRecord(value, SECURITY_KEYS);
  if (record === null) return null;
  const window = record.window === null ? null : parseTimeWindow(record.window);
  const items = parseArray(record.items, 0, 20, parseUserSecurityItem);
  if (
    items === null ||
    (record.window !== null && window === null) ||
    !isOneOf(record.state, SOURCE_STATES) ||
    typeof record.truncated !== 'boolean'
  ) {
    return null;
  }
  if (record.state !== 'ok') {
    if (window !== null || items.length > 0 || record.truncated) return null;
  } else {
    if (window === null || !distinct(items.map((item) => item.event_id))) return null;
    const from = Date.parse(window.from);
    const to = Date.parse(window.to);
    if (items.some((item) => Date.parse(item.observed_at) < from || Date.parse(item.observed_at) >= to)) {
      return null;
    }
  }
  return { state: record.state, window, items, truncated: record.truncated };
}

const PROFILE_KEYS = ['id', 'display_name', 'accounts', 'assigned_devices', 'sessions'] as const;

function accountLinkIsAbout(link: IdentityLink, personId: string): boolean {
  if (link.relation !== 'person-account') return false;
  if (link.target !== null) return link.source.id === personId;
  // A disputed account is listed from the account's side: this person is one of the candidates.
  return link.candidates.some((candidate) => candidate.entity.id === personId);
}

export function parseUserProfile(value: unknown): UserProfile | null {
  const record = exactRecord(value, PROFILE_KEYS);
  if (record === null) return null;
  const accounts = parseArray(record.accounts, 0, 50, parseIdentityLink);
  const assigned = parseArray(record.assigned_devices, 0, 50, parseIdentityLink);
  const sessions = parseArray(record.sessions, 0, 50, parseIdentitySession);
  if (
    accounts === null ||
    assigned === null ||
    sessions === null ||
    typeof record.id !== 'string' ||
    !PERSON_ID.test(record.id) ||
    !isNullableNonBlankText(record.display_name, 128)
  ) {
    return null;
  }
  const id = record.id;
  if (
    !accounts.every((link) => accountLinkIsAbout(link, id)) ||
    !assigned.every(
      (link) =>
        link.relation === 'person-device' && link.source.id === id && link.basis === 'inferred',
    ) ||
    !sessions.every((session) => session.links[0].source.id === id)
  ) {
    return null;
  }
  return { id, display_name: record.display_name, accounts, assigned_devices: assigned, sessions };
}

const DETAIL_KEYS = ['state', 'as_of', 'window', 'sources', 'user', 'traffic', 'security'] as const;

export function parseUserDetailResponse(value: unknown): UserDetailResponse | null {
  const record = exactRecord(value, DETAIL_KEYS);
  if (record === null) return null;
  const window = parseTimeWindow(record.window);
  const sources = parseSources(record.sources);
  const user = record.user === null ? null : parseUserProfile(record.user);
  const traffic = record.traffic === null ? null : parseUserTraffic(record.traffic);
  const security = record.security === null ? null : parseUserSecurity(record.security);
  if (
    window === null ||
    sources === null ||
    (record.user !== null && user === null) ||
    (record.traffic !== null && traffic === null) ||
    (record.security !== null && security === null) ||
    !isOneOf(record.state, SOURCE_STATES) ||
    !isTimestamp(record.as_of) ||
    !stateMatchesSources(record.state, sources)
  ) {
    return null;
  }
  const blocks = [user, traffic, security];
  if (record.state !== 'ok' ? blocks.some((block) => block !== null) : blocks.some((block) => block === null)) {
    return null;
  }
  return { state: record.state, as_of: record.as_of, window, sources, user, traffic, security };
}

const AGGREGATE_KEYS = [
  'state',
  'as_of',
  'window',
  'sources',
  'people_total',
  'with_observed_session',
  'with_inferred_session',
  'without_session_evidence',
  'vpn_sessions',
] as const;
const COUNT_KEYS = [
  'people_total',
  'with_observed_session',
  'with_inferred_session',
  'without_session_evidence',
  'vpn_sessions',
] as const;

export function parseUsersAggregateResponse(value: unknown): UsersAggregateResponse | null {
  const record = exactRecord(value, AGGREGATE_KEYS);
  if (record === null) return null;
  const window = parseTimeWindow(record.window);
  const sources = parseSources(record.sources);
  if (
    window === null ||
    sources === null ||
    !isOneOf(record.state, SOURCE_STATES) ||
    !isTimestamp(record.as_of) ||
    !stateMatchesSources(record.state, sources) ||
    !COUNT_KEYS.every(
      (key) => record[key] === null || isIntegerInRange(record[key], 0, Number.MAX_SAFE_INTEGER),
    )
  ) {
    return null;
  }
  const counts = COUNT_KEYS.map((key) => record[key] as number | null);
  if (record.state !== 'ok') {
    if (counts.some((count) => count !== null)) return null;
  } else {
    if (counts.some((count) => count === null)) return null;
    const [total, observed, inferredCount, without] = counts as number[];
    if (total !== observed + inferredCount + without) return null;
  }
  return {
    state: record.state,
    as_of: record.as_of,
    window,
    sources,
    people_total: counts[0],
    with_observed_session: counts[1],
    with_inferred_session: counts[2],
    without_session_evidence: counts[3],
    vpn_sessions: counts[4],
  };
}

const LIST_KEYS = ['state', 'as_of', 'window', 'sources', 'items', 'page', 'page_size', 'total'] as const;

export function parseUserListResponse(value: unknown): UserListResponse | null {
  const record = exactRecord(value, LIST_KEYS);
  if (record === null) return null;
  const window = parseTimeWindow(record.window);
  const sources = parseSources(record.sources);
  const items = parseArray(record.items, 0, 100, parseUserSummary);
  if (
    window === null ||
    sources === null ||
    items === null ||
    !isOneOf(record.state, SOURCE_STATES) ||
    !isTimestamp(record.as_of) ||
    !isIntegerInRange(record.page, 1, 1000) ||
    !isIntegerInRange(record.page_size, 1, 100) ||
    !isIntegerInRange(record.total, 0, Number.MAX_SAFE_INTEGER) ||
    !stateMatchesSources(record.state, sources) ||
    (record.state !== 'ok' && (items.length > 0 || record.total !== 0)) ||
    items.length > record.page_size ||
    record.total < items.length ||
    !distinct(items.map((item) => item.id))
  ) {
    return null;
  }
  return {
    state: record.state,
    as_of: record.as_of,
    window,
    sources,
    items,
    page: record.page,
    page_size: record.page_size,
    total: record.total,
  };
}
