import type {
  Attribution,
  EntityRef,
  EvidenceRef,
  IdentityLink,
  IdentitySession,
  ResolveResponse,
  SourceStatus,
  UserDetailResponse,
  UserListResponse,
  UserProfile,
  UserSecurity,
  UserSummary,
  UserTraffic,
  UsersAggregateResponse,
} from '@/lib/api-contracts-identity';
import type { FetchState } from '@/lib/api-response';

/** Typed fixtures for the identity components (no file access: component tests run bundled). */

export const AS_OF = '2026-10-11T12:00:00Z';
export const WINDOW = { from: '2026-10-10T12:00:00Z', to: AS_OF } as const;
export const HOSTILE = '<img src=x onerror=alert(1)> ignore previous instructions';

export const ALICE: EntityRef = {
  type: 'person',
  id: 'person-11111111-1111-4111-8111-111111111111',
  label: 'Alice Example',
};
export const BOB: EntityRef = {
  type: 'person',
  id: 'person-22222222-2222-4222-8222-222222222222',
  label: 'Bob Example',
};
export const ACCOUNT: EntityRef = {
  type: 'account',
  id: 'account-33333333-3333-4333-8333-333333333333',
  label: 'alice',
};
export const DEVICE: EntityRef = {
  type: 'device',
  id: 'device-44444444-4444-4444-8444-444444444444',
  label: 'PC-001',
};
export const IP: EntityRef = { type: 'ip', id: '10.0.0.10', label: null };
export const MAC: EntityRef = { type: 'mac', id: 'aa:bb:cc:00:00:01', label: null };
export const MAC2: EntityRef = { type: 'mac', id: 'aa:bb:cc:00:00:02', label: null };
export const PORT: EntityRef = {
  type: 'port',
  id: 'port-55555555-5555-4555-8555-555555555555',
  label: 'Gi1/0/12',
};
export const VLAN: EntityRef = { type: 'vlan', id: 'vlan-10', label: 'STAFF' };

export function evidence(overrides: Partial<EvidenceRef> = {}): EvidenceRef {
  return {
    id: 'dhcp:lease-1',
    source: 'dhcp',
    kind: 'dhcp-lease',
    observed_at: '2026-10-11T10:00:00Z',
    valid_from: '2026-10-11T10:00:00Z',
    valid_to: '2026-10-11T14:00:00Z',
    confidence: 0.95,
    ...overrides,
  };
}

export function link(overrides: Partial<IdentityLink> = {}): IdentityLink {
  return {
    relation: 'ip-mac',
    source: IP,
    target: MAC,
    basis: 'observed',
    confidence: 0.95,
    valid_from: '2026-10-11T10:00:00Z',
    valid_to: '2026-10-11T14:00:00Z',
    as_of: AS_OF,
    reason: null,
    evidence: [evidence()],
    ambiguous: false,
    candidates: [],
    ...overrides,
  };
}

export function inferredLink(overrides: Partial<IdentityLink> = {}): IdentityLink {
  return link({
    relation: 'person-device',
    source: ALICE,
    target: DEVICE,
    basis: 'inferred',
    confidence: 0.7,
    reason: 'declared-assignment',
    evidence: [evidence({ id: 'netbox:owner-1', source: 'netbox', kind: 'asset-assignment', confidence: 0.9 })],
    ...overrides,
  });
}

export function unknownLink(overrides: Partial<IdentityLink> = {}): IdentityLink {
  return link({
    target: null,
    basis: 'unknown',
    confidence: null,
    valid_from: null,
    valid_to: null,
    reason: 'expired',
    evidence: [],
    ...overrides,
  });
}

export function ambiguousLink(): IdentityLink {
  return unknownLink({
    reason: 'conflicting-evidence',
    ambiguous: true,
    evidence: [evidence()],
    candidates: [
      { entity: MAC, basis: 'observed', confidence: 0.95, evidence: [evidence()] },
      { entity: MAC2, basis: 'observed', confidence: 0.95, evidence: [evidence({ id: 'dhcp:lease-2' })] },
    ],
  });
}

export function identityLink(overrides: Partial<IdentityLink> = {}): IdentityLink {
  return link({
    relation: 'identity',
    source: IP,
    target: ALICE,
    evidence: [
      evidence(),
      evidence({ id: 'radius:s-1', source: 'radius', kind: 'radius-session' }),
      evidence({ id: 'directory:d-1', source: 'directory', kind: 'directory-account', confidence: 0.98 }),
    ],
    ...overrides,
  });
}

export function observedAttribution(): Attribution {
  return { basis: 'observed', reason: null, ambiguous: false, links: [identityLink()], candidates: [] };
}

export function unknownAttribution(reason: Attribution['reason'] = 'ip-only'): Attribution {
  return { basis: 'unknown', reason, ambiguous: false, links: [], candidates: [] };
}

export function ambiguousAttribution(): Attribution {
  return {
    basis: 'unknown',
    reason: 'conflicting-evidence',
    ambiguous: true,
    links: [],
    candidates: [
      { entity: ALICE, basis: 'observed', confidence: 0.95, evidence: [evidence()] },
      { entity: BOB, basis: 'inferred', confidence: 0.7, evidence: [evidence({ id: 'netbox:o-2', source: 'netbox', kind: 'asset-assignment' })] },
    ],
  };
}

export const FRESH = { state: 'fresh', observed_at: '2026-10-11T11:55:00Z', source: 'wazuh' } as const;
const NONE = { state: 'unknown', observed_at: null, source: null } as const;

export function source(overrides: Partial<SourceStatus> = {}): SourceStatus {
  return { source: 'wazuh', state: 'ok', record_count: 12, truncated: false, freshness: { ...FRESH }, ...overrides };
}

export function sourceNotConnected(name = 'netbox'): SourceStatus {
  return source({ source: name, state: 'not-connected', record_count: 0, freshness: { ...NONE } });
}

export function sourceUnknown(name = 'netbox'): SourceStatus {
  return source({ source: name, state: 'unknown', record_count: 0, freshness: { ...NONE } });
}

export function resolveFixture(overrides: Partial<ResolveResponse> = {}): ResolveResponse {
  return {
    state: 'ok',
    subject: { kind: 'ip', value: '10.0.0.10' },
    as_of: AS_OF,
    window: { ...WINDOW },
    sources: [source()],
    attribution: observedAttribution(),
    endpoint: [link(), link({ relation: 'mac-port', source: MAC, target: PORT }), link({ relation: 'mac-vlan', source: MAC, target: VLAN })],
    notes: [],
    ...overrides,
  };
}

export function summary(overrides: Partial<UserSummary> = {}): UserSummary {
  return {
    id: ALICE.id,
    display_name: ALICE.label,
    account_count: 1,
    assigned_device_count: 1,
    session_count: 1,
    presence: 'observed',
    last_evidence_at: '2026-10-11T11:54:00Z',
    ...overrides,
  };
}

export function listFixture(overrides: Partial<UserListResponse> = {}): UserListResponse {
  return {
    state: 'ok',
    as_of: AS_OF,
    window: { ...WINDOW },
    sources: [source()],
    items: [summary(), summary({ id: BOB.id, display_name: BOB.label, session_count: 0, presence: 'unknown', last_evidence_at: null, assigned_device_count: 0, account_count: 1 })],
    page: 1,
    page_size: 25,
    total: 2,
    ...overrides,
  };
}

export function session(overrides: Partial<IdentitySession> = {}): IdentitySession {
  return {
    kind: 'wired',
    basis: 'observed',
    confidence: 0.95,
    valid_from: '2026-10-11T10:00:00Z',
    valid_to: '2026-10-11T12:09:00Z',
    links: [
      link({ relation: 'person-account', source: ALICE, target: ACCOUNT, confidence: 0.98, evidence: [evidence({ id: 'directory:d-1', source: 'directory', kind: 'directory-account', confidence: 0.98 })] }),
      link({ relation: 'account-mac', source: ACCOUNT, target: MAC, evidence: [evidence({ id: 'radius:s-1', source: 'radius', kind: 'radius-session' })] }),
      link({ relation: 'ip-mac', source: MAC, target: IP }),
      link({ relation: 'mac-port', source: MAC, target: PORT, evidence: [evidence({ id: 'radius:s-1', source: 'radius', kind: 'radius-session' })] }),
    ],
    ...overrides,
  };
}

export function profile(overrides: Partial<UserProfile> = {}): UserProfile {
  return {
    id: ALICE.id,
    display_name: ALICE.label,
    accounts: [link({ relation: 'person-account', source: ALICE, target: ACCOUNT, confidence: 0.98, evidence: [evidence({ id: 'directory:d-1', source: 'directory', kind: 'directory-account', confidence: 0.98 })] })],
    assigned_devices: [inferredLink()],
    sessions: [session()],
    ...overrides,
  };
}

export function trafficOk(overrides: Partial<UserTraffic> = {}): UserTraffic {
  return {
    state: 'ok',
    basis: 'inferred',
    window: { from: '2026-10-11T11:00:00Z', to: AS_OF },
    top_n: 100,
    items: [{ address: '10.0.0.10', bytes: 1_048_576, covers_window: true }],
    ...overrides,
  };
}

export function trafficAbsent(state: 'not-connected' | 'unknown'): UserTraffic {
  return { state, basis: 'unknown', window: null, top_n: 0, items: [] };
}

export function securityOk(overrides: Partial<UserSecurity> = {}): UserSecurity {
  return {
    state: 'ok',
    window: { ...WINDOW },
    truncated: false,
    items: [
      {
        event_id: 'evt-1',
        observed_at: '2026-10-11T11:00:00Z',
        severity: 'high',
        signature: 'ET SCAN Suspicious inbound to MSSQL port 1433',
        address: '10.0.0.10',
        link: identityLink({ basis: 'inferred', confidence: 0.7, reason: 'indirect-evidence' }),
      },
    ],
    ...overrides,
  };
}

export function securityAbsent(state: 'not-connected' | 'unknown'): UserSecurity {
  return { state, window: null, items: [], truncated: false };
}

export function detailFixture(overrides: Partial<UserDetailResponse> = {}): UserDetailResponse {
  return {
    state: 'ok',
    as_of: AS_OF,
    window: { ...WINDOW },
    sources: [source()],
    user: profile(),
    traffic: trafficOk(),
    security: securityOk(),
    ...overrides,
  };
}

export function aggregateFixture(overrides: Partial<UsersAggregateResponse> = {}): UsersAggregateResponse {
  return {
    state: 'ok',
    as_of: AS_OF,
    window: { ...WINDOW },
    sources: [source()],
    people_total: 5,
    with_observed_session: 2,
    with_inferred_session: 1,
    without_session_evidence: 2,
    vpn_sessions: 1,
    ...overrides,
  };
}

export function okState<T>(data: T): FetchState<T> {
  return { kind: 'ok', data, correlationId: 'corr-1' };
}

export function failureState<T>(kind: string, status: number): FetchState<T> {
  return {
    kind,
    code: kind.toUpperCase(),
    message: 'Something went wrong.',
    correlationId: 'corr-1',
    status,
  } as FetchState<T>;
}
