import type { FetchState } from './api-response.ts';
import {
  PERSON_ID,
  type Attribution,
  type Basis,
  type EntityKind,
  type EntityRef,
  type EvidenceKind,
  type IdentityLink,
  type Reason,
  type Relation,
  type SessionKind,
  type SourceStatus,
  type UserListResponse,
} from './api-contracts-identity.ts';
import { formatUtcTimestamp } from './format-time.ts';

/**
 * Pure presentation rules for the identity surfaces. Nothing here fetches or invents data. The
 * wording never states an uncertain correlation as fact: an observed link is "Observed", an inferred
 * one "possibly", an unknown one "Not identified" with the reason, and a basis is always a word and an
 * icon as well as a colour. Every entity label is untrusted source text returned as plain text.
 */

export const NOT_REPORTED = 'Not reported';
export const NOT_IDENTIFIED = 'Not identified';
export const DEFAULT_PAGE_SIZE = 25;
const MAX_PAGE = 1000;
const MAX_PAGE_SIZE = 100;
const MAX_LOOKUP_LENGTH = 128;
const LOOKUP_KINDS = ['ip', 'mac', 'hostname'] as const;

// --- basis, reason, labels ----------------------------------------------------------------------------

export interface BasisPresentation {
  label: 'Observed' | 'Inferred' | 'Unknown';
  icon: string;
  theme: 'success' | 'warning' | 'secondary';
  explanation: string;
}

const BASIS: Record<Basis, BasisPresentation> = {
  observed: {
    label: 'Observed',
    icon: 'bi-eye-fill',
    theme: 'success',
    explanation: 'A source observed this directly, inside its validity window.',
  },
  inferred: {
    label: 'Inferred',
    icon: 'bi-lightbulb-fill',
    theme: 'warning',
    explanation: 'Reasoned from a declaration or weak evidence; treat it as a lead, not a fact.',
  },
  unknown: {
    label: 'Unknown',
    icon: 'bi-question-circle-fill',
    theme: 'secondary',
    explanation: 'The evidence does not establish this.',
  },
};

export function basisPresentation(basis: Basis): BasisPresentation {
  return BASIS[basis];
}

const REASONS: Record<Reason, string> = {
  'declared-assignment':
    'Based on an asset-register assignment (who a device is assigned to), not on observing who is using it.',
  'indirect-evidence':
    'Based on weak evidence such as a sign-in or a DNS record, which does not prove who is using the address.',
  'low-confidence': 'The source that recorded this reported low confidence in it.',
  'name-match': 'Matched by name only; a name is not proof of identity.',
  'conflicting-evidence':
    'Sources disagree: another claim exists for the same address, device or account.',
  'no-evidence': 'No evidence was found for this in the time window that was read.',
  expired:
    'Evidence exists, but it no longer holds at this time: the session or lease ended or was not renewed.',
  'multiple-candidates': 'More than one person matches equally well, and none is picked.',
  'shared-address':
    'Many hosts can appear behind this address (public, NAT or shared), so an address here is not an identity.',
  'vpn-no-session': 'This address is in a VPN pool and no VPN session records who held it.',
  'guest-network':
    'This endpoint is on a guest or BYOD network and is not attributed to a person.',
  'ip-only': 'Only the network address is known; an IP address alone is not identity.',
  'source-unavailable':
    'An evidence source could not be read, so the absence of evidence here proves nothing.',
  restricted: 'Your role may see the endpoint but not who is behind it.',
};

export function reasonText(reason: Reason | null): string {
  return reason === null ? '' : REASONS[reason];
}

const ENTITY_KINDS: Record<EntityKind, string> = {
  person: 'Person',
  account: 'Account',
  device: 'Device',
  ip: 'IP address',
  mac: 'MAC address',
  switch: 'Switch',
  ap: 'Access point',
  port: 'Port',
  vlan: 'VLAN',
  hostname: 'Hostname',
};

export function entityKindLabel(kind: EntityKind): string {
  return ENTITY_KINDS[kind];
}

/** The entity as plain text: its label when it has one, else a typed id. Never markup. */
/**
 * Where an entity can be read in full, or null when it has no page of its own (an account, an
 * address). The id was validated by the contract parser, and is encoded again here.
 */
export function entityHref(entity: EntityRef): string | null {
  const id = encodeURIComponent(entity.id);
  if (entity.type === 'person') return `/users/${id}`;
  if (entity.type === 'device' || entity.type === 'switch' || entity.type === 'ap') {
    return `/devices/${id}`;
  }
  return null;
}

export function entityText(entity: EntityRef | null): string {
  if (entity === null) return NOT_IDENTIFIED;
  if (entity.label !== null) return entity.label;
  if (entity.type === 'person') return 'Unnamed person';
  if (entity.type === 'account') return 'Unnamed account';
  return entity.id;
}

const RELATIONS: Record<Relation, string> = {
  'person-account': 'Person to account',
  'account-device': 'Account to device',
  'person-device': 'Assigned device',
  'account-mac': 'Account to MAC address',
  'account-ip': 'Account to IP address',
  'device-ip': 'Device to IP address',
  'device-mac': 'Device to MAC address',
  'ip-mac': 'IP address to MAC address',
  'mac-switch': 'MAC address to switch',
  'mac-ap': 'MAC address to access point',
  'mac-port': 'MAC address to port',
  'mac-vlan': 'MAC address to VLAN',
  'port-vlan': 'Port to VLAN',
  'hostname-ip': 'Hostname to IP address',
  'hostname-device': 'Hostname to device',
  identity: 'Who is behind it',
};

export function relationLabel(relation: Relation): string {
  return RELATIONS[relation];
}

const EVIDENCE_KINDS: Record<EvidenceKind, string> = {
  'dhcp-lease': 'DHCP lease',
  'radius-session': 'RADIUS / 802.1X session',
  'vpn-session': 'VPN session',
  'wifi-association': 'Wi-Fi association',
  'switch-mac-table': 'Switch MAC table',
  'endpoint-agent': 'Endpoint agent inventory',
  'directory-account': 'Directory account',
  'idp-signin': 'Identity-provider sign-in',
  'dns-record': 'DNS record',
  'asset-assignment': 'Asset register assignment',
};

export function evidenceKindLabel(kind: EvidenceKind): string {
  return EVIDENCE_KINDS[kind];
}

const SESSION_KINDS: Record<SessionKind, string> = {
  wired: 'Wired (802.1X)',
  wifi: 'Wi-Fi',
  vpn: 'VPN',
  network: 'Network',
};

export function sessionKindLabel(kind: SessionKind): string {
  return SESSION_KINDS[kind];
}

export function confidenceText(value: number | null): string {
  if (value === null || !Number.isFinite(value)) return NOT_REPORTED;
  return `${Math.round(value * 100)}%`;
}

export function validityText(link: Pick<IdentityLink, 'valid_from' | 'valid_to'>): string {
  if (link.valid_from === null || link.valid_to === null) return 'No validity window';
  return `Valid from ${formatUtcTimestamp(link.valid_from)} until ${formatUtcTimestamp(link.valid_to)}`;
}

// --- the attribution headline -----------------------------------------------------------------------------

export interface Headline {
  title: string;
  detail: string;
}

export function attributionHeadline(attribution: Attribution): Headline {
  const { basis, reason, ambiguous, links, candidates } = attribution;
  if (basis === 'unknown') {
    if (ambiguous) {
      return {
        title: `Ambiguous: ${candidates.length} possible people`,
        detail: `${reasonText(reason)} Every candidate is listed with its own basis; none is selected.`,
      };
    }
    return {
      title: reason === 'restricted' ? 'Person withheld' : NOT_IDENTIFIED,
      detail: reasonText(reason),
    };
  }
  const first = entityText(links[0]?.target ?? null);
  const others = links.length - 1;
  const more = others > 0 ? ` ${others} other ${others === 1 ? 'person is' : 'people are'} listed with a weaker basis.` : '';
  if (basis === 'observed') {
    return {
      title: `Observed: ${first}`,
      detail: `Direct sources agree at this time.${more}`,
    };
  }
  return { title: `Inferred: possibly ${first}`, detail: `${reasonText(reason)}${more}` };
}

// --- sources -----------------------------------------------------------------------------------------------------

export interface SourceProblem {
  source: string;
  kind: 'not-connected' | 'unknown' | 'stale';
}

export function sourceProblems(sources: readonly SourceStatus[]): SourceProblem[] {
  const problems: SourceProblem[] = [];
  for (const source of sources) {
    if (source.state === 'not-connected') problems.push({ source: source.source, kind: 'not-connected' });
    else if (source.state === 'unknown') problems.push({ source: source.source, kind: 'unknown' });
    else if (source.freshness.state === 'stale') problems.push({ source: source.source, kind: 'stale' });
  }
  return problems;
}

// --- surfaces --------------------------------------------------------------------------------------------------------

export type Surface = 'permission' | 'failure' | 'not-connected' | 'unknown' | 'empty' | 'data';

function failureSurface(state: Exclude<FetchState<unknown>, { kind: 'ok' }>): Surface {
  return state.kind === 'forbidden' ? 'permission' : 'failure';
}

export function listSurface(state: FetchState<UserListResponse>): Surface {
  if (state.kind !== 'ok') return failureSurface(state);
  if (state.data.state === 'not-connected') return 'not-connected';
  if (state.data.state === 'unknown') return 'unknown';
  return state.data.items.length === 0 ? 'empty' : 'data';
}

export function stateSurface(
  state: FetchState<{ state: 'not-connected' | 'unknown' | 'ok' }>,
): Surface {
  if (state.kind !== 'ok') return failureSurface(state);
  if (state.data.state === 'not-connected') return 'not-connected';
  if (state.data.state === 'unknown') return 'unknown';
  return 'data';
}

// --- paths and paging --------------------------------------------------------------------------------------------------

function clamp(value: number, minimum: number, maximum: number): number {
  return Math.min(maximum, Math.max(minimum, Math.trunc(value)));
}

export function listPath(page: number, pageSize: number): string {
  return `/api/v1/users?page=${clamp(page, 1, MAX_PAGE)}&page_size=${clamp(pageSize, 1, MAX_PAGE_SIZE)}`;
}

export function detailPath(id: string): string | null {
  return PERSON_ID.test(id) ? `/api/v1/users/${id}` : null;
}

export function parsePage(raw: string | string[] | undefined): number {
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (typeof value !== 'string' || !/^[1-9][0-9]{0,3}$/.test(value)) return 1;
  const page = Number(value);
  return page <= MAX_PAGE ? page : 1;
}

export interface PageLinks {
  previous: string | null;
  next: string | null;
}

export function pageHrefs(page: number, pageSize: number, total: number): PageLinks {
  return {
    previous: page > 1 ? `/users?page=${page - 1}` : null,
    next: page * pageSize < total ? `/users?page=${page + 1}` : null,
  };
}

// --- the lookup form -----------------------------------------------------------------------------------------------------

export type Lookup =
  | { ok: true; kind: (typeof LOOKUP_KINDS)[number]; value: string }
  | { ok: false; reason: 'empty' | 'invalid' };

export function parseLookup(raw: {
  kind?: string | string[];
  value?: string | string[];
}): Lookup {
  if (raw.kind === undefined && raw.value === undefined) return { ok: false, reason: 'empty' };
  if (Array.isArray(raw.kind) || Array.isArray(raw.value)) return { ok: false, reason: 'invalid' };
  const value = (raw.value ?? '').trim();
  if (value.length === 0) return { ok: false, reason: 'empty' };
  if (
    value.length > MAX_LOOKUP_LENGTH ||
    !(LOOKUP_KINDS as readonly string[]).includes(raw.kind ?? '')
  ) {
    return { ok: false, reason: 'invalid' };
  }
  return { ok: true, kind: raw.kind as (typeof LOOKUP_KINDS)[number], value };
}

export function lookupPath(lookup: Extract<Lookup, { ok: true }>): string {
  return `/api/v1/identity/resolve?${lookup.kind}=${encodeURIComponent(lookup.value)}`;
}
