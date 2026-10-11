import {
  FINDING_STATES,
  SEVERITIES,
  type FindingState,
  type Severity,
  type SlotName,
  type UnknownDeviceCheck,
  type UnknownDeviceLinkSlot,
  type UnknownDeviceList,
} from './api-contracts-unknown-devices.ts';
import type { FetchState } from './api-response.ts';
import { isOneOf } from './contract-guards.ts';
import type { PageHrefs } from './incident-view.ts';
import type { Presentation } from './inventory-view.ts';

/**
 * Pure presentation rules for unknown-device findings. A finding is something telemetry saw that
 * NetBox does not know; its chain shows only the links actually observed and says, in words, why each
 * other hop is not known. Severity is the operator's policy or "Unknown severity", never a guess. All
 * names and labels are untrusted source text returned as plain text; the URL is untrusted too, and a
 * filter that does not validate is dropped before it can reach an API path.
 */

export const DEFAULT_PAGE_SIZE = 25;
const MAX_PAGE = 100_000;

type Params = Record<string, string | string[] | undefined>;
export type StateFilter = FindingState | 'open' | null;

export interface FindingsQuery {
  page: number;
  /** `open` (the default) is new, acknowledged and investigating; `null` is every state ("all"). */
  state: StateFilter;
  severity: Severity | null;
  assigned: boolean | null;
}

function first(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

export function parseFindingsQuery(params: Params): FindingsQuery {
  const rawPage = first(params.page);
  const page = rawPage !== undefined && /^[0-9]{1,6}$/.test(rawPage) ? Number(rawPage) : 1;
  const state = first(params.state);
  const severity = first(params.severity);
  const assigned = first(params.assigned);
  return {
    page: page >= 1 && page <= MAX_PAGE ? page : 1,
    state: state === 'all' ? null : isOneOf(state, FINDING_STATES) ? state : 'open',
    severity: isOneOf(severity, SEVERITIES) ? severity : null,
    assigned: assigned === 'true' ? true : assigned === 'false' ? false : null,
  };
}

export function findingsPath(query: FindingsQuery): string {
  const search = new URLSearchParams({ page: String(query.page), page_size: String(DEFAULT_PAGE_SIZE) });
  if (query.state !== null) search.set('state', query.state);
  if (query.severity !== null) search.set('severity', query.severity);
  if (query.assigned !== null) search.set('assigned', String(query.assigned));
  return `/api/v1/unknown-devices?${search.toString()}`;
}

function pageLink(query: FindingsQuery, page: number): string {
  const search = new URLSearchParams();
  if (query.state === null) search.set('state', 'all');
  else if (query.state !== 'open') search.set('state', query.state);
  if (query.severity !== null) search.set('severity', query.severity);
  if (query.assigned !== null) search.set('assigned', String(query.assigned));
  if (page > 1) search.set('page', String(page));
  const rest = search.toString();
  return rest === '' ? '/unknown-devices' : `/unknown-devices?${rest}`;
}

export function pageHrefs(query: FindingsQuery, total: number): PageHrefs {
  const last = Math.max(1, Math.ceil(total / DEFAULT_PAGE_SIZE));
  return {
    previous: query.page > 1 ? pageLink(query, query.page - 1) : null,
    next: query.page < last ? pageLink(query, query.page + 1) : null,
  };
}

export function filtersInUse(query: FindingsQuery): boolean {
  return query.state !== 'open' || query.severity !== null || query.assigned !== null;
}

export function findingHref(id: string): string {
  return `/unknown-devices/${encodeURIComponent(id)}`;
}

export function timelinePath(id: string): string {
  return `/api/v1/unknown-devices/${encodeURIComponent(id)}/timeline`;
}

// --- wording ------------------------------------------------------------------------------------------------

const STATE: Record<FindingState, Presentation> = {
  new: { label: 'New', icon: 'bi-bell-fill', theme: 'danger', explanation: 'Nobody has looked at this yet.' },
  acknowledged: {
    label: 'Acknowledged',
    icon: 'bi-eye-fill',
    theme: 'warning',
    explanation: 'Someone has seen it and has not started work.',
  },
  investigating: {
    label: 'Investigating',
    icon: 'bi-search',
    theme: 'info',
    explanation: 'Someone is working out what this device is.',
  },
  resolved: {
    label: 'Resolved',
    icon: 'bi-check-circle-fill',
    theme: 'success',
    explanation: 'It was dealt with. If the device is seen again without a NetBox record, a new finding is made.',
  },
  'false-positive': {
    label: 'False positive',
    icon: 'bi-slash-circle-fill',
    theme: 'secondary',
    explanation: 'It was dismissed. Later sightings of the same endpoint are suppressed.',
  },
};

export function statePresentation(state: FindingState): Presentation {
  return STATE[state];
}

const SEVERITY: Record<Severity, Presentation> = {
  low: { label: 'Low', icon: 'bi-arrow-down-circle-fill', theme: 'info', explanation: "Low by the operator's policy." },
  medium: { label: 'Medium', icon: 'bi-dash-circle-fill', theme: 'warning', explanation: "Medium by the operator's policy." },
  high: { label: 'High', icon: 'bi-arrow-up-circle-fill', theme: 'danger', explanation: "High by the operator's policy." },
  critical: { label: 'Critical', icon: 'bi-x-octagon-fill', theme: 'danger', explanation: "Critical by the operator's policy." },
  unknown: {
    label: 'Unknown severity',
    icon: 'bi-question-circle-fill',
    theme: 'secondary',
    explanation: 'No severity policy decided this, so none is claimed. It is not the same as low.',
  },
};

export function severityPresentation(severity: Severity): Presentation {
  return SEVERITY[severity];
}

const SLOT_LABELS: Record<SlotName, string> = {
  ip: 'IP address',
  mac: 'MAC address',
  attachment: 'Switch or access point',
  port: 'Port',
  vlan: 'VLAN',
};

export function slotLabel(slot: SlotName): string {
  return SLOT_LABELS[slot];
}

const REASON_TEXT: Record<NonNullable<UnknownDeviceLinkSlot['reason']>, string> = {
  'no-evidence': 'No evidence was found for this in the time window that was read.',
  'source-unavailable':
    'No connected source can observe this (for example a switch MAC table, DHCP or Wi-Fi controller adapter is not connected), so it is not known.',
  'conflicting-evidence': 'Sources disagree, so none is picked.',
  expired: 'Evidence existed but no longer holds: the record ended or was not renewed.',
  'indirect-evidence': 'Based on weak evidence that does not prove it.',
  'low-confidence': 'The source reported low confidence in it.',
  'declared-assignment': 'Based on a declaration, not an observation.',
  'name-match': 'Matched by name only; a name is not proof.',
  'guest-network': 'This endpoint is on a guest network and is not analysed further.',
};

/** What to show for a hop: the observed label or value as plain text, else the reason it is unknown. */
export function slotStatement(slot: UnknownDeviceLinkSlot): string {
  if (slot.basis === 'unknown') return slot.reason === null ? 'Not known.' : REASON_TEXT[slot.reason];
  return slot.label ?? slot.value ?? 'Not known.';
}

const CHECK_TEXT: Record<UnknownDeviceCheck['field'], { noMatch: string; name: string }> = {
  ip: { name: 'IP address', noMatch: 'NetBox assigns this address to no device.' },
  mac: { name: 'MAC address', noMatch: 'NetBox has no interface with this MAC address.' },
  hostname: { name: 'Hostname', noMatch: 'NetBox has no device of this name.' },
};

export function checkPresentation(check: UnknownDeviceCheck): { label: string; name: string; text: string } {
  const copy = CHECK_TEXT[check.field];
  if (check.result === 'no-match') return { label: 'No match', name: copy.name, text: copy.noMatch };
  if (check.result === 'match') return { label: 'Match', name: copy.name, text: check.detail ?? 'NetBox has it.' };
  return {
    label: 'Not checked',
    name: copy.name,
    text: `Not compared with NetBox${check.detail ? `: ${check.detail}` : '.'}`,
  };
}

// --- surfaces ---------------------------------------------------------------------------------------------

export type ListSurface =
  | 'permission'
  | 'unauthenticated'
  | 'error'
  | 'not-connected'
  | 'unknown'
  | 'empty'
  | 'filtered-empty'
  | 'data';

export function listSurface(state: FetchState<UnknownDeviceList>, query: FindingsQuery): ListSurface {
  if (state.kind === 'forbidden') return 'permission';
  if (state.kind === 'unauthenticated') return 'unauthenticated';
  if (state.kind !== 'ok') return 'error';
  if (state.data.state === 'not-connected') return 'not-connected';
  if (state.data.state === 'unknown') return 'unknown';
  if (state.data.total === 0) return filtersInUse(query) ? 'filtered-empty' : 'empty';
  return 'data';
}

