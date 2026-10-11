import {
  ACTIVITIES,
  type Activity,
  type IpamTelemetry,
  type IpamUtilisation,
  type UtilisationBasis,
} from './api-contracts-ipam.ts';
import { isOneOf } from './contract-guards.ts';
import type { Presentation } from './inventory-view.ts';

/**
 * Pure presentation rules for IPAM. Utilisation always names its basis; an address is active, stale,
 * unknown or reserved with the reason in words and an icon (never colour alone); "unknown" is not
 * "stale". Prefix and address text come from NetBox and telemetry and are untrusted plain text. The
 * URL is untrusted too: a filter that does not validate is dropped before it reaches an API path.
 */

export const DEFAULT_PAGE_SIZE = 25;
const MAX_PAGE = 100_000;

type Params = Record<string, string | string[] | undefined>;

export interface IpamQuery {
  prefixesPage: number;
  vlansPage: number;
  addressesPage: number;
  family: '4' | '6' | null;
  activity: Activity | null;
}

function first(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

function pageNumber(value: string | string[] | undefined): number {
  const raw = first(value);
  if (raw === undefined || !/^[0-9]{1,6}$/.test(raw)) return 1;
  const page = Number(raw);
  return page >= 1 && page <= MAX_PAGE ? page : 1;
}

export function parseIpamQuery(params: Params): IpamQuery {
  const family = first(params.family);
  const activity = first(params.activity);
  return {
    prefixesPage: pageNumber(params.prefixes_page),
    vlansPage: pageNumber(params.vlans_page),
    addressesPage: pageNumber(params.addresses_page),
    family: family === '4' || family === '6' ? family : null,
    activity: isOneOf(activity, ACTIVITIES) ? activity : null,
  };
}

function paged(page: number, extra: Record<string, string | null> = {}): string {
  const search = new URLSearchParams({ page: String(page), page_size: String(DEFAULT_PAGE_SIZE) });
  for (const [key, value] of Object.entries(extra)) if (value !== null) search.set(key, value);
  return search.toString();
}

export function prefixesPath(query: IpamQuery): string {
  return `/api/v1/ipam/prefixes?${paged(query.prefixesPage, { family: query.family })}`;
}

export function vlansPath(query: IpamQuery): string {
  return `/api/v1/ipam/vlans?${paged(query.vlansPage)}`;
}

export function addressesPath(query: IpamQuery): string {
  return `/api/v1/ipam/addresses?${paged(query.addressesPage, { activity: query.activity })}`;
}

/** A link to the page with some of the query changed; the rest is kept. */
export function ipamHref(query: IpamQuery, change: Partial<IpamQuery>): string {
  const next = { ...query, ...change };
  const search = new URLSearchParams();
  if (next.prefixesPage > 1) search.set('prefixes_page', String(next.prefixesPage));
  if (next.vlansPage > 1) search.set('vlans_page', String(next.vlansPage));
  if (next.addressesPage > 1) search.set('addresses_page', String(next.addressesPage));
  if (next.family !== null) search.set('family', next.family);
  if (next.activity !== null) search.set('activity', next.activity);
  const rest = search.toString();
  return rest === '' ? '/ipam' : `/ipam?${rest}`;
}

// --- utilisation -------------------------------------------------------------------------------------------

const BASIS: Record<UtilisationBasis, string> = {
  'netbox-addresses':
    'Counted from the address records in NetBox only; no telemetry could add addresses NetBox lacks.',
  'netbox-and-discovered':
    'Counted from the NetBox address records plus addresses monitoring telemetry saw that NetBox does not have.',
  'marked-utilized': 'The operator marked this prefix as fully utilised in NetBox; that is a declaration, not a count.',
  'capacity-not-meaningful':
    'A prefix this large (typically IPv6) has no meaningful number of addresses to fill, so no percentage is claimed.',
  'addresses-unavailable':
    'The NetBox address records could not be read, so the usage cannot be computed.',
};

export function basisText(basis: UtilisationBasis): string {
  return BASIS[basis];
}

const BASIS_SHORT: Record<UtilisationBasis, string> = {
  'netbox-addresses': 'NetBox addresses only',
  'netbox-and-discovered': 'NetBox addresses plus telemetry',
  'marked-utilized': 'Marked full in NetBox',
  'capacity-not-meaningful': 'Capacity not meaningful',
  'addresses-unavailable': 'Addresses unreadable',
};

/** A short label for the basis, shown next to every utilisation figure. */
export function basisShort(basis: UtilisationBasis): string {
  return BASIS_SHORT[basis];
}

export function utilisationText(u: IpamUtilisation): string {
  if (u.basis === 'marked-utilized') return '100% (marked as fully utilised in NetBox)';
  if (u.state === 'unknown' || u.percent === null || u.used === null || u.capacity === null) {
    return 'Not computed';
  }
  return `${u.percent}% (${u.used} of ${u.capacity} usable addresses)`;
}

/** The width of the bar, or null when there is no figure to draw (a bar never implies usage). */
export function utilisationBarPercent(u: IpamUtilisation): number | null {
  if (u.percent === null) return null;
  return Math.min(100, Math.max(0, u.percent));
}

// --- activity ----------------------------------------------------------------------------------------------

const ACTIVITY: Record<Activity, Presentation> = {
  active: {
    label: 'Active',
    icon: 'bi-activity',
    theme: 'success',
    explanation: 'Monitoring telemetry saw this address within the window.',
  },
  stale: {
    label: 'Stale',
    icon: 'bi-hourglass-bottom',
    theme: 'warning',
    explanation:
      'NetBox has this address and telemetry was readable but did not see it within the window. It may simply have no monitoring agent.',
  },
  unknown: {
    label: 'Unknown',
    icon: 'bi-question-circle-fill',
    theme: 'secondary',
    explanation: 'Telemetry could not be read, so nothing is claimed about whether this address is in use.',
  },
  reserved: {
    label: 'Reserved',
    icon: 'bi-lock-fill',
    theme: 'info',
    explanation: 'NetBox reserves this address and nothing saw it; a reservation is not expected to be seen.',
  },
};

export function activityPresentation(value: Activity): Presentation {
  return ACTIVITY[value];
}

function windowText(seconds: number): string {
  const hours = Math.round(seconds / 3600);
  return hours === 1 ? '1 hour' : `${hours} hours`;
}

const SOURCE_NAMES = { librenms: 'LibreNMS', wazuh: 'Wazuh' } as const;

export function telemetryNotice(telemetry: IpamTelemetry): { judged: boolean; text: string } {
  const window = windowText(telemetry.window_seconds);
  if (telemetry.state === 'ok') {
    const names = telemetry.sources.map((s) => SOURCE_NAMES[s]).join(' and ');
    return {
      judged: true,
      text: `Seen means reported by ${names} within the last ${window}. LibreNMS counts a device only while it reports it up; an address nothing monitors is stale here, not necessarily unused.`,
    };
  }
  if (telemetry.state === 'not-connected') {
    return {
      judged: false,
      text: `No telemetry source is connected, so activity is not judged (window ${window}). Addresses are shown as unknown, never as stale.`,
    };
  }
  return {
    judged: false,
    text: `Telemetry is configured but could not be read, so activity is not judged (window ${window}). Addresses are shown as unknown, never as stale.`,
  };
}
