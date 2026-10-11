import type { DataSourceStatus } from './api-contracts-sources.ts';
import {
  ASSET_CLASSES,
  DEVICE_STATUSES,
  ITEM_SOURCES,
  type AssetClass,
  type ClassBasis,
  type DeviceStatus,
  type InventoryList,
  type ItemSource,
  type Provenance,
  type ReconcileStatus,
} from './api-contracts-inventory.ts';
import type { FetchState } from './api-response.ts';
import { isOneOf } from './contract-guards.ts';
import type { PageHrefs } from './incident-view.ts';

/**
 * Pure presentation rules for the inventory surfaces. Nothing here fetches or invents data. A value
 * nobody reported is "Not reported", never a guess; where a value came from is a word and an icon as
 * well as a colour; every name, role and site is untrusted source text, returned as plain text. The
 * URL is untrusted too: a filter that does not validate is dropped before it can reach an API path.
 */

export const NOT_REPORTED = 'Not reported';
export const DEFAULT_PAGE_SIZE = 25;
const MAX_PAGE = 100_000;
const MAX_SITE = 255;
const MAX_SEARCH = 64;
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;

type Params = Record<string, string | string[] | undefined>;

export interface InventoryQuery {
  page: number;
  assetClass: AssetClass | null;
  site: string | null;
  status: DeviceStatus | null;
  source: ItemSource | null;
  known: boolean | null;
  q: string | null;
}

function first(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

function text(value: string | string[] | undefined, maximum: number): string | null {
  const raw = first(value);
  if (raw === undefined || raw.trim() === '' || raw.length > maximum || CONTROL.test(raw)) return null;
  return raw;
}

function pageNumber(value: string | string[] | undefined): number {
  const raw = first(value);
  if (raw === undefined || !/^[0-9]{1,6}$/.test(raw)) return 1;
  const page = Number(raw);
  return page >= 1 && page <= MAX_PAGE ? page : 1;
}

/** The query as the page understands it: every field validated, an unusable one dropped. */
export function parseInventoryQuery(params: Params): InventoryQuery {
  const known = first(params.known);
  const assetClass = first(params.asset_class);
  const status = first(params.status);
  const source = first(params.source);
  return {
    page: pageNumber(params.page),
    assetClass: isOneOf(assetClass, ASSET_CLASSES) ? assetClass : null,
    site: text(params.site, MAX_SITE),
    status: isOneOf(status, DEVICE_STATUSES) ? status : null,
    source: isOneOf(source, ITEM_SOURCES) ? source : null,
    known: known === 'true' ? true : known === 'false' ? false : null,
    q: text(params.q, MAX_SEARCH),
  };
}

function filterParams(query: InventoryQuery): URLSearchParams {
  const search = new URLSearchParams();
  if (query.assetClass !== null) search.set('asset_class', query.assetClass);
  if (query.site !== null) search.set('site', query.site);
  if (query.status !== null) search.set('status', query.status);
  if (query.source !== null) search.set('source', query.source);
  if (query.known !== null) search.set('known', String(query.known));
  if (query.q !== null) search.set('q', query.q);
  return search;
}

export function filtersInUse(query: InventoryQuery): boolean {
  return [...filterParams(query).keys()].length > 0;
}

/** The API path for a validated query; only the filters in use are sent. */
export function inventoryPath(query: InventoryQuery): string {
  const search = new URLSearchParams({ page: String(query.page), page_size: String(DEFAULT_PAGE_SIZE) });
  for (const [key, value] of filterParams(query)) search.set(key, value);
  return `/api/v1/inventory?${search.toString()}`;
}

function pageLink(query: InventoryQuery, page: number): string {
  const search = filterParams(query);
  if (page > 1) search.set('page', String(page));
  const rest = search.toString();
  return rest === '' ? '/inventory' : `/inventory?${rest}`;
}

export function pageHrefs(query: InventoryQuery, total: number): PageHrefs {
  const last = Math.max(1, Math.ceil(total / DEFAULT_PAGE_SIZE));
  return {
    previous: query.page > 1 ? pageLink(query, query.page - 1) : null,
    next: query.page < last ? pageLink(query, query.page + 1) : null,
  };
}

const DEVICE_ID = /^device-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** True for a canonical asset id: only such an id may be placed in an API path. */
export function isInventoryId(value: string): boolean {
  return DEVICE_ID.test(value);
}

export function itemHref(id: string): string {
  return `/inventory/${encodeURIComponent(id)}`;
}

// --- wording ---------------------------------------------------------------------------------------------

const CLASS_LABELS: Record<AssetClass, string> = {
  'network-device': 'Network device',
  server: 'Server',
  'access-point': 'Access point',
  endpoint: 'Endpoint',
  cctv: 'CCTV',
  printer: 'Printer',
  iot: 'IoT',
  'unknown-asset': 'Unknown asset',
  unclassified: 'Unclassified',
};

export function classLabel(value: AssetClass): string {
  return CLASS_LABELS[value];
}

const CLASS_BASIS: Record<ClassBasis, string> = {
  'role-map': "From the NetBox role, through the operator's class map.",
  'type-map': "From the NetBox device type, through the operator's class map.",
  unmapped:
    "The operator's class map has no entry for this NetBox role or device type, so it is not guessed.",
  'not-in-netbox':
    'NetBox has no record of this asset, so there is no role or type to classify it by.',
};

export function classBasisText(basis: ClassBasis): string {
  return CLASS_BASIS[basis];
}

export interface Presentation {
  label: string;
  icon: string;
  theme: 'success' | 'warning' | 'danger' | 'secondary' | 'info' | 'primary';
  explanation: string;
}

const PROVENANCE: Record<Provenance, Presentation> = {
  netbox: {
    label: 'NetBox',
    icon: 'bi-journal-check',
    theme: 'primary',
    explanation: 'Only NetBox (intended state) reports this value.',
  },
  discovered: {
    label: 'Discovered',
    icon: 'bi-binoculars-fill',
    theme: 'info',
    explanation: 'Only monitoring telemetry reports this value; NetBox does not have it.',
  },
  both: {
    label: 'Both agree',
    icon: 'bi-check2-all',
    theme: 'success',
    explanation: 'NetBox and monitoring telemetry report the same value.',
  },
  conflict: {
    label: 'Conflict',
    icon: 'bi-exclamation-triangle-fill',
    theme: 'warning',
    explanation:
      'NetBox and telemetry report different values. NetBox, the authority for intended state, is shown; both readings are listed.',
  },
  unknown: {
    label: 'Not reported',
    icon: 'bi-question-circle-fill',
    theme: 'secondary',
    explanation: 'No source reported this value.',
  },
};

export function provenancePresentation(value: Provenance): Presentation {
  return PROVENANCE[value];
}

const RECONCILE: Record<ReconcileStatus, Presentation> = {
  reconciled: {
    label: 'Reconciled',
    icon: 'bi-check-circle-fill',
    theme: 'success',
    explanation: 'NetBox and discovery agree that this asset exists and is in the intended state.',
  },
  'missing-discovered': {
    label: 'Not seen',
    icon: 'bi-eye-slash-fill',
    theme: 'warning',
    explanation: 'NetBox intends this asset, but discovery did not see it.',
  },
  'unknown-discovered': {
    label: 'Unknown to NetBox',
    icon: 'bi-patch-question-fill',
    theme: 'warning',
    explanation: 'Discovery sees this asset, but NetBox has no matching record.',
  },
  'status-mismatch': {
    label: 'Status mismatch',
    icon: 'bi-exclamation-triangle-fill',
    theme: 'warning',
    explanation: 'NetBox and discovery disagree about whether the asset is active.',
  },
  ambiguous: {
    label: 'Ambiguous',
    icon: 'bi-diagram-2-fill',
    theme: 'secondary',
    explanation:
      'More than one device shares this hostname, so it is not joined to anything: a name alone is not an identity.',
  },
  'not-checked': {
    label: 'Not checked',
    icon: 'bi-dash-circle-fill',
    theme: 'secondary',
    explanation: 'A source needed for the comparison could not be read, so nothing is claimed either way.',
  },
};

export function reconcilePresentation(value: ReconcileStatus): Presentation {
  return RECONCILE[value];
}

const SOURCE_LABELS = { netbox: 'NetBox', librenms: 'LibreNMS', wazuh: 'Wazuh' } as const;

export function sourceLabel(source: DataSourceStatus['source']): string {
  return SOURCE_LABELS[source];
}

/** The sources that were not read this time (named so a missing one is never invisible). */
export function degradedSources(sources: readonly DataSourceStatus[]): DataSourceStatus[] {
  return sources.filter((source) => source.state !== 'ok');
}

// --- surfaces --------------------------------------------------------------------------------------------

export type ListSurface =
  | 'permission'
  | 'unauthenticated'
  | 'error'
  | 'not-connected'
  | 'unknown'
  | 'empty'
  | 'filtered-empty'
  | 'data';

export function listSurface(state: FetchState<InventoryList>, query: InventoryQuery): ListSurface {
  if (state.kind === 'forbidden') return 'permission';
  if (state.kind === 'unauthenticated') return 'unauthenticated';
  if (state.kind !== 'ok') return 'error';
  if (state.data.state === 'not-connected') return 'not-connected';
  if (state.data.state === 'unknown') return 'unknown';
  if (state.data.total === 0) return filtersInUse(query) ? 'filtered-empty' : 'empty';
  return 'data';
}
