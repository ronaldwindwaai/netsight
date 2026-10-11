import type { FetchState } from './api-response.ts';
import type {
  BlockState,
  InternetResponse,
  LinkStatus,
  WanLink,
} from './api-contracts-internet.ts';
import type { Freshness } from './api-contracts.ts';
import { formatSpeed } from './format-speed.ts';
import { formatUtcTimestamp } from './format-time.ts';

/**
 * Pure presentation rules for the Internet/WAN surfaces. Nothing here fetches or invents data: a
 * value the API did not report is "Not reported", never a zero, and a status is always carried by
 * a word and an icon as well as a colour.
 */

export const NOT_REPORTED = 'Not reported';
/** A value withheld by the API from a role without internet:read_detail (not the same as missing). */
export const RESTRICTED = 'Restricted';
/** The server accepts the current month and this many before it (apps/api wan/sla.py). */
export const MONTHS_BACK = 24;
const MONTH_PATTERN = /^[0-9]{4}-(0[1-9]|1[0-2])$/;

// --- formatting ------------------------------------------------------------------------------------------

function isUsable(value: number | null | undefined): value is number {
  return typeof value === 'number' && Number.isFinite(value);
}

export function formatPercent(value: number | null): string {
  if (!isUsable(value)) return NOT_REPORTED;
  return `${Number(value.toFixed(3))}%`;
}

export function formatMillis(value: number | null): string {
  if (!isUsable(value) || value < 0) return NOT_REPORTED;
  const rounded = value >= 100 ? Math.round(value) : Math.round(value * 100) / 100;
  return `${rounded} ms`;
}

export function formatDuration(seconds: number | null): string {
  if (!isUsable(seconds) || seconds < 0) return NOT_REPORTED;
  let rest = Math.floor(seconds);
  if (rest === 0) return '0 s';
  const parts: string[] = [];
  for (const [unit, size] of [
    ['d', 86400],
    ['h', 3600],
    ['min', 60],
    ['s', 1],
  ] as const) {
    const amount = Math.floor(rest / size);
    rest -= amount * size;
    if (amount > 0) parts.push(`${amount} ${unit}`);
  }
  return parts.join(' ');
}

export function freshnessLabel(freshness: Freshness): string {
  const source = freshness.source === null ? '' : ` (${freshness.source})`;
  if (freshness.state === 'unknown' || freshness.observed_at === null) {
    return freshness.state === 'stale'
      ? `Stale${source}`
      : `Freshness unknown${source}`;
  }
  const when = formatUtcTimestamp(freshness.observed_at);
  return freshness.state === 'fresh'
    ? `Fresh, observed ${when}${source}`
    : `Stale, last observed ${when}${source}`;
}

export interface StatusPresentation {
  label: string;
  icon: string;
  theme: 'success' | 'warning' | 'danger' | 'secondary';
}

const STATUS: Record<LinkStatus, StatusPresentation> = {
  up: { label: 'Up', icon: 'bi-check-circle-fill', theme: 'success' },
  degraded: { label: 'Degraded', icon: 'bi-exclamation-triangle-fill', theme: 'warning' },
  down: { label: 'Down', icon: 'bi-x-octagon-fill', theme: 'danger' },
  unknown: { label: 'Unknown', icon: 'bi-question-circle-fill', theme: 'secondary' },
};

export function statusPresentation(status: LinkStatus): StatusPresentation {
  return STATUS[status];
}

// --- months -----------------------------------------------------------------------------------------------

function monthKey(year: number, monthIndex: number): string {
  return `${year}-${String(monthIndex + 1).padStart(2, '0')}`;
}

/** The current UTC month and the 24 before it, newest first: the months the API will answer. */
export function monthOptions(now: Date): string[] {
  const months: string[] = [];
  for (let back = 0; back <= MONTHS_BACK; back += 1) {
    const moment = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - back, 1));
    months.push(monthKey(moment.getUTCFullYear(), moment.getUTCMonth()));
  }
  return months;
}

/** A month from the URL, used only when the server would accept it; otherwise the current month. */
export function requestedMonth(
  raw: string | string[] | undefined,
  now: Date,
): { month: string; adjusted: boolean } {
  const current = monthOptions(now)[0];
  if (raw === undefined) return { month: current, adjusted: false };
  if (Array.isArray(raw) && raw.length !== 1) return { month: current, adjusted: true };
  const value = Array.isArray(raw) ? raw[0] : raw;
  return monthOptions(now).includes(value)
    ? { month: value, adjusted: false }
    : { month: current, adjusted: true };
}

function checkedMonth(month: string): string {
  if (!MONTH_PATTERN.test(month)) throw new Error('month must be YYYY-MM');
  return month;
}

export function slaPath(month: string): string {
  return `/api/v1/internet/sla?month=${checkedMonth(month)}`;
}

export function exportHref(month: string, format: 'csv' | 'json'): string {
  return `/internet/export?month=${checkedMonth(month)}&format=${format}`;
}

// --- which surface the page shows -----------------------------------------------------------------------

export type InternetSurface =
  | 'permission'
  | 'unauthenticated'
  | 'error'
  | 'not-connected'
  | 'unknown'
  | 'empty'
  | 'ok';

export function internetSurface(state: FetchState<InternetResponse>): InternetSurface {
  if (state.kind === 'forbidden') return 'permission';
  if (state.kind === 'unauthenticated') return 'unauthenticated';
  if (state.kind !== 'ok') return 'error';
  if (state.data.state === 'not-connected') return 'not-connected';
  if (state.data.state === 'unknown') return 'unknown';
  return state.data.links.length === 0 ? 'empty' : 'ok';
}

export type LinkBlock = 'interface' | 'quality' | 'availability';

/** The source blocks of a link that are not `ok`: the link is partial, and this says which. */
export function nonOkBlocks(link: WanLink): LinkBlock[] {
  const blocks: Array<[LinkBlock, BlockState]> = [
    ['interface', link.interface.state],
    ['quality', link.quality.state],
    ['availability', link.availability.state],
  ];
  return blocks.filter(([, state]) => state !== 'ok').map(([name]) => name);
}

// --- the overview Internet card ----------------------------------------------------------------------------

export interface OverviewCard {
  title: string;
  detail: string;
  theme: 'success' | 'warning' | 'danger' | 'secondary';
  /** 0-100 utilisation when it is a current source value; undefined means no gauge is shown. */
  progress: number | undefined;
}

const NOT_CONNECTED_CARD: OverviewCard = {
  title: 'Not connected',
  detail: 'WAN telemetry unavailable',
  theme: 'secondary',
  progress: undefined,
};

function unknownCard(detail: string): OverviewCard {
  return { title: 'Unknown', detail, theme: 'secondary', progress: undefined };
}

function displayLink(data: InternetResponse): WanLink {
  const usable = (link: WanLink) => link.status === 'up' || link.status === 'degraded';
  if (data.failover.state === 'failed-over') {
    const backup = data.links.find((link) => link.role === 'backup' && usable(link));
    if (backup !== undefined) return backup;
  }
  return data.links.find((link) => link.role === 'primary') ?? data.links[0];
}

function throughputDetail(
  link: WanLink,
  redacted: boolean,
): { text: string; progress: number | undefined } {
  const { interface: wan } = link;
  if (wan.state !== 'ok') {
    return {
      text: wan.state === 'not-connected' ? 'Interface not connected' : 'Interface state unknown',
      progress: undefined,
    };
  }
  if (redacted) return { text: 'Throughput restricted for your role', progress: undefined };
  const parts: string[] = [];
  if (wan.rx_bps !== null) parts.push(`${formatSpeed(wan.rx_bps)} down`);
  if (wan.tx_bps !== null) parts.push(`${formatSpeed(wan.tx_bps)} up`);
  if (parts.length === 0) parts.push('Throughput not reported');
  if (wan.utilisation_pct !== null) parts.push(`${formatPercent(wan.utilisation_pct)} utilised`);
  const current = wan.freshness.state === 'fresh';
  if (wan.freshness.state === 'stale') parts.push('(stale)');
  if (wan.freshness.state === 'unknown') parts.push('(freshness unknown)');
  const progress =
    current && wan.utilisation_pct !== null
      ? Math.min(100, Math.max(0, wan.utilisation_pct))
      : undefined;
  return { text: parts.join(' · '), progress };
}

export function overviewInternetCard(state: FetchState<InternetResponse>): OverviewCard {
  if (state.kind === 'forbidden') {
    return {
      title: 'Restricted',
      detail: 'Your role cannot read WAN telemetry',
      theme: 'secondary',
      progress: undefined,
    };
  }
  if (state.kind !== 'ok') return unknownCard('WAN telemetry could not be read');
  const { data } = state;
  if (data.state === 'not-connected') return NOT_CONNECTED_CARD;
  if (data.state === 'unknown') return unknownCard('WAN configuration or sources could not be read');
  if (data.links.length === 0) return unknownCard('The API reported no WAN links');

  const link = displayLink(data);
  const { text, progress } = throughputDetail(link, data.detail_redacted);
  if (data.failover.state === 'failed-over') {
    return { title: 'Failed over', detail: `Primary link down · ${text}`, theme: 'warning', progress };
  }
  if (data.failover.state === 'all-down') {
    return { title: 'Down', detail: 'Every declared link is down', theme: 'danger', progress: undefined };
  }
  const presentation = statusPresentation(link.status);
  return { title: presentation.label, detail: text, theme: presentation.theme, progress };
}
