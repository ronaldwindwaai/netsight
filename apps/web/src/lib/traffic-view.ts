import type {
  Anomaly,
  AnomalyContext,
  AppTrend,
  Approval,
  AttributionStatus,
  CohortStatus,
  DaylightSaving,
  DestinationScope,
  Evaluation,
  FilterName,
  FirstSeenStatus,
  FlowAttribution,
  BaselineMethod,
  Reputation,
  RiskLevel,
  WorkingHours,
} from './api-contracts-traffic-explorer.ts';
import { FILTER_NAMES } from './api-contracts-traffic-explorer.ts';
import type { TrafficPreset } from './api-contracts.ts';
import { formatBytes } from './format-bytes.ts';
import { formatUtcTimestamp } from './format-time.ts';
import type { Basis, Reason } from './api-contracts-identity.ts';
import { reasonText } from './identity-view.ts';

/**
 * Pure presentation and request rules for the traffic surfaces. Nothing here fetches or invents
 * data: the window and filters a visitor typed are validated against the same bounds the API
 * enforces before they can reach an API path (the API re-checks everything), a value the API did not
 * report is "Not reported" or "Unknown", never a zero, and every status is a word and an icon as well
 * as a colour. Text that came from a flow source (names, domains, labels) is returned as plain
 * strings for the components to render as text.
 */

export const TRAFFIC_PRESET_OPTIONS: ReadonlyArray<{ id: TrafficPreset; label: string }> = [
  { id: '1h', label: 'Last hour' },
  { id: '6h', label: 'Last 6 hours' },
  { id: '24h', label: 'Last 24 hours' },
  { id: '7d', label: 'Last 7 days' },
];
export const DEFAULT_PRESET: TrafficPreset = '24h';
export const MAX_WINDOW_DAYS = 31;
export const MAX_BASELINE_WINDOW_DAYS = 7;
export const DEFAULT_FLOW_LIMIT = 50;
export const DEFAULT_LIST_LIMIT = 25;
const FUTURE_TOLERANCE_MS = 60_000;
const DAY_MS = 86_400_000;

export const NOT_REPORTED = 'Not reported';
export const UNKNOWN = 'Unknown';

// --- the time window -----------------------------------------------------------------------------------

type Raw = string | string[] | undefined;

function first(value: Raw): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

export interface TrafficWindow {
  /** The preset in use, or null for a custom window. */
  preset: TrafficPreset | null;
  /** RFC 3339 bounds of a custom window (UTC), else null. */
  from: string | null;
  to: string | null;
  /** The query string to send to the API and to keep in page links. */
  query: string;
  /** Values for the custom-range inputs (UTC, minute precision). */
  fromInput: string;
  toInput: string;
  label: string;
  /** True when what was asked for was unusable and the default was used instead. */
  adjusted: boolean;
}

const LOCAL_INPUT = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})(?::(\d{2}))?Z?$/;

function parseInstant(value: string | undefined): Date | null {
  if (value === undefined) return null;
  const match = LOCAL_INPUT.exec(value.trim());
  if (match === null) return null;
  const normalised = `${match[1]}T${match[2]}:${match[3] ?? '00'}Z`;
  const moment = new Date(normalised);
  if (Number.isNaN(moment.getTime())) return null;
  // Date rolls an impossible day (30 February) over; only an exact round trip is a real instant.
  return moment.toISOString().slice(0, 19) === normalised.slice(0, 19) ? moment : null;
}

function inputText(moment: Date): string {
  return moment.toISOString().slice(0, 16);
}

function windowText(moment: Date): string {
  return `${moment.toISOString().slice(0, 16).replace('T', ' ')} UTC`;
}

function presetWindow(preset: TrafficPreset, adjusted: boolean): TrafficWindow {
  const option = TRAFFIC_PRESET_OPTIONS.find((candidate) => candidate.id === preset);
  return {
    preset,
    from: null,
    to: null,
    query: `preset=${preset}`,
    fromInput: '',
    toInput: '',
    label: option?.label ?? preset,
    adjusted,
  };
}

export function resolveTrafficWindow(
  raw: { preset?: Raw; from?: Raw; to?: Raw },
  now: Date,
  maxDays: number,
): TrafficWindow {
  const preset = first(raw.preset);
  const fromText = first(raw.from)?.trim() ?? '';
  const toText = first(raw.to)?.trim() ?? '';
  if (fromText !== '' || toText !== '') {
    const from = parseInstant(fromText);
    const to = parseInstant(toText);
    const usable =
      from !== null &&
      to !== null &&
      from.getTime() < to.getTime() &&
      to.getTime() - from.getTime() <= maxDays * DAY_MS &&
      to.getTime() <= now.getTime() + FUTURE_TOLERANCE_MS;
    if (!usable) return presetWindow(DEFAULT_PRESET, true);
    const query = new URLSearchParams({
      from: `${from.toISOString().slice(0, 19)}Z`,
      to: `${to.toISOString().slice(0, 19)}Z`,
    }).toString();
    return {
      preset: null,
      from: `${from.toISOString().slice(0, 19)}Z`,
      to: `${to.toISOString().slice(0, 19)}Z`,
      query,
      fromInput: inputText(from),
      toInput: inputText(to),
      label: `${windowText(from)} to ${windowText(to)}`,
      adjusted: false,
    };
  }
  if (preset === undefined || preset === '') return presetWindow(DEFAULT_PRESET, false);
  const known = TRAFFIC_PRESET_OPTIONS.find((candidate) => candidate.id === preset);
  return known ? presetWindow(known.id, false) : presetWindow(DEFAULT_PRESET, true);
}

// --- filters ---------------------------------------------------------------------------------------------

export type FilterValues = Partial<Record<FilterName, string>>;

export interface ExplorerFilters {
  /** Canonical values that may be sent to the API. */
  values: FilterValues;
  /** Filters that were dropped: malformed, or needing a permission the viewer does not hold. */
  refused: FilterName[];
}

const IPV4 = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const ENDPOINT_FILTERS: readonly FilterName[] = ['source_ip', 'destination_ip'];
const PROTOCOLS = ['tcp', 'udp', 'icmp', 'other'];
const DIRECTIONS = ['inbound', 'outbound', 'internal'];

function isIpAddress(value: string): boolean {
  if (value.length > 45) return false;
  if (IPV4.test(value)) return true;
  if (!/^[0-9a-fA-F:.]+$/.test(value) || !value.includes(':')) return false;
  try {
    new URL(`http://[${value}]/`);
    return true;
  } catch {
    return false;
  }
}

function inRange(value: string, low: number, high: number): boolean {
  return /^[0-9]{1,10}$/.test(value) && Number(value) >= low && Number(value) <= high;
}

function isFilterText(value: string): boolean {
  const length = Array.from(value).length;
  return length >= 1 && length <= 128 && !/[\p{C}]/u.test(value) && !/[^\S ]/.test(value);
}

const VALIDATORS: Record<FilterName, (value: string) => boolean> = {
  source_ip: isIpAddress,
  destination_ip: isIpAddress,
  device: isFilterText,
  application: isFilterText,
  vlan: (value) => inRange(value, 0, 4094),
  port: (value) => inRange(value, 0, 65535),
  asn: (value) => inRange(value, 1, 4294967295),
  country: (value) => /^[A-Z]{2}$/.test(value),
  protocol: (value) => PROTOCOLS.includes(value),
  direction: (value) => DIRECTIONS.includes(value),
};

export function parseExplorerFilters(
  raw: Record<string, Raw>,
  options: { detail: boolean },
): ExplorerFilters {
  const values: FilterValues = {};
  const refused: FilterName[] = [];
  for (const name of FILTER_NAMES) {
    const text = first(raw[name])?.trim() ?? '';
    if (text === '') continue;
    if (ENDPOINT_FILTERS.includes(name) && !options.detail) {
      refused.push(name);
    } else if (VALIDATORS[name](text)) {
      values[name] = text;
    } else {
      refused.push(name);
    }
  }
  return { values, refused };
}

function filterPairs(filters: FilterValues): URLSearchParams {
  const params = new URLSearchParams();
  for (const name of FILTER_NAMES) {
    const value = filters[name];
    if (value !== undefined) params.set(name, value);
  }
  return params;
}

// --- paths -------------------------------------------------------------------------------------------------

export function flowsPath(window: TrafficWindow, filters: FilterValues, limit: number): string {
  const extra = filterPairs(filters).toString();
  return `/api/v1/traffic/flows?${window.query}&limit=${limit}${extra === '' ? '' : `&${extra}`}`;
}

export function applicationsPath(window: TrafficWindow, limit: number): string {
  return `/api/v1/traffic/applications?${window.query}&limit=${limit}`;
}

export function destinationsPath(window: TrafficWindow, limit: number): string {
  return `/api/v1/traffic/destinations?${window.query}&limit=${limit}`;
}

export function anomaliesPath(window: TrafficWindow): string {
  return `/api/v1/traffic/anomalies?${window.query}`;
}

/**
 * The Flow Explorer address that drills into one row's subject, or null when the filters could not
 * be applied (malformed text, or an address filter the viewer's role would be refused). Going through
 * the same parser the page uses means a link can never lead to a "filter not applied" notice.
 */
export function flowsDrillHref(
  window: TrafficWindow,
  filters: FilterValues,
  options: { detail: boolean },
): string | null {
  const parsed = parseExplorerFilters(filters, options);
  if (parsed.refused.length > 0 || Object.keys(parsed.values).length === 0) return null;
  return trafficHref('flows', window, parsed.values);
}

function canonicalInstant(value: string): string {
  return `${value.slice(0, 19)}Z`;
}

/** The Flow Explorer for exactly one anomalous hour (UTC), optionally narrowed by a filter. */
export function hourFlowsHref(
  start: string,
  end: string,
  filters: FilterValues,
  options: { detail: boolean },
): string | null {
  const parsed = parseExplorerFilters(filters, options);
  if (parsed.refused.length > 0) return null;
  const range = new URLSearchParams({ from: canonicalInstant(start), to: canonicalInstant(end) });
  for (const [name, value] of Object.entries(parsed.values)) range.set(name, value);
  return `/traffic/flows?${range.toString()}`;
}

export type TrafficSection = 'overview' | 'flows' | 'applications' | 'destinations' | 'anomalies';

export function trafficHref(
  section: TrafficSection,
  window: TrafficWindow,
  filters: FilterValues = {},
): string {
  const base = section === 'overview' ? '/traffic' : `/traffic/${section}`;
  const extra = filterPairs(filters).toString();
  return `${base}?${window.query}${extra === '' ? '' : `&${extra}`}`;
}

// --- attribution ------------------------------------------------------------------------------------------------

export interface AttributionView {
  kind: 'person' | 'unknown' | 'restricted' | 'withheld' | 'unavailable';
  headline: string;
  /** Present only when the identity service answered with a basis. */
  basis: Basis | null;
  confidence: string;
  reason: string;
  device: string | null;
  /** The canonical device id, only when the identity service named one (for an inventory link). */
  deviceId: string | null;
  /** The canonical person id, only when a person is named (for a profile link); never a guess. */
  personId: string | null;
}

function deviceText(attribution: FlowAttribution | null): string | null {
  const device = attribution?.device ?? null;
  if (device === null) return null;
  return device.label ?? device.id;
}

function confidenceTextOf(value: number | null): string {
  return value === null || !Number.isFinite(value) ? '' : `${Math.round(value * 100)}%`;
}

function unavailable(headline: string, kind: AttributionView['kind'] = 'unavailable'): AttributionView {
  return { kind, headline, basis: null, confidence: '', reason: '', device: null, deviceId: null, personId: null };
}

export function attributionPresentation(
  attribution: FlowAttribution | null,
  status: AttributionStatus,
): AttributionView {
  if (status.level === 'none' || status.state === 'withheld') {
    return unavailable('Not available to your role', 'withheld');
  }
  if (status.state === 'not-connected') return unavailable('Identity service not connected');
  if (status.state === 'unknown') return unavailable('Identity state unknown');
  if (status.state === 'not-evaluated' || attribution === null) return unavailable('Not evaluated');

  const reason = reasonText(attribution.reason as Reason | null);
  const device = deviceText(attribution);
  const common = {
    basis: attribution.basis,
    confidence: confidenceTextOf(attribution.confidence),
    reason,
    device,
    deviceId: attribution.device?.id ?? null,
    personId: null,
  };
  if (attribution.reason === 'restricted') {
    return { kind: 'restricted', headline: 'Withheld for your role', ...common, basis: 'unknown', confidence: '' };
  }
  if (attribution.basis === 'unknown' || attribution.person === null) {
    return { kind: 'unknown', headline: 'Not identified', ...common, basis: 'unknown' };
  }
  const personId = attribution.person.id;
  const name = attribution.person.label;
  if (attribution.basis === 'inferred') {
    return {
      kind: 'person',
      headline: name === null ? 'Possibly an unnamed person' : `Possibly ${name}`,
      ...common,
      personId,
    };
  }
  return { kind: 'person', headline: name ?? 'Unnamed person', ...common, personId };
}

export function attributionNotice(status: AttributionStatus, hasRows: boolean): string {
  if (!hasRows) return '';
  switch (status.state) {
    case 'withheld':
      return 'Your role does not include naming the person behind an address, so rows show endpoints only.';
    case 'not-connected':
      return 'No identity source is connected, so no flow is attributed to a person. An address alone is never an identity.';
    case 'unknown':
      return 'The identity service could not be read, so no flow is attributed. Nothing is estimated in its place.';
    case 'ok':
      return status.level === 'endpoint'
        ? 'Your role may see the device behind an address but not the person; the person is withheld.'
        : 'People are shown as observed, inferred or unknown, with the evidence-based confidence. Inferred is never a fact.';
    default:
      return '';
  }
}

// --- applications, destinations ------------------------------------------------------------------------------------

export interface StatusView {
  label: string;
  icon: string;
  theme: 'success' | 'warning' | 'danger' | 'secondary' | 'info';
}

export function trendPresentation(trend: AppTrend): { text: string; icon: string; theme: StatusView['theme'] } {
  switch (trend.state) {
    case 'up': {
      const percent = Math.round((trend.change_ratio ?? 0) * 100);
      return { text: `Up ${percent.toLocaleString('en-GB')}%`, icon: 'bi-arrow-up-right', theme: 'info' };
    }
    case 'down': {
      const percent = Math.round(-(trend.change_ratio ?? 0) * 100);
      return { text: `Down ${percent.toLocaleString('en-GB')}%`, icon: 'bi-arrow-down-right', theme: 'info' };
    }
    case 'flat':
      return { text: 'Flat (within 10%)', icon: 'bi-dash', theme: 'secondary' };
    case 'new':
      return { text: 'New in this window', icon: 'bi-plus-circle', theme: 'info' };
    default:
      return { text: 'Unknown (no earlier window to compare)', icon: 'bi-question-circle', theme: 'secondary' };
  }
}

export function riskPresentation(risk: RiskLevel): StatusView {
  switch (risk) {
    case 'low':
      return { label: 'Low risk', icon: 'bi-check-circle', theme: 'success' };
    case 'medium':
      return { label: 'Medium risk', icon: 'bi-exclamation-circle', theme: 'warning' };
    case 'high':
      return { label: 'High risk', icon: 'bi-exclamation-triangle', theme: 'danger' };
    default:
      return { label: UNKNOWN, icon: 'bi-question-circle', theme: 'secondary' };
  }
}

export function approvalPresentation(approval: Approval): StatusView {
  switch (approval) {
    case 'approved':
      return { label: 'Approved', icon: 'bi-check-circle', theme: 'success' };
    case 'unapproved':
      return { label: 'Not approved', icon: 'bi-x-circle', theme: 'danger' };
    default:
      return { label: UNKNOWN, icon: 'bi-question-circle', theme: 'secondary' };
  }
}

export function reputationPresentation(reputation: Reputation): StatusView {
  switch (reputation) {
    case 'allow-listed':
      return { label: 'Allow-listed', icon: 'bi-check-circle', theme: 'success' };
    case 'deny-listed':
      return { label: 'Deny-listed', icon: 'bi-slash-circle', theme: 'danger' };
    default:
      return { label: UNKNOWN, icon: 'bi-question-circle', theme: 'secondary' };
  }
}

export function policyNotice(state: 'not-configured' | 'configured' | 'invalid', noun: string): string {
  if (state === 'configured') return '';
  if (state === 'invalid') {
    return `The operator traffic policy file is invalid, so no ${noun} is classified. Fix the file; nothing is guessed.`;
  }
  return `No operator traffic policy is configured, so ${noun} is Unknown. Netsight does not classify anything on its own.`;
}

// --- anomalies ---------------------------------------------------------------------------------------------------------

export function formatRatio(ratio: number | null): string {
  if (ratio === null || !Number.isFinite(ratio)) return 'No baseline traffic';
  return `${Number(ratio.toFixed(ratio >= 10 ? 0 : 1))}×`;
}

export function formatSignedBytes(value: number): string {
  return value < 0 ? `−${formatBytes(-value)}` : `+${formatBytes(value)}`;
}

export function anomalyHeadline(anomaly: Anomaly): string {
  const subject = anomaly.subject.kind === 'total' ? 'Total traffic' : (anomaly.subject.label ?? 'Application');
  const observed = formatBytes(anomaly.observed);
  const usual = formatBytes(anomaly.baseline);
  if (anomaly.ratio === null) {
    return `${subject}: ${observed} with no traffic in the same hour of the prior weeks`;
  }
  if (anomaly.direction === 'below') {
    return `${subject}: ${observed}, ${formatRatio(anomaly.ratio)} the usual ${usual}, below the same hour of prior weeks`;
  }
  return `${subject}: ${observed}, ${formatRatio(anomaly.ratio)} the usual ${usual} for this hour`;
}

export function contextText(context: AnomalyContext): string {
  if (context.outside_working_hours === null) return 'Working hours not configured';
  return context.outside_working_hours
    ? 'Outside configured working hours (context only, not a finding)'
    : 'Within working hours';
}

const PATTERN_LABELS: Record<string, string> = {
  backup: 'Backups',
  'cloud-sync': 'Cloud sync',
  'cctv-or-nvr': 'CCTV or NVR uploads',
  'patching-or-updates': 'Patching and software updates',
  replication: 'Replication',
  'scheduled-maintenance': 'Scheduled maintenance',
  'antivirus-update': 'Antivirus updates',
  'authorised-remote-work': 'Authorised remote work',
};

export function patternLabel(pattern: string): string {
  return PATTERN_LABELS[pattern] ?? pattern;
}

export function workingHoursText(hours: WorkingHours): string {
  switch (hours.state) {
    case 'configured':
      return `Working hours: ${hours.timezone ?? ''}`;
    case 'invalid':
      return 'Working hours configuration is invalid: after-hours context is unavailable';
    default:
      return 'Working hours not configured: after-hours context is unavailable';
  }
}

export function evaluationNotice(evaluation: Evaluation, method: BaselineMethod): string {
  switch (evaluation.status) {
    case 'insufficient-baseline':
      return `Insufficient baseline: fewer than ${method.min_weeks} comparable weeks of the same hour are available for ${evaluation.insufficient_baseline} hourly checks, so nothing is flagged.`;
    case 'partial':
      return `${evaluation.insufficient_baseline} of ${evaluation.buckets} hourly checks had fewer than ${method.min_weeks} comparable weeks and were not judged.`;
    case 'no-data':
      return 'No flow data was available for the hours in this window, so nothing was judged. A gap is not reported as a drop.';
    default:
      return '';
  }
}

export function historyNotice(status: FirstSeenStatus): string {
  switch (status.state) {
    case 'sufficient':
      return '';
    case 'unknown':
      return 'History could not be determined, so first-seen flags are not raised.';
    default:
      return status.oldest === null
        ? 'The flow source holds no flow history before this window, so first-seen flags are not raised.'
        : `First-seen flags need at least ${status.required_days} days of history before the window; the oldest record is ${formatUtcTimestamp(status.oldest)}, so none are raised.`;
  }
}

// --- small cohorts, internal destinations and daylight saving -------------------------------------------------

/**
 * What the small-cohort rule did to an answer. The aggregate tier is never shown figures that rest on
 * fewer source addresses than the minimum the server states; saying so keeps an emptier answer from
 * reading as "nothing happened".
 */
export function cohortNotice(cohort: CohortStatus, noun: string): string {
  switch (cohort.state) {
    case 'sufficient':
      return `These ${noun} describe at least ${cohort.minimum} internal endpoints. Smaller groups are never shown to your role.`;
    case 'too-few-sources':
      return `Some ${noun} were withheld because fewer than ${cohort.minimum} internal endpoints were involved. Small groups are not shown to your role because they can point at one machine; the traffic:read-detail permission shows them.`;
    default:
      return '';
  }
}

/** A count the server withheld for a small group, as opposed to one the source did not report. */
export function withheldCountText(cohort: CohortStatus): string {
  return cohort.state === 'too-few-sources'
    ? `Withheld (fewer than ${cohort.minimum})`
    : NOT_REPORTED;
}

/**
 * What a withheld row shows in place of a figure it may not give: its volume, share, trend, counts and
 * dates are all null, which is different from "not reported" and must not look like zero.
 */
export function withheldRowText(cohort: CohortStatus): string {
  return cohort.minimum === null ? 'Withheld' : `Withheld (fewer than ${cohort.minimum} endpoints)`;
}

/** The Explorer's own items carry no cohort object of their own; the word is enough. */
export const WITHHELD_ITEM = 'Withheld (too few endpoints)';

/** Series the aggregate tier is not shown because too few internal endpoints stood behind them. */
export function seriesWithheldNotice(withheld: number, minimum: number | null): string {
  if (withheld === 0) return '';
  const noun = withheld === 1 ? 'series was' : 'series were';
  const floor = minimum === null ? 'the minimum' : `${minimum}`;
  return `${withheld} ${noun} left out because fewer than ${floor} internal endpoints stood behind ${withheld === 1 ? 'it' : 'them'}. The counts above cover only the series that were judged.`;
}

export function destinationScopeText(scope: DestinationScope): string {
  return scope === 'internal' ? 'Inside the organisation' : '';
}

/**
 * The baseline compares fixed 168-hour UTC weeks. When the policy time zone changed its clock inside
 * the span, the local hour of the earlier weeks is shifted by one; the scores are not affected.
 */
export function daylightSavingNotice(state: DaylightSaving, timezone: string | null): string {
  if (state !== 'crossed') return '';
  const zone = timezone ?? 'the configured time zone';
  return `The weeks compared include a daylight-saving change in ${zone}. Weeks are fixed 168-hour UTC weeks, so the local hour of the earlier weeks is shifted by one hour. Scores are not affected, but whether an earlier week fell outside working hours may differ.`;
}
