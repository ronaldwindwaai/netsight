import type {
  AlertCondition,
  AlertOperator,
  AlertRule,
  AlertScope,
  MaintenanceWindow,
} from './api-contracts-alert-rule.ts';
import { MAX_RULE_LIST_OFFSET } from './api-contracts-alert-rule-api.ts';
import type { PageHrefs, RawQuery } from './incident-view.ts';

export const DEFAULT_ALERTING_PAGE_SIZE = 50;
const NON_NEGATIVE_INTEGER = /^\d{1,7}$/;

export type RuleApproval = 'awaiting' | 'approved' | 'inconsistent' | 'disabled';

export interface RuleStatusView {
  label: string;
  approval: RuleApproval;
  detail: string;
}

/**
 * Status and approval as the server recorded them. An active rule with no
 * approval record is surfaced as inconsistent instead of being shown as approved.
 */
export function ruleStatusView(rule: AlertRule): RuleStatusView {
  if (rule.status === 'disabled') {
    return { label: 'Disabled', approval: 'disabled', detail: 'Not evaluated while disabled.' };
  }
  if (rule.status === 'draft') {
    return {
      label: 'Draft',
      approval: 'awaiting',
      detail: 'Awaiting approval; a draft rule is not evaluated.',
    };
  }
  if (rule.approved_by === null || rule.approved_at === null) {
    return {
      label: 'Active',
      approval: 'inconsistent',
      detail: 'Marked active but the API reports no approval record.',
    };
  }
  return { label: 'Active', approval: 'approved', detail: `Approved by ${rule.approved_by}.` };
}

const OPERATOR_SYMBOLS: Record<AlertOperator, string> = {
  gt: '>',
  gte: '>=',
  lt: '<',
  lte: '<=',
  eq: '==',
  ne: '!=',
  matches: 'matches',
};

/** Plain-text condition. The pattern is untrusted text and is never interpreted. */
export function describeCondition(condition: AlertCondition): string {
  const operand = condition.pattern ?? (condition.threshold === null ? '' : String(condition.threshold));
  return `${condition.metric} ${OPERATOR_SYMBOLS[condition.operator]} ${operand}`.trimEnd();
}

export function describeScope(scope: AlertScope): string {
  return `${scope.kind.replaceAll('_', ' ')}: ${scope.ref}`;
}

/** Whole minutes or hours only when exact; otherwise the raw seconds. */
export function formatSeconds(seconds: number): string {
  if (seconds > 0 && seconds % 3600 === 0 && seconds <= 86_400) return `${seconds / 3600} h`;
  if (seconds > 0 && seconds % 60 === 0 && seconds < 86_400) return `${seconds / 60} min`;
  return `${seconds} s`;
}

export type WindowPhase = 'upcoming' | 'active' | 'ended' | 'cancelled' | 'unknown';

const PHASE_LABELS: Record<WindowPhase, string> = {
  upcoming: 'Upcoming',
  active: 'Active now',
  ended: 'Ended',
  cancelled: 'Cancelled',
  unknown: 'Unknown',
};

export function windowPhaseLabel(phase: WindowPhase): string {
  return PHASE_LABELS[phase];
}

/** Phase at the given clock (epoch ms). A cancelled window is never active. */
export function windowPhase(window: MaintenanceWindow, nowMs: number): WindowPhase {
  if (window.status === 'cancelled') return 'cancelled';
  const start = Date.parse(window.starts_at);
  const end = Date.parse(window.ends_at);
  if (!Number.isFinite(nowMs) || Number.isNaN(start) || Number.isNaN(end)) return 'unknown';
  if (nowMs < start) return 'upcoming';
  return nowMs < end ? 'active' : 'ended';
}

export interface WindowCounts extends Record<WindowPhase, number> {
  /** Number of windows in the list these counts were taken from. */
  listed: number;
}

/** Counts over the listed page only; callers must label them so. */
export function windowCounts(windows: readonly MaintenanceWindow[], nowMs: number): WindowCounts {
  const counts: WindowCounts = {
    active: 0,
    upcoming: 0,
    ended: 0,
    cancelled: 0,
    unknown: 0,
    listed: windows.length,
  };
  for (const window of windows) counts[windowPhase(window, nowMs)] += 1;
  return counts;
}

export interface AlertingOffsets {
  rules: number;
  windows: number;
}

function boundedOffset(raw: string | string[] | undefined): number {
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (value === undefined || !NON_NEGATIVE_INTEGER.test(value)) return 0;
  const parsed = Number(value);
  return parsed <= MAX_RULE_LIST_OFFSET ? parsed : 0;
}

export function parseAlertingOffsets(raw: RawQuery): AlertingOffsets {
  return { rules: boundedOffset(raw.rules_offset), windows: boundedOffset(raw.windows_offset) };
}

export type AlertingList = 'rules' | 'windows';

export function alertingListPath(list: AlertingList, offset: number): string {
  const paging = `limit=${DEFAULT_ALERTING_PAGE_SIZE}&offset=${offset}`;
  return list === 'rules'
    ? `/api/v1/alert-rules?${paging}`
    : `/api/v1/maintenance-windows?${paging}&include_cancelled=true`;
}

function alertsHref(offsets: AlertingOffsets, alertsPage: number): string {
  const pairs: string[] = [];
  if (alertsPage > 1) pairs.push(`page=${alertsPage}`);
  if (offsets.rules > 0) pairs.push(`rules_offset=${offsets.rules}`);
  if (offsets.windows > 0) pairs.push(`windows_offset=${offsets.windows}`);
  return pairs.length === 0 ? '/alerts' : `/alerts?${pairs.join('&')}`;
}

/** Paging links for one list that keep the other list's position and the source-alerts page. */
export function alertingPageHrefs(
  list: AlertingList,
  offsets: AlertingOffsets,
  limit: number,
  nextOffset: number | null,
  alertsPage: number,
): PageHrefs {
  const current = offsets[list];
  const withOffset = (offset: number): string =>
    alertsHref({ ...offsets, [list]: offset }, alertsPage);
  return {
    previous: current > 0 ? withOffset(Math.max(0, current - limit)) : null,
    next: nextOffset === null ? null : withOffset(nextOffset),
  };
}
