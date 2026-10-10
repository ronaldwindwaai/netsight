/**
 * Pure view helpers for the diagnostic session page (S7 Step 4e).
 *
 * Deterministic and side-effect free so the page can be tested without React or a browser.
 * Labels never turn a missing measurement into a healthy-looking one, and untrusted values (names,
 * titles, statements) are never interpolated into markup here: components render them as text nodes.
 */
import type { ProbeLocation } from './api-contracts-diagnostic.ts';
import type {
  ChangeKind,
  DiagnosticLocationResult,
  DiagnosticPathHop,
  DiagnosticSession,
  EvidenceBasis,
  PathTier,
} from './api-contracts-diagnostic-session.ts';
import { MAX_SESSION_LIST_OFFSET } from './api-contracts-diagnostic-session.ts';

/** A stored session is a snapshot: after this long its probes are history, not current state. */
export const SESSION_STALE_AFTER_MS = 15 * 60_000;
export const SESSION_LIST_PAGE_SIZE = 20;

const SESSION_ID = /^diagnostic-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export function isSessionId(value: string): boolean {
  return SESSION_ID.test(value);
}

/** Browser link to a stored session; null for anything that is not exactly a session id. */
export function sessionHref(id: string): string | null {
  return isSessionId(id) ? `/diagnostics/${id}` : null;
}

/** Server-side API path for one session; null for anything that is not exactly a session id. */
export function sessionApiPath(id: string): string | null {
  return isSessionId(id) ? `/api/v1/diagnostics/${id}` : null;
}

export function sessionListPath(offset: number): string {
  return `/api/v1/diagnostics?limit=${SESSION_LIST_PAGE_SIZE}&offset=${offset}`;
}

/** Offset from the address bar: a plain non-negative integer within the cap, else the first page. */
export function parseListOffset(raw: string | string[] | undefined): number {
  if (typeof raw !== 'string' || !/^\d{1,5}$/.test(raw)) return 0;
  const value = Number(raw);
  return value <= MAX_SESSION_LIST_OFFSET ? value : 0;
}

export const LOCATION_LABELS: Record<ProbeLocation, string> = {
  'cloud-external': 'Cloud / external',
  'user-lan': 'User LAN',
  'server-vlan': 'Server VLAN',
  branch: 'Branch',
  wifi: 'Wi-Fi',
  'remote-site': 'Remote site',
};

export const TIER_LABELS: Record<PathTier, string> = {
  user: 'User',
  'access-point': 'Access point',
  'access-switch': 'Access switch',
  core: 'Core',
  firewall: 'Firewall',
  server: 'Server',
};

export function tierLabel(tier: PathTier): string {
  return TIER_LABELS[tier];
}

const BASIS_LABELS: Record<EvidenceBasis, string> = {
  observed: 'Observed',
  inferred: 'Inferred',
  unknown: 'Unknown',
};

export function basisLabel(basis: EvidenceBasis): string {
  return BASIS_LABELS[basis];
}

export function changeKindLabel(kind: ChangeKind): string {
  return kind === 'incident' ? 'Incident' : 'Alert';
}

export function changeScopeLabel(scope: 'target' | 'time-window'): string {
  return scope === 'target'
    ? 'Recorded against this target'
    : 'Same time window, not matched to the target';
}

export type OutcomeTone = 'pass' | 'fail' | 'unknown' | 'none';

export interface LocationOutcome {
  tone: OutcomeTone;
  label: string;
  detail: string;
}

function countsText(row: DiagnosticLocationResult): string {
  return `${row.failed} failed, ${row.passed} passed, ${row.unknown_checks} unanswered`;
}

/** What one location reported. Only a measurement is ever shown as pass or fail. */
export function locationOutcome(row: DiagnosticLocationResult): LocationOutcome {
  if (row.state === 'observed') {
    return row.status === 'fail'
      ? { tone: 'fail', label: 'Checks failed', detail: countsText(row) }
      : { tone: 'pass', label: 'Checks passed', detail: countsText(row) };
  }
  if (row.state === 'unknown') {
    return {
      tone: 'unknown',
      label: 'No answer',
      detail:
        'A probe source is configured here but none of its checks could be answered; this location is not assumed healthy.',
    };
  }
  return {
    tone: 'none',
    label: 'Not connected',
    detail: 'No probe source is configured for this location, so its state is unknown.',
  };
}

export interface SessionAge {
  stale: boolean;
  minutes: number;
}

/** Age of a stored session. An unreadable time is treated as stale; a future time as just now. */
export function sessionAge(completedAt: string, nowMs: number): SessionAge {
  const completed = Date.parse(completedAt);
  if (Number.isNaN(completed)) return { stale: true, minutes: 0 };
  const elapsed = Math.max(0, nowMs - completed);
  return { stale: elapsed >= SESSION_STALE_AFTER_MS, minutes: Math.floor(elapsed / 60_000) };
}

/** The sections of a session that are not fully available (empty when everything was observed). */
export function partialSections(session: DiagnosticSession): string[] {
  const sections: string[] = [];
  if (session.locations.some((row) => row.state !== 'observed')) {
    sections.push('Probe locations without a source');
  }
  if (session.path.state !== 'ok') sections.push('Path');
  if (session.recent_changes.state !== 'ok') sections.push('Recent changes');
  return sections;
}

/** Text for one path hop: the explicit device name, or Unknown. The name is untrusted text. */
export function pathHopLabel(hop: DiagnosticPathHop): string {
  const base = hop.state === 'known' && hop.name !== null ? hop.name : 'Unknown';
  return hop.highlight === 'suspected' ? `${base} (suspected tier)` : base;
}
