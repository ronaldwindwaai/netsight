// Typed diagnostic session fixtures for component tests. They mirror the shared contract vector
// base (contracts/test-vectors/diagnostic-session.vectors.json); a unit test parses them with the
// contract parser so they cannot drift into an impossible shape. Imports are relative with explicit
// extensions so both the `node --test` strip-types runner and the esbuild component bundle load them.
import type { DiagnosticRun } from '../lib/api-contracts-diagnostic.ts';
import type {
  DiagnosticLocationResult,
  DiagnosticPath,
  DiagnosticPathHop,
  DiagnosticRecentChanges,
  DiagnosticSession,
  DiagnosticSessionSummary,
} from '../lib/api-contracts-diagnostic-session.ts';

export const SESSION_ID = 'diagnostic-1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d';
export const COMPLETED_AT = '2026-10-10T08:00:05Z';
export const COMPLETED_MS = Date.parse(COMPLETED_AT);
const FW = 'device-2f8a1b2c-3d4e-5f60-7a8b-9c0d1e2f3a4b';
const CORE = 'device-1f8a1b2c-3d4e-5f60-7a8b-9c0d1e2f3a4b';
const ACCESS = 'device-0f8a1b2c-3d4e-5f60-7a8b-9c0d1e2f3a4b';
const SERVER = 'device-3f8a1b2c-3d4e-5f60-7a8b-9c0d1e2f3a4b';

function run(): DiagnosticRun {
  return {
    id: SESSION_ID,
    target: 'SERVER01',
    target_id: SERVER,
    symptom: 'External users cannot reach the service',
    vantage: 'internet',
    started_at: '2026-10-10T08:00:00Z',
    completed_at: COMPLETED_AT,
    checks: [
      {
        id: 'check-tcp-internet-443',
        kind: 'tcp',
        label: 'TCP 443 from internet',
        status: 'fail',
        vantage: 'internet',
        location: 'cloud-external',
        port: 443,
        latency_ms: null,
        detail: 'connection timed out',
        observed_at: '2026-10-10T08:00:03Z',
        evidence_id: 'ev-2',
      },
      {
        id: 'check-tcp-server-vlan-443',
        kind: 'tcp',
        label: 'TCP 443 from the server VLAN',
        status: 'pass',
        vantage: 'server-vlan',
        location: 'server-vlan',
        port: 443,
        latency_ms: 1.8,
        detail: 'the port accepted a connection',
        observed_at: '2026-10-10T08:00:02Z',
        evidence_id: 'ev-1',
      },
    ],
    facts: [{ statement: 'Internal TCP 443 to the host passes', evidence_ids: ['ev-1'] }],
    contradictions: [],
    unknowns: [{ statement: 'No flow telemetry for the perimeter link', evidence_ids: [] }],
    probable_fault_domain: 'firewall',
    confidence: 'low',
    alternative_hypotheses: [{ statement: 'Upstream routing change', evidence_ids: ['ev-2'] }],
    recommended_next_checks: [
      { statement: 'Compare the firewall rule set against the last change', evidence_ids: [] },
    ],
    evidence_ids: ['ev-1', 'ev-2'],
  };
}

function locations(): DiagnosticLocationResult[] {
  const none = (location: DiagnosticLocationResult['location']): DiagnosticLocationResult => ({
    location,
    state: 'not-connected',
    status: null,
    passed: 0,
    failed: 0,
    unknown_checks: 0,
    check_ids: [],
  });
  return [
    {
      location: 'cloud-external',
      state: 'observed',
      status: 'fail',
      passed: 0,
      failed: 1,
      unknown_checks: 0,
      check_ids: ['check-tcp-internet-443'],
    },
    none('user-lan'),
    {
      location: 'server-vlan',
      state: 'observed',
      status: 'pass',
      passed: 1,
      failed: 0,
      unknown_checks: 0,
      check_ids: ['check-tcp-server-vlan-443'],
    },
    none('branch'),
    none('wifi'),
    none('remote-site'),
  ];
}

function hop(
  tier: DiagnosticPathHop['tier'],
  device: string | null = null,
  name: string | null = null,
  highlight: DiagnosticPathHop['highlight'] = null,
): DiagnosticPathHop {
  return { tier, state: device === null ? 'unknown' : 'known', device_id: device, name, highlight };
}

export function okPath(): DiagnosticPath {
  return {
    state: 'ok',
    observed_at: '2026-10-10T08:00:04Z',
    hops: [
      hop('user'),
      hop('access-point'),
      hop('access-switch', ACCESS, 'sw-access-01'),
      hop('core', CORE, 'core-01'),
      hop('firewall', FW, 'fw-01', 'suspected'),
      hop('server', SERVER, 'SERVER01'),
    ],
    links: [
      { from_tier: 'user', to_tier: 'access-point', state: 'unknown' },
      { from_tier: 'access-point', to_tier: 'access-switch', state: 'unknown' },
      { from_tier: 'access-switch', to_tier: 'core', state: 'known' },
      { from_tier: 'core', to_tier: 'firewall', state: 'known' },
      { from_tier: 'firewall', to_tier: 'server', state: 'known' },
    ],
  };
}

export function okChanges(): DiagnosticRecentChanges {
  return {
    state: 'ok',
    window_start: '2026-10-09T08:00:05Z',
    window_end: COMPLETED_AT,
    sources: [
      { source: 'incidents', state: 'ok' },
      { source: 'alerts', state: 'ok' },
      { source: 'configuration-changes', state: 'not-connected' },
    ],
    items: [
      {
        kind: 'incident',
        ref_id: 'incident-1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d',
        severity: 'high',
        title: 'Incident title withheld',
        title_redacted: true,
        occurred_at: '2026-10-10T07:40:00Z',
        scope: 'time-window',
        relation: 'may-correlate',
      },
    ],
  };
}

export function changesState(state: 'not-connected' | 'unknown'): DiagnosticRecentChanges {
  const sourceState = state;
  return {
    state,
    window_start: '2026-10-09T08:00:05Z',
    window_end: COMPLETED_AT,
    sources: [
      { source: 'incidents', state: sourceState },
      { source: 'alerts', state: 'not-connected' },
      { source: 'configuration-changes', state: 'not-connected' },
    ],
    items: [],
  };
}

export function sessionFixture(): DiagnosticSession {
  return {
    run: run(),
    locations: locations(),
    probable_cause: {
      domain: 'firewall',
      confidence: 'low',
      basis: 'inferred',
      pattern: 'external-only-failure',
      summary:
        'The service answers from the internal locations but not from the external one, which narrows the fault to the path between them.',
      evidence: [
        {
          basis: 'observed',
          statement: 'From the external (cloud) location: 1 failed, 0 passed, 0 could not be answered',
          check_ids: ['check-tcp-internet-443'],
        },
        {
          basis: 'observed',
          statement: 'From the server VLAN: 0 failed, 1 passed, 0 could not be answered',
          check_ids: ['check-tcp-server-vlan-443'],
        },
        {
          basis: 'inferred',
          statement:
            'Internal success with external failure narrows the fault to the path between them; it does not prove which device is at fault',
          check_ids: ['check-tcp-internet-443', 'check-tcp-server-vlan-443'],
        },
        {
          basis: 'unknown',
          statement:
            'No probe source is connected for the user LAN, the branch, Wi-Fi, the remote site; they are not assumed healthy',
          check_ids: [],
        },
      ],
    },
    recent_changes: okChanges(),
    path: okPath(),
  };
}

export function unnarrowedSession(): DiagnosticSession {
  const base = sessionFixture();
  return {
    ...base,
    run: { ...base.run, probable_fault_domain: null, confidence: 'unknown' },
    probable_cause: {
      domain: null,
      confidence: 'unknown',
      basis: 'unknown',
      pattern: 'none',
      summary: 'No probable cause could be named from this run.',
      evidence: [
        {
          basis: 'unknown',
          statement: 'The available evidence did not narrow the fault to a single domain',
          check_ids: [],
        },
      ],
    },
    path: {
      ...base.path,
      hops: base.path.hops.map((item) => ({ ...item, highlight: null })),
    },
  };
}

export function summaryFixture(
  id: string = SESSION_ID,
  overrides: Partial<DiagnosticSessionSummary> = {},
): DiagnosticSessionSummary {
  return {
    id,
    target: 'SERVER01',
    started_at: '2026-10-10T08:00:00Z',
    completed_at: COMPLETED_AT,
    probable_fault_domain: 'firewall',
    confidence: 'low',
    ...overrides,
  };
}
