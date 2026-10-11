import assert from 'node:assert/strict';
import test from 'node:test';

import type {
  Anomaly,
  AppTrend,
  AttributionStatus,
  FlowAttribution,
} from './api-contracts-traffic-explorer.ts';
import {
  DEFAULT_PRESET,
  anomalyHeadline,
  applicationsPath,
  approvalPresentation,
  anomaliesPath,
  attributionPresentation,
  contextText,
  destinationsPath,
  evaluationNotice,
  flowsPath,
  formatRatio,
  formatSignedBytes,
  historyNotice,
  parseExplorerFilters,
  reputationPresentation,
  resolveTrafficWindow,
  riskPresentation,
  trafficHref,
  trendPresentation,
  workingHoursText,
} from './traffic-view.ts';

const NOW = new Date('2026-10-11T12:00:00Z');

// --- the time window ---------------------------------------------------------------------------------

test('a valid preset is used as asked', () => {
  const window = resolveTrafficWindow({ preset: '6h' }, NOW, 31);
  assert.equal(window.preset, '6h');
  assert.equal(window.query, 'preset=6h');
  assert.equal(window.adjusted, false);
  assert.equal(window.label, 'Last 6 hours');
});

test('nothing asked for is the default preset, not an adjustment', () => {
  const window = resolveTrafficWindow({}, NOW, 31);
  assert.equal(window.preset, DEFAULT_PRESET);
  assert.equal(window.adjusted, false);
});

test('an unknown preset falls back to the default and says it was adjusted', () => {
  const window = resolveTrafficWindow({ preset: '12h' }, NOW, 31);
  assert.deepEqual([window.preset, window.adjusted], [DEFAULT_PRESET, true]);
  assert.equal(resolveTrafficWindow({ preset: ['6h', '1h'] }, NOW, 31).preset, '6h');
});

test('a custom window is read as UTC and sent as RFC 3339', () => {
  const window = resolveTrafficWindow(
    { from: '2026-10-10T08:30', to: '2026-10-11T08:30' },
    NOW,
    31,
  );
  assert.equal(window.preset, null);
  assert.equal(window.query, 'from=2026-10-10T08%3A30%3A00Z&to=2026-10-11T08%3A30%3A00Z');
  assert.equal(window.fromInput, '2026-10-10T08:30');
  assert.equal(window.toInput, '2026-10-11T08:30');
  assert.match(window.label, /2026-10-10 08:30 UTC to 2026-10-11 08:30 UTC/);
  assert.equal(window.adjusted, false);
});

test('a custom window that the API would refuse is never sent', () => {
  const refused = [
    { from: '2026-10-10T08:30' },
    { to: '2026-10-11T08:30' },
    { from: '2026-10-11T08:30', to: '2026-10-10T08:30' },
    { from: '2026-10-11T08:30', to: '2026-10-11T08:30' },
    { from: 'yesterday', to: 'today' },
    { from: '2026-02-30T00:00', to: '2026-03-02T00:00' },
    { from: '2026-08-01T00:00', to: '2026-10-11T00:00' },
    { from: '2026-10-11T10:00', to: '2026-10-12T10:00' },
    { from: '', to: '' },
  ];
  for (const raw of refused) {
    const window = resolveTrafficWindow(raw, NOW, 31);
    assert.equal(window.preset, DEFAULT_PRESET, JSON.stringify(raw));
    assert.equal(window.query, `preset=${DEFAULT_PRESET}`);
  }
  assert.equal(resolveTrafficWindow({ from: '2026-10-10T10:00', to: '2026-10-11T10:00' }, NOW, 31).adjusted, false);
  assert.equal(resolveTrafficWindow({ from: '2026-10-10T10:00', to: '2026-10-12T10:00' }, NOW, 31).adjusted, true);
});

test('the window is capped at 31 days, and at 7 for the baseline surface', () => {
  const thirtyOneDays = { from: '2026-09-10T12:00', to: '2026-10-11T12:00' };
  assert.equal(resolveTrafficWindow(thirtyOneDays, NOW, 31).preset, null);
  assert.equal(resolveTrafficWindow(thirtyOneDays, NOW, 7).preset, DEFAULT_PRESET);
  const week = { from: '2026-10-04T12:00', to: '2026-10-11T12:00' };
  assert.equal(resolveTrafficWindow(week, NOW, 7).preset, null);
});

test('window text is never echoed from the request when it is refused', () => {
  const window = resolveTrafficWindow({ from: '<script>', to: '"; drop' }, NOW, 31);
  assert.doesNotMatch(JSON.stringify(window), /script|drop/);
});

// --- filters -------------------------------------------------------------------------------------------

test('filters are canonicalised and blank form fields are absent', () => {
  const parsed = parseExplorerFilters(
    {
      source_ip: ' 10.1.2.3 ',
      destination_ip: '',
      device: ' edge-1 ',
      vlan: '20',
      application: 'Microsoft 365',
      protocol: 'tcp',
      port: '443',
      country: 'ZA',
      asn: '64500',
      direction: 'outbound',
    },
    { detail: true },
  );
  assert.deepEqual(parsed.refused, []);
  assert.deepEqual(parsed.values, {
    source_ip: '10.1.2.3',
    device: 'edge-1',
    vlan: '20',
    application: 'Microsoft 365',
    protocol: 'tcp',
    port: '443',
    country: 'ZA',
    asn: '64500',
    direction: 'outbound',
  });
});

test('filters the API would refuse are dropped and named, never forwarded', () => {
  const parsed = parseExplorerFilters(
    {
      source_ip: '10.0.0.0/8',
      vlan: '4095',
      port: '65536',
      asn: 'AS64500',
      country: 'za',
      protocol: 'gre',
      direction: 'sideways',
      device: 'x'.repeat(129),
      application: 'a\u0000b',
    },
    { detail: true },
  );
  assert.deepEqual(parsed.values, {});
  assert.deepEqual(
    [...parsed.refused].sort(),
    ['application', 'asn', 'country', 'device', 'direction', 'port', 'protocol', 'source_ip', 'vlan'].sort(),
  );
});

test('an address filter without the endpoint-level permission is dropped', () => {
  const parsed = parseExplorerFilters(
    { source_ip: '10.1.2.3', destination_ip: '10.1.2.4', protocol: 'udp' },
    { detail: false },
  );
  assert.deepEqual(parsed.values, { protocol: 'udp' });
  assert.deepEqual([...parsed.refused].sort(), ['destination_ip', 'source_ip']);
});

test('only allow-listed names are read from the request', () => {
  const parsed = parseExplorerFilters({ user: 'alice', sort: 'bytes', port: '80' }, { detail: true });
  assert.deepEqual(parsed.values, { port: '80' });
  assert.deepEqual(parsed.refused, []);
});

test('IPv6 and mapped addresses are accepted, nonsense is not', () => {
  for (const ok of ['2001:db8::1', '::1', '::ffff:10.1.2.3', '255.255.255.255']) {
    assert.equal(parseExplorerFilters({ source_ip: ok }, { detail: true }).values.source_ip, ok, ok);
  }
  for (const bad of ['999.1.1.1', '1.2.3', 'fe80::1%eth0', '10.1.2.3; drop', 'host.example']) {
    assert.deepEqual(parseExplorerFilters({ source_ip: bad }, { detail: true }).values, {}, bad);
  }
});

// --- request paths ---------------------------------------------------------------------------------------

test('the flows path carries the window, the limit and the filters in a fixed order', () => {
  const window = resolveTrafficWindow({ preset: '1h' }, NOW, 31);
  const path = flowsPath(window, { port: '443', protocol: 'tcp', source_ip: '10.0.0.1' }, 50);
  assert.equal(
    path,
    '/api/v1/traffic/flows?preset=1h&limit=50&source_ip=10.0.0.1&protocol=tcp&port=443',
  );
});

test('filter values are URL-encoded', () => {
  const window = resolveTrafficWindow({ preset: '1h' }, NOW, 31);
  const path = flowsPath(window, { application: 'a&b=c d' }, 10);
  assert.ok(path.endsWith('application=a%26b%3Dc+d'), path);
});

test('summary paths carry the window and a limit only', () => {
  const window = resolveTrafficWindow({ preset: '24h' }, NOW, 31);
  assert.equal(applicationsPath(window, 25), '/api/v1/traffic/applications?preset=24h&limit=25');
  assert.equal(destinationsPath(window, 25), '/api/v1/traffic/destinations?preset=24h&limit=25');
  assert.equal(anomaliesPath(window), '/api/v1/traffic/anomalies?preset=24h');
});

test('page links keep the window and the filters', () => {
  const window = resolveTrafficWindow({ preset: '6h' }, NOW, 31);
  assert.equal(trafficHref('applications', window), '/traffic/applications?preset=6h');
  assert.equal(
    trafficHref('flows', window, { application: 'Zoom' }),
    '/traffic/flows?preset=6h&application=Zoom',
  );
  assert.equal(trafficHref('overview', window), '/traffic?preset=6h');
});

// --- attribution -------------------------------------------------------------------------------------------

const PERSON = { id: 'person-3f1c2a9e-1b2c-4d3e-8f4a-5b6c7d8e9f01', label: 'Alice Example' };
const DEVICE = { id: 'device-a7f3d9e1-1c2b-4a8e-9f0d-5b6c7d8e9f01', label: 'PC-001' };
const OK: AttributionStatus = { level: 'person', state: 'ok', as_of: '2026-10-11T12:00:00Z' };

function attribution(over: Partial<FlowAttribution> = {}): FlowAttribution {
  return {
    basis: 'observed',
    reason: null,
    confidence: 0.9,
    ambiguous: false,
    person: PERSON,
    device: DEVICE,
    ...over,
  };
}

test('an observed person is named with the word Observed and the confidence', () => {
  const view = attributionPresentation(attribution(), OK);
  assert.equal(view.kind, 'person');
  assert.equal(view.headline, 'Alice Example');
  assert.equal(view.basis, 'observed');
  assert.equal(view.confidence, '90%');
  assert.equal(view.device, 'PC-001');
});

test('only a named person carries a profile id for drill-down', () => {
  assert.equal(attributionPresentation(attribution(), OK).personId, PERSON.id);
  assert.equal(
    attributionPresentation(
      attribution({ basis: 'unknown', reason: 'no-evidence', confidence: null, person: null }),
      OK,
    ).personId,
    null,
  );
  assert.equal(
    attributionPresentation(null, { level: 'none', state: 'withheld', as_of: null }).personId,
    null,
  );
});

test('an inferred person is only ever "possibly" that person', () => {
  const view = attributionPresentation(
    attribution({ basis: 'inferred', reason: 'declared-assignment', confidence: 0.6 }),
    OK,
  );
  assert.equal(view.headline, 'Possibly Alice Example');
  assert.equal(view.basis, 'inferred');
  assert.match(view.reason, /asset-register/);
});

test('unknown names nobody and says why', () => {
  const view = attributionPresentation(
    attribution({ basis: 'unknown', reason: 'shared-address', confidence: null, person: null, ambiguous: true }),
    OK,
  );
  assert.equal(view.kind, 'unknown');
  assert.equal(view.headline, 'Not identified');
  assert.match(view.reason, /NAT or shared/);
});

test('the endpoint level says the person is withheld', () => {
  const view = attributionPresentation(
    attribution({ basis: 'unknown', reason: 'restricted', confidence: null, person: null }),
    { ...OK, level: 'endpoint' },
  );
  assert.equal(view.kind, 'restricted');
  assert.equal(view.headline, 'Withheld for your role');
  assert.equal(view.device, 'PC-001');
});

test('a role with no users permission sees that attribution is not available, not "unknown"', () => {
  const view = attributionPresentation(null, { level: 'none', state: 'withheld', as_of: null });
  assert.equal(view.kind, 'withheld');
  assert.equal(view.headline, 'Not available to your role');
});

test('an unconnected or failing identity service is named as such', () => {
  assert.equal(
    attributionPresentation(null, { level: 'person', state: 'not-connected', as_of: null }).headline,
    'Identity service not connected',
  );
  assert.equal(
    attributionPresentation(null, { level: 'person', state: 'unknown', as_of: null }).headline,
    'Identity state unknown',
  );
});

test('an unnamed person is not given a made-up name', () => {
  const view = attributionPresentation(attribution({ person: { ...PERSON, label: null } }), OK);
  assert.equal(view.headline, 'Unnamed person');
});

test('hostile labels are returned as plain text', () => {
  const hostile = '<img src=x onerror=alert(1)>';
  const view = attributionPresentation(attribution({ person: { ...PERSON, label: hostile } }), OK);
  assert.equal(view.headline, hostile);
});

// --- applications, destinations ---------------------------------------------------------------------------

test('trends are words and numbers, never an invented direction', () => {
  const trend = (state: AppTrend['state'], ratio: number | null, previous: number | null): AppTrend => ({
    state,
    change_ratio: ratio,
    previous_bytes: previous,
  });
  assert.equal(trendPresentation(trend('up', 0.5, 100)).text, 'Up 50%');
  assert.equal(trendPresentation(trend('down', -0.6, 100)).text, 'Down 60%');
  assert.match(trendPresentation(trend('flat', 0.02, 100)).text, /Flat/);
  assert.equal(trendPresentation(trend('new', null, 0)).text, 'New in this window');
  assert.match(trendPresentation(trend('unknown', null, null)).text, /Unknown/);
  assert.equal(trendPresentation(trend('up', 12, 1)).text, 'Up 1,200%');
});

test('risk, approval and reputation are Unknown unless the operator policy said otherwise', () => {
  assert.equal(riskPresentation('unknown').label, 'Unknown');
  assert.equal(riskPresentation('high').label, 'High risk');
  assert.equal(approvalPresentation('unknown').label, 'Unknown');
  assert.equal(approvalPresentation('approved').label, 'Approved');
  assert.equal(approvalPresentation('unapproved').label, 'Not approved');
  assert.equal(reputationPresentation('unknown').label, 'Unknown');
  assert.equal(reputationPresentation('allow-listed').label, 'Allow-listed');
  assert.equal(reputationPresentation('deny-listed').label, 'Deny-listed');
  for (const view of [riskPresentation('low'), approvalPresentation('approved'), reputationPresentation('deny-listed')]) {
    assert.ok(view.icon.startsWith('bi-'), 'a status is an icon and a word, never colour alone');
  }
});

// --- anomalies -----------------------------------------------------------------------------------------------

const ANOMALY: Anomaly = {
  kind: 'volume-deviation',
  subject: { kind: 'total', label: null },
  bucket_start: '2026-10-06T02:00:00Z',
  bucket_end: '2026-10-06T03:00:00Z',
  direction: 'above',
  observed: 9_000_000_000,
  baseline: 1_000_000_000,
  baseline_samples: 4,
  difference: 8_000_000_000,
  ratio: 9,
  score: 12.5,
  confidence: 'high',
  context: { outside_working_hours: true, common_legitimate_patterns: ['backup'] },
};

test('an anomaly is described by its evidence, not by a verdict', () => {
  const text = anomalyHeadline(ANOMALY);
  assert.match(text, /Total traffic/);
  assert.match(text, /9 GB/);
  assert.match(text, /9×/);
  assert.match(text, /usual 1 GB/);
  assert.doesNotMatch(text, /malicious|attack|threat|breach/i);
});

test('a zero baseline and a drop are worded honestly', () => {
  const zero = anomalyHeadline({ ...ANOMALY, baseline: 0, ratio: null, difference: ANOMALY.observed });
  assert.match(zero, /no traffic in the same hour/);
  const drop = anomalyHeadline({
    ...ANOMALY,
    subject: { kind: 'application', label: 'Zoom' },
    direction: 'below',
    observed: 100_000_000,
    difference: -900_000_000,
    ratio: 0.1,
  });
  assert.match(drop, /Zoom/);
  assert.match(drop, /below/);
});

test('ratios and signed differences are formatted without losing the sign', () => {
  assert.equal(formatRatio(9), '9×');
  assert.equal(formatRatio(0.1), '0.1×');
  assert.equal(formatRatio(null), 'No baseline traffic');
  assert.equal(formatSignedBytes(8_000_000_000), '+8 GB');
  assert.equal(formatSignedBytes(-900_000_000), '−900 MB');
});

test('working hours are context: not configured is unknown, never "after hours"', () => {
  assert.equal(contextText({ outside_working_hours: null, common_legitimate_patterns: [] }), 'Working hours not configured');
  assert.equal(contextText({ outside_working_hours: false, common_legitimate_patterns: [] }), 'Within working hours');
  assert.equal(
    contextText({ outside_working_hours: true, common_legitimate_patterns: [] }),
    'Outside configured working hours (context only, not a finding)',
  );
  assert.equal(workingHoursText({ state: 'configured', timezone: 'Africa/Johannesburg' }), 'Working hours: Africa/Johannesburg');
  assert.match(workingHoursText({ state: 'not-configured', timezone: null }), /not configured/);
  assert.match(workingHoursText({ state: 'invalid', timezone: null }), /invalid/);
});

test('an insufficient baseline is stated plainly and flags nothing', () => {
  const notice = evaluationNotice(
    { status: 'insufficient-baseline', series: 1, buckets: 24, evaluated: 0, insufficient_baseline: 24, no_data: 0, anomalies_total: 0, application_series: 'evaluated', daylight_saving: 'none' },
    { algorithm: 'same-hour-of-week-median-mad', weeks: 4, min_weeks: 3, threshold: 3.5, min_difference_bytes: 10485760 },
  );
  assert.match(notice, /Insufficient baseline/);
  assert.match(notice, /fewer than 3 comparable weeks/);
  assert.match(notice, /nothing is flagged/i);
});

test('every evaluation status has a notice or none', () => {
  const method = { algorithm: 'same-hour-of-week-median-mad' as const, weeks: 4, min_weeks: 3, threshold: 3.5, min_difference_bytes: 1 };
  const base = { series: 1, buckets: 10, evaluated: 10, insufficient_baseline: 0, no_data: 0, anomalies_total: 0, application_series: 'evaluated' as const, daylight_saving: 'none' as const };
  assert.equal(evaluationNotice({ ...base, status: 'evaluated' }, method), '');
  assert.match(evaluationNotice({ ...base, status: 'partial', evaluated: 6, insufficient_baseline: 4 }, method), /4 of 10/);
  assert.match(evaluationNotice({ ...base, status: 'no-data', evaluated: 0, no_data: 10 }, method), /No flow data/);
});

test('first-seen history states', () => {
  assert.equal(historyNotice({ state: 'sufficient', required_days: 7, oldest: '2026-08-01T00:00:00Z' }), '');
  assert.match(historyNotice({ state: 'insufficient', required_days: 7, oldest: '2026-10-09T00:00:00Z' }), /at least 7 days/);
  assert.match(historyNotice({ state: 'insufficient', required_days: 7, oldest: null }), /no flow history/i);
  assert.match(historyNotice({ state: 'unknown', required_days: 7, oldest: null }), /could not be determined/);
});
