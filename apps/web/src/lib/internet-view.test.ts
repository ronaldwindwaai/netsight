import assert from 'node:assert/strict';
import test from 'node:test';

import type { FetchState } from './api-response.ts';
import type { InternetResponse } from './api-contracts-internet.ts';
import { parseInternetResponse } from './api-contracts-internet.ts';
import { buildInstance, loadInternetVectors } from './contract-vectors.ts';
import {
  exportHref,
  formatDuration,
  formatMillis,
  formatPercent,
  freshnessLabel,
  internetSurface,
  monthOptions,
  nonOkBlocks,
  overviewInternetCard,
  requestedMonth,
  slaPath,
  statusPresentation,
} from './internet-view.ts';

const NOW = new Date('2026-10-11T12:00:00Z');
const VECTORS = loadInternetVectors();

function response(set: Record<string, unknown> = {}): InternetResponse {
  const instance = buildInstance(VECTORS.internet_response, { name: 'x', valid: true, set });
  const parsed = parseInternetResponse(instance);
  assert.notEqual(parsed, null);
  return parsed as InternetResponse;
}

const ok = (data: InternetResponse): FetchState<InternetResponse> => ({
  kind: 'ok',
  data,
  correlationId: 'c',
});

const failed = (kind: string, status: number): FetchState<InternetResponse> =>
  ({ kind, code: kind.toUpperCase(), message: 'x', correlationId: 'c', status }) as FetchState<InternetResponse>;

// --- formatting: a missing value is never a zero ----------------------------------------------------

test('unreported values are labelled, never zero', () => {
  assert.equal(formatPercent(null), 'Not reported');
  assert.equal(formatMillis(null), 'Not reported');
  assert.equal(formatDuration(null), 'Not reported');
  assert.equal(formatPercent(0), '0%');
  assert.equal(formatMillis(0), '0 ms');
  assert.equal(formatDuration(0), '0 s');
});

test('percentages keep at most three decimals and drop trailing zeros', () => {
  assert.equal(formatPercent(99.925), '99.925%');
  assert.equal(formatPercent(100), '100%');
  assert.equal(formatPercent(99.9), '99.9%');
  assert.equal(formatPercent(12.34567), '12.346%');
  assert.equal(formatPercent(Number.NaN), 'Not reported');
});

test('milliseconds are rounded sensibly', () => {
  assert.equal(formatMillis(12.5), '12.5 ms');
  assert.equal(formatMillis(1234.567), '1235 ms');
  assert.equal(formatMillis(0.123), '0.12 ms');
  assert.equal(formatMillis(Number.POSITIVE_INFINITY), 'Not reported');
});

test('durations read in the largest sensible units', () => {
  assert.equal(formatDuration(45), '45 s');
  assert.equal(formatDuration(330), '5 min 30 s');
  assert.equal(formatDuration(3600), '1 h');
  assert.equal(formatDuration(3905), '1 h 5 min 5 s');
  assert.equal(formatDuration(90061), '1 d 1 h 1 min 1 s');
  assert.equal(formatDuration(-5), 'Not reported');
});

test('freshness is labelled with the source and its observation time', () => {
  assert.equal(
    freshnessLabel({ state: 'fresh', observed_at: '2026-10-11T09:59:00Z', source: 'librenms' }),
    'Fresh, observed 2026-10-11 09:59:00 UTC (librenms)',
  );
  assert.match(
    freshnessLabel({ state: 'stale', observed_at: '2026-10-11T07:00:00Z', source: 'blackbox-probes' }),
    /^Stale, last observed 2026-10-11 07:00:00 UTC/,
  );
  assert.equal(
    freshnessLabel({ state: 'unknown', observed_at: null, source: 'librenms' }),
    'Freshness unknown (librenms)',
  );
  assert.equal(freshnessLabel({ state: 'unknown', observed_at: null, source: null }), 'Freshness unknown');
});

test('a status is never conveyed by colour alone', () => {
  for (const status of ['up', 'degraded', 'down', 'unknown'] as const) {
    const presentation = statusPresentation(status);
    assert.ok(presentation.label.length > 0 && presentation.icon.startsWith('bi-'));
  }
  assert.equal(statusPresentation('unknown').theme, 'secondary');
  assert.notEqual(statusPresentation('down').label, statusPresentation('up').label);
});

// --- months are server-bounded ------------------------------------------------------------------------

test('the month picker offers the current month and 24 before it, newest first', () => {
  const months = monthOptions(NOW);
  assert.equal(months.length, 25);
  assert.equal(months[0], '2026-10');
  assert.equal(months[1], '2026-09');
  assert.equal(months[24], '2024-10');
});

test('months roll back across a year boundary', () => {
  const months = monthOptions(new Date('2026-01-15T00:00:00Z'));
  assert.equal(months[1], '2025-12');
  assert.equal(months[0], '2026-01');
});

test('a requested month is used only when it is one the server would accept', () => {
  assert.deepEqual(requestedMonth('2026-09', NOW), { month: '2026-09', adjusted: false });
  assert.deepEqual(requestedMonth(undefined, NOW), { month: '2026-10', adjusted: false });
  for (const bad of ['2026-11', '2024-09', '2026-13', 'abc', '', '2026-9', '2026-10\n', ['2026-09', 'x']]) {
    const result = requestedMonth(bad as string, NOW);
    assert.equal(result.month, '2026-10', String(bad));
    assert.equal(result.adjusted, true, String(bad));
  }
  assert.deepEqual(requestedMonth(['2026-08'], NOW), { month: '2026-08', adjusted: false });
});

test('paths and links are built only from a validated month', () => {
  assert.equal(slaPath('2026-09'), '/api/v1/internet/sla?month=2026-09');
  assert.equal(exportHref('2026-09', 'csv'), '/internet/export?month=2026-09&format=csv');
  assert.equal(exportHref('2026-09', 'json'), '/internet/export?month=2026-09&format=json');
  assert.throws(() => slaPath('2026-09&x=1'));
  assert.throws(() => exportHref('../../etc', 'csv'));
});

// --- which surface the page shows -----------------------------------------------------------------------

test('every fetch outcome maps to exactly one honest surface', () => {
  assert.equal(internetSurface(failed('forbidden', 403)), 'permission');
  assert.equal(internetSurface(failed('unauthenticated', 401)), 'unauthenticated');
  assert.equal(internetSurface(failed('error', 500)), 'error');
  assert.equal(internetSurface(failed('rate_limited', 429)), 'error');
  assert.equal(
    internetSurface(ok(response({ state: 'not-connected', links: [], failover: { state: 'unknown', basis: 'unknown' } }))),
    'not-connected',
  );
  assert.equal(
    internetSurface(ok(response({ state: 'unknown', links: [], failover: { state: 'unknown', basis: 'unknown' } }))),
    'unknown',
  );
  assert.equal(internetSurface(ok(response({ links: [] }))), 'empty');
  assert.equal(internetSurface(ok(response())), 'ok');
});

test('a link with a source that is not ok is partial, and says which', () => {
  const full = response().links[0];
  assert.deepEqual(nonOkBlocks(full), []);
  const partial = response({ 'links.0.interface': { ...full.interface, state: 'unknown', oper_status: null, capacity_bps: null, rx_bps: null, tx_bps: null, utilisation_pct: null, public_ip: null } }).links[0];
  assert.deepEqual(nonOkBlocks(partial), ['interface']);
});

// --- the overview Internet card ----------------------------------------------------------------------------

test('the overview card keeps the explicit not-connected surface when nothing is declared', () => {
  const card = overviewInternetCard(
    ok(response({ state: 'not-connected', links: [], failover: { state: 'unknown', basis: 'unknown' } })),
  );
  assert.deepEqual(
    { title: card.title, detail: card.detail, theme: card.theme, progress: card.progress },
    { title: 'Not connected', detail: 'WAN telemetry unavailable', theme: 'secondary', progress: undefined },
  );
});

test('the overview card shows real values only: status, throughput and utilisation', () => {
  const card = overviewInternetCard(ok(response()));
  assert.equal(card.title, 'Up');
  assert.equal(card.theme, 'success');
  assert.equal(card.progress, 10);
  assert.match(card.detail, /100 Mbps down/);
  assert.match(card.detail, /20 Mbps up/);
  assert.match(card.detail, /10% utilised/);
});

test('the overview card never invents throughput that the source did not report', () => {
  const full = response().links[0];
  const silent = response({
    'links.0.interface': { ...full.interface, rx_bps: null, tx_bps: null, utilisation_pct: null },
  });
  const card = overviewInternetCard(ok(silent));
  assert.match(card.detail, /Throughput not reported/);
  assert.equal(card.progress, undefined);
  assert.doesNotMatch(card.detail, /\b0 (bps|Mbps)\b/);
});

test('the overview card says throughput is restricted, not "not reported", without the detail permission', () => {
  const full = response().links[0];
  const restricted = response({
    detail_redacted: true,
    'links.0.configured': { ...full.configured, isp: null, gateway: null },
    'links.0.interface': {
      ...full.interface,
      rx_bps: null,
      tx_bps: null,
      utilisation_pct: null,
      public_ip: null,
    },
  });
  const card = overviewInternetCard(ok(restricted));
  assert.equal(card.title, 'Up');
  assert.match(card.detail, /Throughput restricted/);
  assert.doesNotMatch(card.detail, /not reported|Mbps/i);
  assert.equal(card.progress, undefined);
});

test('stale interface values are labelled stale on the card and not shown as a live gauge', () => {
  const full = response().links[0];
  const stale = response({
    'links.0.interface': {
      ...full.interface,
      freshness: { state: 'stale', observed_at: '2026-10-11T07:00:00Z', source: 'librenms' },
    },
  });
  const card = overviewInternetCard(ok(stale));
  assert.match(card.detail, /stale/i);
  assert.equal(card.progress, undefined);
});

test('the overview card names a failover and a down link', () => {
  const full = response().links[0];
  const down = { ...full, status: 'down' };
  const backup = { ...full, id: 'lte-1', name: 'LTE', role: 'backup', status: 'up' };
  const card = overviewInternetCard(
    ok(response({ links: [down, backup], failover: { state: 'failed-over', basis: 'inferred' } })),
  );
  assert.equal(card.title, 'Failed over');
  assert.equal(card.theme, 'warning');
  const allDown = overviewInternetCard(
    ok(response({ links: [down, { ...backup, status: 'down' }], failover: { state: 'all-down', basis: 'inferred' } })),
  );
  assert.equal(allDown.title, 'Down');
  assert.equal(allDown.theme, 'danger');
});

test('the overview card is restricted, not empty, when the role cannot read the WAN', () => {
  const card = overviewInternetCard(failed('forbidden', 403));
  assert.equal(card.title, 'Restricted');
  assert.equal(card.theme, 'secondary');
  assert.equal(card.progress, undefined);
});

test('the overview card is unknown when the read failed', () => {
  for (const kind of ['error', 'source_unavailable', 'invalid_response', 'rate_limited', 'unauthenticated']) {
    const card = overviewInternetCard(failed(kind, 500));
    assert.equal(card.title, 'Unknown', kind);
    assert.equal(card.theme, 'secondary', kind);
  }
});
