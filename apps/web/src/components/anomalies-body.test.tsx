import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen, within } from '@testing-library/react';

import { AnomaliesBody } from '@/components/anomalies-body';
import type { TrafficAnomaliesResponse } from '@/lib/api-contracts-traffic-explorer';
import {
  HOSTILE,
  STALE,
  anomaliesFixture,
  anomalyFixture,
  emptyAnomalies,
  failureState,
  firstSeenFixture,
  okState,
} from '@/test/traffic-fixtures';

afterEach(() => cleanup());

function show(state: ReturnType<typeof okState<TrafficAnomaliesResponse>> | ReturnType<typeof failureState<TrafficAnomaliesResponse>>) {
  return render(<AnomaliesBody state={state} />);
}
const text = () => document.body.textContent ?? '';

describe('every outcome of the read has its own surface', () => {
  it('permission denied names the permission', () => {
    show(failureState<TrafficAnomaliesResponse>('forbidden', 403));
    assert.match(screen.getByRole('status').textContent ?? '', /traffic:read/);
  });

  it('sign-in, error and rate limit are distinct', () => {
    show(failureState<TrafficAnomaliesResponse>('unauthenticated', 401));
    assert.ok(screen.getByRole('link', { name: /Sign in/ }));
    cleanup();
    show(failureState<TrafficAnomaliesResponse>('error', 500));
    assert.match(text(), /Unable to load data/);
    cleanup();
    show(failureState<TrafficAnomaliesResponse>('rate_limited', 429));
    assert.match(text(), /Too many requests/);
  });

  it('not connected and unknown flag nothing and show no zero', () => {
    show(okState(emptyAnomalies('not-connected')));
    assert.match(screen.getByRole('status').textContent ?? '', /Flow source not connected/);
    assert.equal(screen.queryAllByRole('article').length, 0);
    cleanup();
    show(okState(emptyAnomalies('unknown')));
    assert.match(screen.getByRole('status').textContent ?? '', /state unknown/i);
  });

  it('stale data is labelled', () => {
    show(okState(anomaliesFixture({ freshness: { ...STALE } })));
    assert.match(text(), /Stale monitoring data/);
  });
});

describe('the baseline', () => {
  it('states the deterministic method in plain words', () => {
    show(okState(anomaliesFixture()));
    const method = screen.getByRole('region', { name: /How hours are compared/i }).textContent ?? '';
    assert.match(method, /same hour of the week/i);
    assert.match(method, /median/i);
    assert.match(method, /4 prior weeks/);
    assert.match(method, /at least 3/);
    assert.match(method, /3\.5/);
    assert.match(method, /10 MiB/);
    assert.match(method, /No machine learning/);
  });

  it('insufficient baseline is a result, flags nothing and says why', () => {
    show(
      okState(
        anomaliesFixture({
          anomalies: [],
          first_seen: [],
          evaluation: {
            status: 'insufficient-baseline',
            series: 1,
            buckets: 24,
            evaluated: 0,
            insufficient_baseline: 24,
            no_data: 0,
            anomalies_total: 0,
            application_series: 'evaluated',
            daylight_saving: 'none',
          },
        }),
      ),
    );
    assert.match(text(), /Insufficient baseline/);
    assert.match(text(), /nothing is flagged/i);
    assert.equal(screen.queryAllByRole('article').length, 0);
    assert.doesNotMatch(text(), /No anomalies/);
  });

  it('a window with no data is not reported as calm', () => {
    show(
      okState(
        anomaliesFixture({
          anomalies: [],
          first_seen: [],
          evaluation: {
            status: 'no-data',
            series: 1,
            buckets: 24,
            evaluated: 0,
            insufficient_baseline: 0,
            no_data: 24,
            anomalies_total: 0,
            application_series: 'evaluated',
            daylight_saving: 'none',
          },
        }),
      ),
    );
    assert.match(text(), /No flow data was available/);
    assert.doesNotMatch(text(), /No anomalies/);
  });

  it('a fully evaluated window with no deviation says nothing deviated', () => {
    show(
      okState(
        anomaliesFixture({
          anomalies: [],
          evaluation: { ...anomaliesFixture().evaluation, anomalies_total: 0 },
        }),
      ),
    );
    assert.match(text(), /No hour deviated from its baseline/);
  });

  it('a partly evaluated window says how much was judged', () => {
    show(
      okState(
        anomaliesFixture({
          evaluation: {
            status: 'partial',
            series: 6,
            buckets: 100,
            evaluated: 80,
            insufficient_baseline: 15,
            no_data: 5,
            anomalies_total: 1,
            application_series: 'evaluated',
            daylight_saving: 'none',
          },
        }),
      ),
    );
    assert.match(text(), /15 of 100 hourly checks/);
  });

  it('says when applications were not reported by the source', () => {
    show(
      okState(
        anomaliesFixture({
          evaluation: { ...anomaliesFixture().evaluation, application_series: 'not-reported' },
        }),
      ),
    );
    assert.match(text(), /Application series were not evaluated/);
  });
});

describe('an anomaly is evidence, not a verdict', () => {
  function card() {
    return screen.getAllByRole('article')[0];
  }

  it('shows the baseline, the observed value, the difference, the ratio and the confidence', () => {
    show(okState(anomaliesFixture()));
    const body = card().textContent ?? '';
    assert.match(body, /Total traffic/);
    assert.match(body, /Observed/);
    assert.match(body, /9 GB/);
    assert.match(body, /Baseline/);
    assert.match(body, /1 GB/);
    assert.match(body, /median of 4 weeks/);
    assert.match(body, /\+8 GB/);
    assert.match(body, /9×/);
    assert.match(body, /High confidence/);
    assert.match(body, /2026-10-11 02:00:00 UTC/);
  });

  it('never calls anything malicious and says outright that it is not a finding', () => {
    show(okState(anomaliesFixture()));
    assert.doesNotMatch(text(), /malicious|attack|breach|compromis|threat/i);
    assert.match(text(), /evidence, not a verdict|not automatically malicious/i);
  });

  it('outside working hours is context and lists common legitimate causes', () => {
    show(okState(anomaliesFixture()));
    const body = card().textContent ?? '';
    assert.match(body, /Outside configured working hours \(context only, not a finding\)/);
    assert.match(body, /Common legitimate causes/);
    assert.match(body, /Backups/);
    assert.match(body, /Patching and software updates/);
  });

  it('without configured working hours the context is unknown and no cause list appears', () => {
    show(
      okState(
        anomaliesFixture({
          working_hours: { state: 'not-configured', timezone: null },
          anomalies: [anomalyFixture({ context: { outside_working_hours: null, common_legitimate_patterns: [] } })],
        }),
      ),
    );
    assert.match(card().textContent ?? '', /Working hours not configured/);
    assert.doesNotMatch(card().textContent ?? '', /Common legitimate causes/);
    assert.match(text(), /after-hours context is unavailable/);
  });

  it('a drop is worded as below the baseline', () => {
    show(
      okState(
        anomaliesFixture({
          anomalies: [
            anomalyFixture({
              direction: 'below',
              observed: 100_000_000,
              difference: -900_000_000,
              ratio: 0.1,
              score: -6,
              confidence: 'medium',
              context: { outside_working_hours: false, common_legitimate_patterns: [] },
            }),
          ],
        }),
      ),
    );
    assert.match(card().textContent ?? '', /−900 MB/);
    assert.match(card().textContent ?? '', /Medium confidence/);
    assert.match(card().textContent ?? '', /Within working hours/);
    assert.match(card().textContent ?? '', /may also be flow loss/i);
  });

  it('a zero baseline has no ratio and says so', () => {
    show(okState(anomaliesFixture({ anomalies: [anomalyFixture({ baseline: 0, ratio: null, difference: 9_000_000_000 })] })));
    assert.match(card().textContent ?? '', /No baseline traffic/);
  });

  it('an application subject is named, as text', () => {
    show(
      okState(
        anomaliesFixture({
          anomalies: [anomalyFixture({ subject: { kind: 'application', label: HOSTILE } })],
        }),
      ),
    );
    assert.equal(document.querySelectorAll('img, script, iframe').length, 0);
    assert.ok((card().textContent ?? '').includes(HOSTILE));
  });

  it('says how many were found when more than are listed', () => {
    show(okState(anomaliesFixture({ evaluation: { ...anomaliesFixture().evaluation, anomalies_total: 120 } })));
    assert.match(text(), /1 of 120 anomalies listed/);
  });
});

describe('first-seen context', () => {
  it('lists first-seen destinations and ASNs as context with working-hours context', () => {
    show(
      okState(
        anomaliesFixture({
          first_seen: [
            firstSeenFixture(),
            firstSeenFixture({ kind: 'first-seen-asn', asn: 64501, address: null, domain: null, bytes: 7 }),
          ],
        }),
      ),
    );
    const table = screen.getByRole('table', { name: /first seen/i });
    const rows = within(table).getAllByRole('row');
    assert.match(rows[1].textContent ?? '', /198\.51\.100\.7/);
    assert.match(rows[1].textContent ?? '', /First-seen destination/);
    assert.match(rows[2].textContent ?? '', /AS64501/);
    assert.match(rows[2].textContent ?? '', /First-seen ASN/);
    assert.match(text(), /not a finding/);
  });

  it('without enough history no first-seen flag is raised and the page says why', () => {
    show(
      okState(
        anomaliesFixture({
          first_seen: [],
          first_seen_status: { state: 'insufficient', required_days: 7, oldest: '2026-10-09T00:00:00Z' },
        }),
      ),
    );
    assert.match(text(), /at least 7 days/);
    assert.equal(screen.queryAllByRole('table', { name: /first seen/i }).length, 0);
  });

  it('with enough history and nothing new it says so', () => {
    show(okState(anomaliesFixture({ first_seen: [] })));
    assert.match(text(), /Nothing new was first seen/);
  });

  it('hostile domains are only text', () => {
    show(okState(anomaliesFixture({ first_seen: [firstSeenFixture({ domain: HOSTILE })] })));
    assert.equal(document.querySelectorAll('img, script, iframe').length, 0);
    assert.ok(text().includes(HOSTILE));
  });
});
