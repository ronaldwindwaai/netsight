import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen, within } from '@testing-library/react';

import { ForecastBody } from '@/components/forecast-body';
import type { ForecastResponse } from '@/lib/api-contracts-forecast';
import type { FetchState } from '@/lib/api-response';
import { parseForecastQuery } from '@/lib/forecast-view';
import { GB, RECOMMENDATION, day, offSeries, okSeries, response } from '@/test/forecast-fixtures';

afterEach(() => cleanup());

const HOSTILE = '<script>alert(1)</script>';
const QUERY = parseForecastQuery({ horizon_days: '7', history_days: '28' });
const ok = (data: ForecastResponse): FetchState<ForecastResponse> => ({
  kind: 'ok',
  data,
  correlationId: 'c',
});
const fail = (kind: string, status: number): FetchState<ForecastResponse> =>
  ({ kind, code: kind.toUpperCase(), message: 'x', correlationId: 'c', status }) as FetchState<ForecastResponse>;

function body(state: FetchState<ForecastResponse>, canExport = true) {
  return render(<ForecastBody state={state} query={QUERY} canExport={canExport} />);
}

const charts = () => document.querySelectorAll('svg[role="img"]').length;

describe('the page has a surface for every outcome', () => {
  it('permission denied names the permission and shows no chart', () => {
    body(fail('forbidden', 403));
    assert.match(screen.getByRole('status').textContent ?? '', /forecast:read/);
    assert.equal(charts(), 0);
  });

  it('an unauthenticated session is sent to sign in', () => {
    body(fail('unauthenticated', 401));
    assert.match(document.body.textContent ?? '', /sign-in required/i);
  });

  it('an API error is an error, not an empty forecast', () => {
    body(fail('error', 500));
    assert.match(document.body.textContent ?? '', /Unable to load data/);
    assert.equal(charts(), 0);
  });

  it('nothing connected says no forecast can be made and that this is not the same as no traffic', () => {
    const none = response({
      state: 'not-connected',
      series: [
        offSeries('traffic-volume', { reason: 'no-source', detail: 'No flow source is configured.' }),
        offSeries('wan-utilisation'),
        offSeries('inventory-growth'),
      ],
    });
    body(ok(none));
    const text = document.body.textContent ?? '';
    assert.match(text, /No forecast can be made/);
    assert.match(text, /not the same as having no traffic/);
    assert.equal(charts(), 0);
  });

  it('an unreadable source is unknown and nothing is estimated', () => {
    const unknown = response({
      state: 'unknown',
      series: [
        okSeries({
          state: 'unknown',
          reason: 'source-unreadable',
          detail: 'The flow source is configured but could not be read.',
          history: [],
          method: null,
          forecast: [],
          source_observed_at: null,
        }),
        offSeries(),
        offSeries('inventory-growth'),
      ],
      recommendations: [],
    });
    body(ok(unknown));
    const text = document.body.textContent ?? '';
    assert.match(text, /could not be read/);
    assert.match(text, /Unknown/);
    assert.equal(charts(), 0);
  });

  it('too little history shows the measured days and projects nothing', () => {
    const few = okSeries({
      state: 'insufficient-data',
      reason: 'too-few-days',
      detail: '9 observed days; at least 14 are needed before a forecast is made.',
      method: null,
      forecast: [],
      history: okSeries().history.slice(0, 9),
    });
    body(
      ok(
        response({
          state: 'insufficient-data',
          series: [few, offSeries(), offSeries('inventory-growth')],
        }),
      ),
    );
    const text = document.body.textContent ?? '';
    assert.match(text, /Not enough history/);
    assert.match(text, /9 observed days/);
    assert.equal(charts(), 1); // the measured days are real and are drawn
    assert.equal(document.querySelectorAll('[data-forecast-line]').length, 0);
    assert.equal(document.querySelectorAll('[data-forecast-band]').length, 0);
    assert.equal(document.querySelectorAll('tr[data-kind="forecast"]').length, 0);
  });
});

describe('a forecast is labelled and accessible', () => {
  it('says forecast, not measurement, in words, before any figure', () => {
    body(ok(response()));
    const note = screen.getByRole('note');
    assert.match(note.textContent ?? '', /Forecast, not measurement/);
    const first = document.body.querySelector('[role="note"], svg');
    assert.equal(first, note);
  });

  it('the chart has a name and a description that separate measured from forecast', () => {
    body(ok(response()));
    const chart = document.querySelector('svg[role="img"]') as SVGElement;
    const name = document.getElementById(chart.getAttribute('aria-labelledby') ?? '')?.textContent ?? '';
    const description =
      document.getElementById(chart.getAttribute('aria-describedby') ?? '')?.textContent ?? '';
    assert.match(name, /Network traffic volume/);
    assert.match(description, /Measured: 14 days/);
    assert.match(description, /Forecast, not measured: 7 days/);
    assert.match(description, /approximate 95 %/);
  });

  it('forecast is drawn differently from measurement (dashed line, hatched band) and listed in a key', () => {
    body(ok(response()));
    const line = document.querySelector('[data-forecast-line]') as SVGElement;
    assert.ok(line.getAttribute('stroke-dasharray'));
    const band = document.querySelector('[data-forecast-band]') as SVGElement;
    assert.match(band.getAttribute('fill') ?? '', /url\(#/);
    const key = screen.getByRole('list', { name: /chart key/i });
    assert.match(key.textContent ?? '', /Measured/);
    assert.match(key.textContent ?? '', /Forecast/);
  });

  it('a data table labels every row measured or forecast, with the band for forecasts', () => {
    body(ok(response()));
    const rows = Array.from(document.querySelectorAll('table tbody tr'));
    assert.equal(rows.length, 14 + 7);
    const forecasts = rows.filter((r) => r.getAttribute('data-kind') === 'forecast');
    assert.equal(forecasts.length, 7);
    assert.match(forecasts[0].textContent ?? '', /Forecast/);
    assert.match(forecasts[0].textContent ?? '', /GB\/day to .* GB\/day/);
    assert.ok(within(rows[0] as HTMLElement).getByText('Measured'));
  });

  it('shows how the numbers were made, in words', () => {
    body(ok(response()));
    const text = document.body.textContent ?? '';
    assert.match(text, /Linear trend/);
    assert.match(text, /straight-line trend fitted to 14 observed days/);
    assert.match(text, /not a model/i);
  });

  it('a configured limit and its crossing day are stated', () => {
    const limited = okSeries({
      threshold: { value: 116 * GB, basis: 'operator-configured' },
      crossing: { point_day: day(16), upper_day: day(14) },
    });
    body(ok(response({ series: [limited, offSeries(), offSeries('inventory-growth')] })));
    const text = document.body.textContent ?? '';
    assert.match(text, /limit you configured/i);
    assert.match(text, new RegExp(day(16)));
  });

  it('a limit that is not reached says so', () => {
    const limited = okSeries({
      threshold: { value: 900 * GB, basis: 'operator-configured' },
      crossing: { point_day: null, upper_day: null },
    });
    body(ok(response({ series: [limited, offSeries(), offSeries('inventory-growth')] })));
    assert.match(document.body.textContent ?? '', /not reached within the forecast/i);
  });

  it('every state badge is a word and an icon, never colour alone', () => {
    body(ok(response()));
    const badges = Array.from(document.querySelectorAll('[data-state-badge]'));
    assert.ok(badges.length >= 3);
    for (const badge of badges) {
      assert.ok((badge.textContent ?? '').trim().length > 3);
      assert.ok(badge.querySelector('i[aria-hidden="true"]'));
    }
  });
});

describe('recommendations are advice, never an action', () => {
  it('are labelled advisory with their evidence and offer no control', () => {
    body(ok(response()));
    const section = screen.getByRole('region', { name: /Recommendations/i });
    assert.match(section.textContent ?? '', /Advisory/);
    assert.match(section.textContent ?? '', /Netsight does not act on these/);
    assert.match(section.textContent ?? '', /No source in this deployment reports/);
    assert.equal(section.querySelectorAll('button, form, input, a[href*="actions"]').length, 0);
  });

  it('say so when there are none, without claiming everything is fine', () => {
    body(ok(response({ recommendations: [] })));
    const section = screen.getByRole('region', { name: /Recommendations/i });
    assert.match(section.textContent ?? '', /No recommendations/);
    assert.match(section.textContent ?? '', /not a statement that capacity is fine/i);
  });

  it('untrusted text is rendered as text', () => {
    const hostile = response({
      recommendations: [{ ...RECOMMENDATION, title: HOSTILE, evidence: [HOSTILE] }],
      series: [okSeries({ name: HOSTILE }), offSeries(), offSeries('inventory-growth')],
    });
    body(ok(hostile));
    assert.ok(screen.getAllByText(HOSTILE).length >= 2);
    assert.equal(document.querySelector('script'), null);
  });
});

describe('the report link and the window controls', () => {
  it('offers the CSV report to a viewer who can export, to the web route with the validated window', () => {
    body(ok(response()));
    const link = screen.getByRole('link', { name: /Download capacity report/i });
    assert.equal(link.getAttribute('href'), '/forecast/export?horizon_days=7&history_days=28');
    assert.match(document.body.textContent ?? '', /CSV/);
  });

  it('does not offer it otherwise', () => {
    body(ok(response()), false);
    assert.equal(screen.queryAllByRole('link', { name: /Download capacity report/i }).length, 0);
  });

  it('the window form is a plain GET with the offered options', () => {
    body(ok(response()));
    const form = document.querySelector('form[method="get"]') as HTMLFormElement;
    assert.equal(form.getAttribute('action'), '/forecast');
    const horizon = form.querySelector('select[name="horizon_days"]') as HTMLSelectElement;
    assert.deepEqual(
      Array.from(horizon.options).map((o) => o.value),
      ['7', '14', '30'],
    );
    assert.equal(horizon.value, '7');
  });
});
