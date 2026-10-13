import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen, within } from '@testing-library/react';

import { AnomaliesBody } from '@/components/anomalies-body';
import { ApplicationsBody } from '@/components/applications-body';
import { DestinationsBody } from '@/components/destinations-body';
import { FlowExplorerBody } from '@/components/flow-explorer-body';
import type {
  TrafficAnomaliesResponse,
  TrafficApplicationsResponse,
  TrafficDestinationsResponse,
  TrafficFlowsResponse,
} from '@/lib/api-contracts-traffic-explorer';
import {
  COHORT_SUFFICIENT,
  COHORT_TOO_FEW,
  aggregationsFixture,
  anomaliesFixture,
  applicationFixture,
  applicationsFixture,
  destinationFixture,
  destinationsFixture,
  flowsFixture,
  okState,
} from '@/test/traffic-fixtures';

afterEach(() => cleanup());

const NO_TREND = { state: 'unknown', previous_bytes: null, change_ratio: null } as const;
const WITHHELD_DESTINATION = {
  visibility: 'withheld',
  bytes: null,
  packets: null,
  share: null,
  endpoints: null,
  users: null,
  domain: null,
  asn: null,
  country: null,
  first_seen: null,
  last_seen: null,
} as const;
const WITHHELD_APPLICATION = {
  visibility: 'withheld',
  bytes: null,
  packets: null,
  share: null,
  endpoints: null,
  users: null,
  trend: NO_TREND,
} as const;
const text = () => document.body.textContent ?? '';

const RESTRICTED: Partial<TrafficFlowsResponse> = {
  flows_restricted: true,
  flows: [],
  attribution: { level: 'none', state: 'withheld', as_of: null },
};

function flows(over: Partial<TrafficFlowsResponse>) {
  return render(<FlowExplorerBody state={okState(flowsFixture({ ...RESTRICTED, ...over }))} filtered />);
}

describe('the Flow Explorer under the small-cohort rule', () => {
  it('too few sources withholds the aggregates and says so', () => {
    flows({ cohort: COHORT_TOO_FEW, aggregations: null });
    const notice = screen.getByRole('status', { name: /Too few sources/i }).textContent ?? '';
    assert.match(notice, /fewer than 5 internal endpoints/);
    assert.match(notice, /traffic:read-detail/);
    assert.equal(screen.queryAllByRole('table').length, 0);
    assert.doesNotMatch(text(), /No flows match/);
    assert.doesNotMatch(text(), /Top destinations/);
  });

  it('a sufficient cohort shows the aggregates and the size of the group behind them', () => {
    flows({ cohort: COHORT_SUFFICIENT, aggregations: aggregationsFixture() });
    assert.match(text(), /Top destinations/);
    assert.match(text(), /at least 5 internal endpoints/);
  });

  it('the detail tier sees no cohort notice', () => {
    render(<FlowExplorerBody state={okState(flowsFixture())} filtered={false} />);
    assert.doesNotMatch(text(), /internal endpoints; smaller groups|fewer than \d+ source/i);
  });

  it('an internal destination is labelled for the detail tier', () => {
    const aggregations = aggregationsFixture({
      destinations: [
        { address: '192.168.1.20', host: 'nas.corp.example', scope: 'internal', visibility: 'shown', bytes: 5, share: 0.1, endpoints: 11 },
        { address: '203.0.113.9', host: null, scope: 'external', visibility: 'shown', bytes: 9, share: 0.2, endpoints: 12 },
      ],
    });
    render(<FlowExplorerBody state={okState(flowsFixture({ aggregations }))} filtered={false} />);
    const panel = screen.getByRole('region', { name: /Top destinations/i });
    assert.match(panel.textContent ?? '', /192\.168\.1\.20/);
    assert.match(panel.textContent ?? '', /Inside the organisation/);
    assert.equal((panel.textContent ?? '').match(/Inside the organisation/g)?.length, 1);
  });
});

describe('Applications under the small-cohort rule', () => {
  function apps(over: Partial<TrafficApplicationsResponse>) {
    return render(<ApplicationsBody state={okState(applicationsFixture(over))} />);
  }

  it('a withheld endpoint count says why', () => {
    apps({
      cohort: COHORT_TOO_FEW,
      items: [
        applicationFixture({ rank: 1, endpoints: 25 }),
        applicationFixture({
          rank: 2,
          application: 'BitTorrent',
          endpoints: null,
          trend: { state: 'unknown', previous_bytes: null, change_ratio: null },
        }),
      ],
    });
    const rows = within(screen.getByRole('table')).getAllByRole('row');
    assert.match(rows[1]?.textContent ?? '', /25/);
    assert.match(rows[2]?.textContent ?? '', /Withheld \(fewer than 5\)/);
    assert.match(text(), /withheld because fewer than 5 internal endpoints/);
  });

  it('a sufficient cohort says the counts are complete', () => {
    apps({ cohort: COHORT_SUFFICIENT });
    assert.match(text(), /at least 5 internal endpoints/);
    assert.doesNotMatch(text(), /Withheld/);
  });

  it('the detail tier sees plain counts and no notice', () => {
    apps({ items: [applicationFixture({ endpoints: 1 })] });
    assert.doesNotMatch(text(), /Withheld|internal endpoints; smaller/);
  });
});

describe('Destinations under the small-cohort rule', () => {
  function destinations(over: Partial<TrafficDestinationsResponse>) {
    return render(<DestinationsBody state={okState(destinationsFixture(over))} />);
  }

  it('a destination a small group reached is named and every figure of it is withheld', () => {
    destinations({
      cohort: COHORT_TOO_FEW,
      items: [
        destinationFixture({ rank: 1, endpoints: 12 }),
        destinationFixture({ rank: 2, address: '198.51.100.7', ...WITHHELD_DESTINATION }),
      ],
    });
    const rows = within(screen.getByRole('table', { name: /destinations/i })).getAllByRole('row');
    assert.match(rows[2]?.textContent ?? '', /198\.51\.100\.7/);
    assert.match(rows[2]?.textContent ?? '', /Withheld \(fewer than 5 endpoints\)/);
    assert.doesNotMatch(rows[2]?.textContent ?? '', /AS\d|cdn\.example\.net|\bZA\b|\d+ ?(MB|GB)|%/);
    assert.match(text(), /withheld because fewer than 5 internal endpoints/);
  });

  it('an internal destination is labelled', () => {
    destinations({
      items: [
        destinationFixture({ rank: 1, address: '10.1.1.5', scope: 'internal' }),
        destinationFixture({ rank: 2, address: '203.0.113.9' }),
      ],
    });
    const rows = within(screen.getByRole('table', { name: /destinations/i })).getAllByRole('row');
    assert.match(rows[1]?.textContent ?? '', /Inside the organisation/);
    assert.doesNotMatch(rows[2]?.textContent ?? '', /Inside the organisation/);
  });

  it('the aggregate tier is told internal destinations are not listed', () => {
    destinations({ cohort: COHORT_SUFFICIENT });
    assert.match(text(), /not listed to your role|inside the organisation are not listed/i);
  });
});

describe('Anomalies: first seen and daylight saving', () => {
  function anomalies(over: Partial<TrafficAnomaliesResponse>) {
    return render(<AnomaliesBody state={okState(anomaliesFixture(over))} />);
  }

  it('says when first-seen rows were withheld for a small cohort', () => {
    anomalies({ cohort: COHORT_TOO_FEW, first_seen: [] });
    assert.match(text(), /withheld because fewer than 5 internal endpoints/);
    assert.doesNotMatch(text(), /Nothing new was first seen/);
  });

  it('a sufficient cohort needs no apology', () => {
    anomalies({ cohort: COHORT_SUFFICIENT });
    assert.doesNotMatch(text(), /Withheld|withheld/);
  });

  it('flags a daylight-saving change in the baseline weeks', () => {
    const base = anomaliesFixture();
    anomalies({ evaluation: { ...base.evaluation, daylight_saving: 'crossed' } });
    const notice = screen.getByRole('note', { name: /daylight saving/i }).textContent ?? '';
    assert.match(notice, /daylight-saving change in Africa\/Johannesburg/);
    assert.match(notice, /168-hour UTC weeks/);
  });

  it('says nothing when no clock change is involved', () => {
    anomalies({});
    assert.equal(screen.queryAllByRole('note', { name: /daylight saving/i }).length, 0);
  });
});

describe('Applications and the Explorer under per-row withholding', () => {
  it('a small application is named, its volume and trend are withheld and it is listed last', () => {
    render(
      <ApplicationsBody
        state={okState(
          applicationsFixture({
            cohort: COHORT_TOO_FEW,
            items: [
              applicationFixture({ rank: 1, application: 'Microsoft 365', endpoints: 25 }),
              applicationFixture({ rank: 2, application: 'BitTorrent', ...WITHHELD_APPLICATION }),
            ],
          }),
        )}
      />,
    );
    const rows = within(screen.getByRole('table', { name: /applications/i })).getAllByRole('row');
    assert.match(rows[1]?.textContent ?? '', /Microsoft 365/);
    assert.match(rows[2]?.textContent ?? '', /BitTorrent/);
    assert.match(rows[2]?.textContent ?? '', /Withheld \(fewer than 5 endpoints\)/);
    assert.doesNotMatch(rows[2]?.textContent ?? '', /\d+ ?(MB|GB)|%|Up|Down|Flat|New/);
  });

  it('a withheld mix item and destination share show the word, no figure and no bar', () => {
    const aggregations = aggregationsFixture({
      application_mix: {
        items: [
          { application: 'https', visibility: 'shown', bytes: 300_000_000, share: 0.25, endpoints: 12 },
          { application: 'BitTorrent', visibility: 'withheld', bytes: null, share: null, endpoints: null },
        ],
        other_bytes: 900_000_000,
        total_bytes: 1_200_000_000,
      },
      destinations: [
        { address: '203.0.113.9', host: 'cdn.example.net', scope: 'external', visibility: 'shown', bytes: 600_000_000, share: 0.5, endpoints: 14 },
        { address: '198.51.100.7', host: null, scope: 'external', visibility: 'withheld', bytes: null, share: null, endpoints: null },
      ],
    });
    flows({ cohort: COHORT_TOO_FEW, aggregations });
    const mix = screen.getByRole('region', { name: /Application mix/i });
    const item = within(mix).getAllByRole('listitem')[1];
    assert.match(item.textContent ?? '', /BitTorrent/);
    assert.match(item.textContent ?? '', /Withheld/);
    assert.equal(item.querySelectorAll('.progress').length, 0);
    const shares = screen.getByRole('region', { name: /Top destinations/i });
    const share = within(shares).getAllByRole('listitem')[1];
    assert.match(share.textContent ?? '', /198\.51\.100\.7/);
    assert.match(share.textContent ?? '', /Withheld/);
    assert.equal(share.querySelectorAll('.progress').length, 0);
  });

  it('the Explorer volume reports the internal endpoint count next to the source addresses', () => {
    flows({ cohort: COHORT_SUFFICIENT, aggregations: aggregationsFixture() });
    assert.match(text(), /Internal endpoints/);
    assert.match(text(), /Source addresses/);
  });

  it('an unreported internal endpoint count is not shown as a number', () => {
    const base = aggregationsFixture();
    flows({
      cohort: COHORT_SUFFICIENT,
      aggregations: { ...base, volume: { ...base.volume, internal_endpoints: null } },
    });
    const dd = within(screen.getByRole('region', { name: /Volume/i })).getAllByRole('definition');
    assert.ok(dd.some((cell) => cell.textContent === 'Not reported'));
  });
});

describe('Anomalies under series withholding', () => {
  it('says how many series were left out and why', () => {
    const base = anomaliesFixture();
    render(
      <AnomaliesBody
        state={okState(
          anomaliesFixture({
            cohort: COHORT_TOO_FEW,
            evaluation: { ...base.evaluation, series_withheld: 2 },
          }),
        )}
      />,
    );
    const notice = screen.getByRole('status', { name: /Series withheld/i }).textContent ?? '';
    assert.match(notice, /2 series were left out/);
    assert.match(notice, /fewer than 5 internal endpoints/);
  });

  it('says nothing when no series was left out', () => {
    render(<AnomaliesBody state={okState(anomaliesFixture())} />);
    assert.equal(screen.queryAllByRole('status', { name: /Series withheld/i }).length, 0);
  });
});

