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
    assert.match(notice, /fewer than 5 source addresses/);
    assert.match(notice, /traffic:read-detail/);
    assert.equal(screen.queryAllByRole('table').length, 0);
    assert.doesNotMatch(text(), /No flows match/);
    assert.doesNotMatch(text(), /Top destinations/);
  });

  it('a sufficient cohort shows the aggregates and the size of the group behind them', () => {
    flows({ cohort: COHORT_SUFFICIENT, aggregations: aggregationsFixture() });
    assert.match(text(), /Top destinations/);
    assert.match(text(), /at least 5 source addresses/);
  });

  it('the detail tier sees no cohort notice', () => {
    render(<FlowExplorerBody state={okState(flowsFixture())} filtered={false} />);
    assert.doesNotMatch(text(), /source addresses; smaller groups|fewer than \d+ source/i);
  });

  it('an internal destination is labelled for the detail tier', () => {
    const aggregations = aggregationsFixture({
      destinations: [
        { address: '192.168.1.20', host: 'nas.corp.example', scope: 'internal', bytes: 5, share: 0.1 },
        { address: '203.0.113.9', host: null, scope: 'external', bytes: 9, share: 0.2 },
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
    assert.match(text(), /withheld because fewer than 5 source addresses/);
  });

  it('a sufficient cohort says the counts are complete', () => {
    apps({ cohort: COHORT_SUFFICIENT });
    assert.match(text(), /at least 5 source addresses/);
    assert.doesNotMatch(text(), /Withheld/);
  });

  it('the detail tier sees plain counts and no notice', () => {
    apps({ items: [applicationFixture({ endpoints: 1 })] });
    assert.doesNotMatch(text(), /Withheld|source addresses; smaller/);
  });
});

describe('Destinations under the small-cohort rule', () => {
  function destinations(over: Partial<TrafficDestinationsResponse>) {
    return render(<DestinationsBody state={okState(destinationsFixture(over))} />);
  }

  it('a withheld endpoint count says why', () => {
    destinations({
      cohort: COHORT_TOO_FEW,
      items: [destinationFixture({ rank: 1, endpoints: 12 }), destinationFixture({ rank: 2, address: '198.51.100.7', endpoints: null })],
    });
    const rows = within(screen.getByRole('table', { name: /destinations/i })).getAllByRole('row');
    assert.match(rows[2]?.textContent ?? '', /Withheld \(fewer than 5\)/);
    assert.match(text(), /withheld because fewer than 5 source addresses/);
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
    assert.match(text(), /withheld because fewer than 5 source addresses/);
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
