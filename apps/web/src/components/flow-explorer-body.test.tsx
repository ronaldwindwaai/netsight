import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen, within } from '@testing-library/react';

import { FlowExplorerBody } from '@/components/flow-explorer-body';
import type { TrafficFlowsResponse } from '@/lib/api-contracts-traffic-explorer';
import {
  HOSTILE,
  STALE,
  aggregationsFixture,
  attributionFixture,
  emptyFlows,
  failureState,
  flowFixture,
  flowsFixture,
  okState,
} from '@/test/traffic-fixtures';

afterEach(() => cleanup());

function show(
  state: ReturnType<typeof okState<TrafficFlowsResponse>> | ReturnType<typeof failureState<TrafficFlowsResponse>>,
  filtered = false,
) {
  return render(<FlowExplorerBody state={state} filtered={filtered} />);
}

const text = () => document.body.textContent ?? '';

describe('every outcome of the read has its own surface', () => {
  it('permission denied names the permission and shows no data', () => {
    show(failureState<TrafficFlowsResponse>('forbidden', 403));
    const status = screen.getByRole('status').textContent ?? '';
    assert.match(status, /not available to your role/);
    assert.match(status, /traffic:read/);
    assert.equal(screen.queryAllByRole('table').length, 0);
  });

  it('an unauthenticated session is asked to sign in', () => {
    show(failureState<TrafficFlowsResponse>('unauthenticated', 401));
    assert.ok(screen.getByRole('link', { name: /Sign in/ }));
  });

  it('an API error is an error, not an empty list', () => {
    show(failureState<TrafficFlowsResponse>('error', 500));
    assert.match(text(), /Unable to load data/);
    assert.equal(screen.queryAllByRole('table').length, 0);
  });

  it('a rate limit is reported as such', () => {
    show(failureState<TrafficFlowsResponse>('rate_limited', 429));
    assert.match(text(), /Too many requests/);
  });

  it('a busy flow source is a source problem, not an empty result', () => {
    show(failureState<TrafficFlowsResponse>('source_unavailable', 503));
    assert.match(text(), /source unavailable/i);
    assert.equal(screen.queryAllByRole('table').length, 0);
  });

  it('nothing configured is not-connected and never a count of zero', () => {
    show(okState(emptyFlows('not-connected')));
    const status = screen.getByRole('status').textContent ?? '';
    assert.match(status, /Flow source not connected/);
    assert.match(status, /not the same as having none/);
    assert.equal(screen.queryAllByRole('table').length, 0);
    assert.doesNotMatch(text(), /\b0 flows\b/);
  });

  it('a failing source is unknown and nothing is estimated', () => {
    show(okState(emptyFlows('unknown')));
    const status = screen.getByRole('status').textContent ?? '';
    assert.match(status, /state unknown/i);
    assert.match(status, /Nothing is estimated/);
  });

  it('a filter the source cannot honour is named and the read is not run unfiltered', () => {
    show(okState(emptyFlows('unknown', { unsupported: ['device', 'vlan'] })), true);
    const status = screen.getByRole('status').textContent ?? '';
    assert.match(status, /does not report/i);
    assert.match(status, /device/);
    assert.match(status, /vlan/);
    assert.match(status, /not run unfiltered/i);
  });

  it('an ok read with nothing is empty and says so', () => {
    show(okState(flowsFixture({ flows: [], attribution: { level: 'person', state: 'not-evaluated', as_of: null } })));
    const status = screen.getByRole('status').textContent ?? '';
    assert.match(status, /No flows in this window/);
    assert.equal(screen.queryAllByRole('table').filter((t) => t.querySelector('tbody tr')).length, 0);
  });

  it('an ok read with nothing under filters points at the filters', () => {
    show(okState(flowsFixture({ flows: [], attribution: { level: 'person', state: 'not-evaluated', as_of: null } })), true);
    assert.match(screen.getByRole('status').textContent ?? '', /No flows match these filters/);
  });

  it('stale data is labelled as last-known', () => {
    show(okState(flowsFixture({ freshness: { ...STALE } })));
    assert.match(text(), /Stale monitoring data/);
  });
});

describe('the rows', () => {
  it('a table has a caption, column headers and one row per flow', () => {
    show(okState(flowsFixture({ flows: [flowFixture(), flowFixture({ source_ip: '10.0.0.11' })] })));
    const table = screen.getByRole('table', { name: /flows/i });
    assert.equal(within(table).getAllByRole('columnheader').length >= 6, true);
    assert.equal(within(table).getAllByRole('row').length, 3);
  });

  it('shows source, destination, application, direction and volume exactly as reported', () => {
    show(okState(flowsFixture()));
    const row = within(screen.getByRole('table', { name: /flows/i })).getAllByRole('row')[1];
    const cells = row.textContent ?? '';
    assert.match(cells, /10\.0\.0\.10/);
    assert.match(cells, /203\.0\.113\.9/);
    assert.match(cells, /cdn\.example\.net/);
    assert.match(cells, /443/);
    assert.match(cells, /tcp/i);
    assert.match(cells, /https/);
    assert.match(cells, /Outbound/i);
    assert.match(cells, /988 MB/);
  });

  it('a value the source did not report is Not reported, never zero', () => {
    show(okState(flowsFixture({ flows: [flowFixture({ application: null, destination_host: null, destination_port: null, packets: null, attribution: null })], attribution: { level: 'none', state: 'withheld', as_of: null } })));
    const row = within(screen.getByRole('table', { name: /flows/i })).getAllByRole('row')[1].textContent ?? '';
    assert.match(row, /Not reported/);
    assert.match(row, /packets not reported/);
  });

  it('an observed person is shown with the word Observed and the confidence', () => {
    show(okState(flowsFixture()));
    const cell = within(screen.getByRole('table', { name: /flows/i })).getAllByRole('row')[1].textContent ?? '';
    assert.match(cell, /Alice Example/);
    assert.match(cell, /Observed/);
    assert.match(cell, /90%/);
    assert.match(cell, /PC-001/);
  });

  it('a named person links to their profile, and nobody else does', () => {
    show(okState(flowsFixture({ flows: [flowFixture(), flowFixture({ attribution: attributionFixture({ basis: 'unknown', reason: 'no-evidence', confidence: null, person: null }) })] })));
    const rows = within(screen.getByRole('table', { name: /flows/i })).getAllByRole('row');
    const link = within(rows[1]).getByRole('link', { name: /Alice Example/ });
    assert.equal(link.getAttribute('href'), '/users/person-3f1c2a9e-1b2c-4d3e-8f4a-5b6c7d8e9f01');
    assert.equal(within(rows[2]).queryAllByRole('link').length, 0);
  });

  it('an inferred person is possibly that person, never stated as fact', () => {
    const attribution = attributionFixture({ basis: 'inferred', reason: 'declared-assignment', confidence: 0.6 });
    show(okState(flowsFixture({ flows: [flowFixture({ attribution })] })));
    const cell = within(screen.getByRole('table', { name: /flows/i })).getAllByRole('row')[1].textContent ?? '';
    assert.match(cell, /Possibly Alice Example/);
    assert.match(cell, /Inferred/);
    assert.match(cell, /asset-register/);
  });

  it('an unknown answer names nobody and says why', () => {
    const attribution = attributionFixture({ basis: 'unknown', reason: 'shared-address', confidence: null, person: null, ambiguous: true });
    show(okState(flowsFixture({ flows: [flowFixture({ attribution })] })));
    const cell = within(screen.getByRole('table', { name: /flows/i })).getAllByRole('row')[1].textContent ?? '';
    assert.match(cell, /Not identified/);
    assert.match(cell, /Unknown/);
    assert.match(cell, /NAT or shared/);
    assert.doesNotMatch(cell, /Alice/);
  });

  it('the endpoint level shows the device and withholds the person', () => {
    const attribution = attributionFixture({ basis: 'unknown', reason: 'restricted', confidence: null, person: null });
    show(okState(flowsFixture({ attribution: { level: 'endpoint', state: 'ok', as_of: '2026-10-11T12:00:00Z' }, flows: [flowFixture({ attribution })] })));
    const cell = within(screen.getByRole('table', { name: /flows/i })).getAllByRole('row')[1].textContent ?? '';
    assert.match(cell, /Withheld for your role/);
    assert.match(cell, /PC-001/);
    assert.match(text(), /not the person/);
  });

  it('a role with no users permission is told attribution is not available to it', () => {
    show(okState(flowsFixture({ attribution: { level: 'none', state: 'withheld', as_of: null }, flows: [flowFixture({ attribution: null })] })));
    const cell = within(screen.getByRole('table', { name: /flows/i })).getAllByRole('row')[1].textContent ?? '';
    assert.match(cell, /Not available to your role/);
    assert.doesNotMatch(cell, /Alice/);
    assert.match(text(), /rows show endpoints only/);
  });

  it('an unconnected identity service is named and no flow is attributed', () => {
    show(okState(flowsFixture({ attribution: { level: 'person', state: 'not-connected', as_of: null }, flows: [flowFixture({ attribution: null })] })));
    assert.match(text(), /No identity source is connected/);
    assert.match(text(), /Identity service not connected/);
  });

  it('a failing identity service is unknown, not a guess', () => {
    show(okState(flowsFixture({ attribution: { level: 'person', state: 'unknown', as_of: null }, flows: [flowFixture({ attribution: null })] })));
    assert.match(text(), /identity service could not be read/);
  });

  it('hostile source text is rendered as text and nothing is interpreted', () => {
    const flow = flowFixture({
      destination_host: HOSTILE,
      application: HOSTILE,
      attribution: attributionFixture({ person: { id: attributionFixture().person?.id ?? '', label: HOSTILE } }),
    });
    const aggregations = aggregationsFixture({
      destinations: [{ address: '203.0.113.9', host: HOSTILE, scope: 'external', bytes: 5, share: null }],
    });
    show(okState(flowsFixture({ flows: [flow], aggregations })));
    assert.equal(document.querySelectorAll('img, script, iframe').length, 0);
    assert.ok(text().includes(HOSTILE));
  });
});

describe('role-restricted rows', () => {
  it('a role without row access sees the aggregates and a plain explanation', () => {
    show(okState(flowsFixture({ flows_restricted: true, flows: [], attribution: { level: 'none', state: 'withheld', as_of: null } })));
    assert.match(text(), /traffic:read-detail/);
    assert.match(text(), /aggregates only/i);
    assert.equal(screen.queryAllByRole('table', { name: /flows/i }).length, 0);
    assert.ok(screen.getByRole('region', { name: /Traffic over time/i }));
    assert.ok(screen.getByRole('region', { name: /Volume/i }));
  });
});

describe('the aggregations', () => {
  it('shows the volume with counts the source reported', () => {
    show(okState(flowsFixture()));
    const volume = screen.getByRole('region', { name: /Volume/i }).textContent ?? '';
    assert.match(volume, /1\.2 GB/);
    assert.match(volume, /300/);
    assert.match(volume, /14/);
    assert.match(volume, /80/);
    assert.match(volume, /Not reported/); // packets
  });

  it('shows the timeline as a labelled list with the bucket width', () => {
    show(okState(flowsFixture()));
    const timeline = screen.getByRole('region', { name: /Traffic over time/i });
    assert.match(timeline.textContent ?? '', /1 hour/);
    assert.equal(within(timeline).getAllByRole('listitem').length, 2);
  });

  it('shows the application mix with the unattributed remainder named', () => {
    show(okState(flowsFixture()));
    const mix = screen.getByRole('region', { name: /Application mix/i }).textContent ?? '';
    assert.match(mix, /https/);
    assert.match(mix, /No application reported/);
    assert.match(mix, /Other applications/);
    assert.match(mix, /whole filtered window/);
  });

  it('says plainly when the source does not report applications', () => {
    show(okState(flowsFixture({ aggregations: aggregationsFixture({ application_mix: null }) })));
    assert.match(screen.getByRole('region', { name: /Application mix/i }).textContent ?? '', /not reported by the flow source/i);
  });

  it('shows the top destinations', () => {
    show(okState(flowsFixture()));
    const destinations = screen.getByRole('region', { name: /Top destinations/i }).textContent ?? '';
    assert.match(destinations, /203\.0\.113\.9/);
    assert.match(destinations, /cdn\.example\.net/);
    assert.match(destinations, /198\.51\.100\.7/);
  });

  it('an empty window still reports honest zero totals as source-reported', () => {
    show(okState(flowsFixture({ flows: [], attribution: { level: 'person', state: 'not-evaluated', as_of: null }, aggregations: aggregationsFixture({ timeline: [], destinations: [], application_mix: null, volume: { bytes: 0, packets: null, flows: 0, source_addresses: 0, destination_addresses: 0 } }) })));
    assert.match(text(), /No traffic in the timeline/);
  });
});
