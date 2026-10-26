import assert from 'node:assert/strict';
import test from 'node:test';

import type { TopologyResponse } from './api-contracts.ts';
import type { FetchState } from './api-response.ts';
import { overviewTopology } from './overview-topology.ts';

const FRESHNESS = { state: 'unknown', observed_at: null, source: null } as TopologyResponse['freshness'];

function ok(partial: Partial<TopologyResponse>): FetchState<TopologyResponse> {
  const data: TopologyResponse = { state: 'ok', nodes: [], edges: [], freshness: FRESHNESS, ...partial };
  return { kind: 'ok', data, correlationId: 'c1' };
}

const NODE = {
  device_id: 'netbox:11',
  name: 'core-sw-01',
  reconciled: true,
  finding: null,
} as unknown as TopologyResponse['nodes'][number];

test('an ok topology with nodes is drawn', () => {
  const result = overviewTopology(ok({ nodes: [NODE] }));
  assert.equal(result.kind, 'graph');
});

test('not-connected, unknown and empty each keep their own wording and draw nothing', () => {
  const titles = [
    overviewTopology(ok({ state: 'not-connected' })),
    overviewTopology(ok({ state: 'unknown' })),
    overviewTopology(ok({ state: 'ok', nodes: [] })),
  ].map((result) => (result.kind === 'surface' ? result.title : 'graph'));
  assert.deepEqual(titles, [
    'Topology is not yet connected',
    'Topology is unknown',
    'No explicit links reported',
  ]);
});

test('a failed request is never shown as an empty or connected map', () => {
  const failed: FetchState<TopologyResponse> = {
    kind: 'source_unavailable',
    code: 'SOURCE_UNAVAILABLE',
    message: 'down',
    correlationId: 'c2',
    status: 503,
  };
  const result = overviewTopology(failed);
  assert.equal(result.kind, 'surface');
  assert.equal(result.kind === 'surface' && result.title, 'Topology could not be read');
});
