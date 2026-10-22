import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { matchNodes, neighboursOf, reconciliationText, resolveFocus } from './topology-view.ts';
import type { TopologyResponse } from './api-contracts.ts';

const A = 'device-6f1c2a9e-0b1d-5c3e-8f4a-123456789aaa';
const B = 'device-6f1c2a9e-0b1d-5c3e-8f4a-123456789bbb';
const C = 'device-6f1c2a9e-0b1d-5c3e-8f4a-123456789ccc';

const TOPOLOGY: TopologyResponse = {
  state: 'ok',
  freshness: { state: 'fresh', observed_at: null, source: null },
  nodes: [
    { device_id: A, name: 'Core-1', reconciled: true, finding: null },
    { device_id: B, name: null, reconciled: false, finding: null },
    {
      device_id: C,
      name: 'Edge',
      reconciled: true,
      finding: { kind: 'missing-discovered', detail: 'x' },
    },
  ],
  edges: [
    { source_device_id: A, target_device_id: B, source: 'lldp', observed_at: null },
    { source_device_id: C, target_device_id: A, source: 'netbox', observed_at: '2026-10-11T12:00:00Z' },
  ],
} as TopologyResponse;

describe('topology view helpers', () => {
  it('lists neighbours from either end of a link', () => {
    const result = neighboursOf(TOPOLOGY, A);
    assert.deepEqual(result.map((n) => [n.name, n.source]), [[B, 'lldp'], ['Edge', 'netbox']]);
    assert.deepEqual(neighboursOf(TOPOLOGY, B).map((n) => n.name), ['Core-1']);
  });

  it('matches by name or id and treats an empty query as no search', () => {
    assert.deepEqual(matchNodes(TOPOLOGY.nodes, 'core').map((n) => n.device_id), [A]);
    assert.deepEqual(matchNodes(TOPOLOGY.nodes, '789bbb').map((n) => n.device_id), [B]);
    assert.deepEqual(matchNodes(TOPOLOGY.nodes, '  '), []);
  });

  it('honours a focus only when it is a node of the graph', () => {
    assert.equal(resolveFocus(A, TOPOLOGY), A);
    assert.equal(resolveFocus(['bad', A], TOPOLOGY), null);
    assert.equal(resolveFocus('device-6f1c2a9e-0b1d-5c3e-8f4a-123456789ddd', TOPOLOGY), null);
    assert.equal(resolveFocus(undefined, TOPOLOGY), null);
  });

  it('ignores a focus that is not a device id, such as an inventory-only asset id', () => {
    assert.equal(resolveFocus('asset-6f1c2a9e-0b1d-5c3e-8f4a-123456789aaa', TOPOLOGY), null);
    assert.equal(resolveFocus('', TOPOLOGY), null);
  });

  it('never calls an unchecked node clean', () => {
    assert.match(reconciliationText(TOPOLOGY.nodes[1]), /Not checked/);
    assert.match(reconciliationText(TOPOLOGY.nodes[0]), /no findings/);
    assert.match(reconciliationText(TOPOLOGY.nodes[2]), /not discovered/);
  });
});
