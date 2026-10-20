import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { relatedLinks } from './device-links.ts';
import type { Device } from './api-contracts.ts';

const BASE: Device = {
  id: 'device-6f1c2a9e-0b1d-5c3e-8f4a-123456789abc',
  name: 'core & edge',
  hostname: null,
  type: 'switch',
  status: 'healthy',
  ip_addresses: [],
  mac_addresses: [],
  site_id: null,
  owner_identity_id: null,
  source_aliases: [],
  freshness: { state: 'fresh', observed_at: null, source: null },
};

describe('relatedLinks', () => {
  it('omits the flow link when no address is recorded', () => {
    assert.equal(relatedLinks(BASE).some((l) => l.id === 'flows'), false);
  });

  it('filters flows by the primary address', () => {
    const flows = relatedLinks({ ...BASE, ip_addresses: ['10.0.0.1', '10.0.0.2'] }).find((l) => l.id === 'flows');
    assert.equal(flows?.href, '/traffic/flows?source_ip=10.0.0.1');
  });

  it('encodes names and focus ids in query strings', () => {
    const links = relatedLinks(BASE);
    assert.equal(links.find((l) => l.id === 'inventory')?.href, '/inventory?q=core+%26+edge');
    assert.match(links.find((l) => l.id === 'map')?.href ?? '', /focus=device-6f1c/);
  });

  it('says unfiltered destinations are not filtered to the device', () => {
    for (const id of ['alerts', 'incidents', 'config']) {
      assert.match(relatedLinks(BASE).find((l) => l.id === id)?.scope ?? '', /not (filtered|linked)/);
    }
  });
});
