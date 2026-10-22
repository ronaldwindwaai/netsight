import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { LINK_PERMISSIONS, assetLinks, endpointLinks, relatedLinks } from './device-links.ts';
import type { Device } from './api-contracts.ts';
import { menuItemsFor } from './menu.ts';

const ALL = Object.values(LINK_PERMISSIONS);

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

const ids = (links: { id: string }[]) => links.map((l) => l.id);

describe('relatedLinks', () => {
  it('omits the flow link when no address is recorded', () => {
    assert.equal(ids(relatedLinks(BASE, ALL)).includes('flows'), false);
  });

  it('filters flows by the primary address', () => {
    const flows = relatedLinks({ ...BASE, ip_addresses: ['10.0.0.1', '10.0.0.2'] }, ALL).find((l) => l.id === 'flows');
    assert.equal(flows?.href, '/traffic/flows?source_ip=10.0.0.1');
  });

  it('encodes names and focus ids in query strings', () => {
    const links = relatedLinks(BASE, ALL);
    assert.equal(links.find((l) => l.id === 'inventory')?.href, '/inventory?q=core+%26+edge');
    assert.match(links.find((l) => l.id === 'map')?.href ?? '', /focus=device-6f1c/);
  });

  it('says unfiltered destinations are not filtered to the device', () => {
    for (const id of ['alerts', 'incidents', 'config']) {
      assert.match(relatedLinks(BASE, ALL).find((l) => l.id === id)?.scope ?? '', /not (filtered|linked)/);
    }
  });
});

describe('permission gating', () => {
  const withIp = { ...BASE, ip_addresses: ['10.0.0.1'] };

  it('hides every gated link from a role holding none of the permissions', () => {
    assert.deepEqual(ids(relatedLinks(withIp, [])), ['map', 'alerts', 'incidents']);
    assert.deepEqual(ids(relatedLinks(withIp, null)), ['map', 'alerts', 'incidents']);
  });

  it('shows only the links whose permission is held', () => {
    assert.deepEqual(ids(relatedLinks(withIp, ['traffic:read'])), ['map', 'flows', 'alerts', 'incidents']);
  });

  it('gates endpoint and asset links the same way', () => {
    const endpoint = { ip: '10.0.0.9', mac: null, hostname: null };
    assert.deepEqual(ids(endpointLinks(endpoint, [])), ['map']);
    assert.deepEqual(ids(endpointLinks(endpoint, ALL)), ['inventory', 'flows', 'map', 'ipam']);
    assert.deepEqual(ids(assetLinks({ id: BASE.id, ip: '10.0.0.2' }, [])), ['device', 'map']);
    assert.deepEqual(ids(assetLinks({ id: BASE.id, ip: '10.0.0.2' }, ALL)), ['device', 'map', 'flows', 'ipam']);
  });

  it('uses the permission the sidebar uses for each gated destination', () => {
    const hrefFor: Record<string, string> = {
      inventory: '/inventory',
      traffic: '/traffic',
      config: '/config',
      ipam: '/ipam',
    };
    for (const [name, permission] of Object.entries(LINK_PERMISSIONS)) {
      const shown = (held: string[]) =>
        menuItemsFor(held).some((node) => 'href' in node && node.href === hrefFor[name]);
      assert.equal(shown([]), false, `${name} is hidden without ${permission}`);
      assert.equal(shown([permission]), true, `${name} is shown with ${permission}`);
    }
  });
});

describe('endpointLinks', () => {
  it('links only what the endpoint has', () => {
    assert.deepEqual(ids(endpointLinks({ ip: null, mac: null, hostname: null }, ALL)), ['map', 'ipam']);
    const full = endpointLinks({ ip: '10.0.0.9', mac: 'aa:bb:cc:00:11:22', hostname: 'h' }, ALL);
    assert.equal(full.find((l) => l.id === 'inventory')?.href, '/inventory?q=aa%3Abb%3Acc%3A00%3A11%3A22');
    assert.equal(full.find((l) => l.id === 'flows')?.href, '/traffic/flows?source_ip=10.0.0.9');
  });
});
