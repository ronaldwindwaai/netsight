import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, fireEvent, render, screen } from '@testing-library/react';

import { DeviceDetailTabs } from '@/components/device-detail-tabs';
import type { Device } from '@/lib/api-contracts';
import { LINK_PERMISSIONS } from '@/lib/device-links';

afterEach(() => cleanup());

const DEVICE: Device = {
  id: 'device-6f1c2a9e-0b1d-5c3e-8f4a-123456789abc',
  name: 'core-sw-1',
  hostname: 'core-sw-1.example.test',
  type: 'switch',
  status: 'warning',
  ip_addresses: ['10.0.0.1'],
  mac_addresses: ['aa:bb:cc:dd:ee:ff'],
  site_id: null,
  owner_identity_id: null,
  source_aliases: [{ source: 'librenms', native_id: '42' }],
  freshness: { state: 'stale', observed_at: '2026-10-11T12:00:00Z', source: 'librenms' },
};

const NO_INTERFACES = { kind: 'source_unavailable', code: 'X', message: '', correlationId: 'c', status: 503 } as never;

const ALL = Object.values(LINK_PERMISSIONS);

function open(name: RegExp): void {
  fireEvent.click(screen.getByRole('tab', { name }));
}

describe('DeviceDetailTabs cross-links', () => {
  it('summary shows every address, source alias and links to map, inventory and flows', () => {
    render(<DeviceDetailTabs device={DEVICE} interfaces={NO_INTERFACES} permissions={ALL} />);
    const text = document.body.textContent ?? '';
    assert.match(text, /aa:bb:cc:dd:ee:ff/);
    assert.match(text, /librenms: 42/);
    const hrefs = screen.getAllByRole('link').map((a) => a.getAttribute('href'));
    assert.ok(hrefs.some((h) => h?.startsWith('/network/map?focus=device-')));
    assert.ok(hrefs.includes('/traffic/flows?source_ip=10.0.0.1'));
    assert.ok(hrefs.includes('/inventory?q=core-sw-1'));
  });

  it('a not-connected tab is explicit and is not a dead end', () => {
    render(<DeviceDetailTabs device={DEVICE} interfaces={NO_INTERFACES} permissions={ALL} />);
    open(/Incidents/);
    const panel = document.body.textContent ?? '';
    assert.match(panel, /Per-device incident linkage is not yet connected/);
    assert.match(panel, /not filtered to this device/);
  });

  it('says so when no address exists to link flows from', () => {
    render(<DeviceDetailTabs device={{ ...DEVICE, ip_addresses: [] }} interfaces={NO_INTERFACES} permissions={ALL} />);
    open(/Traffic/);
    assert.match(document.body.textContent ?? '', /No address is recorded/);
  });

  it('hides gated links from a role without the permissions and still names the missing telemetry', () => {
    render(<DeviceDetailTabs device={DEVICE} interfaces={NO_INTERFACES} permissions={[]} />);
    const hrefs = screen.getAllByRole('link').map((a) => a.getAttribute('href') ?? '');
    assert.equal(hrefs.some((h) => h.startsWith('/traffic') || h.startsWith('/inventory') || h === '/config'), false);
    open(/Config/);
    assert.match(document.body.textContent ?? '', /Per-device configuration history is not yet connected/);
  });
});
