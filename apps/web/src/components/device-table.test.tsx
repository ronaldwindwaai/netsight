import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';

import { DeviceTable } from '@/components/device-table';
import type { Device } from '@/lib/api-contracts';

afterEach(() => cleanup());

function device(id: string, over: Partial<Device> = {}): Device {
  return {
    id: `device-6f1c2a9e-0b1d-5c3e-8f4a-12345678900${id}`,
    name: `sw-${id}`,
    hostname: null,
    type: 'switch',
    status: 'healthy',
    ip_addresses: [],
    mac_addresses: [],
    site_id: null,
    owner_identity_id: null,
    source_aliases: [],
    freshness: { state: 'fresh', observed_at: null, source: null },
    ...over,
  };
}

const ROWS = [
  device('1', { name: 'alpha', status: 'healthy' }),
  device('2', { name: 'bravo', status: 'critical' }),
  device('3', { name: 'charlie', status: 'critical', ip_addresses: ['10.0.0.3'] }),
];

function names(): string[] {
  return screen
    .getAllByRole('row')
    .slice(1)
    .map((row) => within(row).getAllByRole('link')[0].textContent ?? '');
}

describe('DeviceTable', () => {
  it('says the filters only cover the loaded page', () => {
    render(<DeviceTable devices={ROWS} total={120} />);
    assert.match(document.body.textContent ?? '', /3 shown \/ 120 total/);
    assert.match(document.body.textContent ?? '', /this page/i);
  });

  it('sorts by a column and announces the direction', () => {
    render(<DeviceTable devices={ROWS} total={3} />);
    const button = screen.getByRole('button', { name: /Sort by Device/ });
    fireEvent.click(button);
    assert.deepEqual(names(), ['alpha', 'bravo', 'charlie']);
    fireEvent.click(screen.getByRole('button', { name: /Sort by Device/ }));
    assert.deepEqual(names(), ['charlie', 'bravo', 'alpha']);
    assert.match(screen.getByRole('button', { name: /Sort by Device/ }).getAttribute('aria-label') ?? '', /descending/);
  });

  it('filters by a status chip and offers a clear control with a filtered-empty state', () => {
    render(<DeviceTable devices={ROWS} total={3} />);
    const chip = screen.getByRole('button', { name: /critical \(2\)/i });
    fireEvent.click(chip);
    assert.equal(chip.getAttribute('aria-pressed'), 'true');
    assert.deepEqual(names(), ['bravo', 'charlie']);
    fireEvent.change(screen.getByRole("searchbox"), { target: { value: 'zzz' } });
    assert.match(document.body.textContent ?? '', /No devices match/);
    fireEvent.click(screen.getByRole('button', { name: /Clear filters/ }));
    assert.equal(names().length, 3);
  });

  it('shows zero-count statuses as disabled, never hidden', () => {
    render(<DeviceTable devices={ROWS} total={3} />);
    const chip = screen.getByRole('button', { name: /offline \(0\)/i });
    assert.equal((chip as HTMLButtonElement).disabled, true);
  });

  it('links an owner to the identity page when one is recorded', () => {
    render(
      <DeviceTable
        devices={[device('1', { owner_identity_id: 'person-6f1c2a9e-0b1d-5c3e-8f4a-123456789abc' })]}
        total={1}
      />,
    );
    assert.ok(screen.getByRole('link', { name: /Owner/ }).getAttribute('href')?.startsWith('/users/'));
  });
});
