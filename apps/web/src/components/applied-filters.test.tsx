import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen, within } from '@testing-library/react';

import { AppliedFilters } from '@/components/applied-filters';
import { resolveTrafficWindow } from '@/lib/traffic-view';

afterEach(() => cleanup());

const NOW = new Date('2026-10-11T12:00:00Z');
const window24h = resolveTrafficWindow({}, NOW, 31);

describe('the applied-filter chips', () => {
  it('always names the time window, even with no filters', () => {
    render(<AppliedFilters window={window24h} values={{}} />);
    const region = screen.getByRole('region', { name: /Applied filters/i });
    assert.match(region.textContent ?? '', /Time range: Last 24 hours/);
    assert.match(region.textContent ?? '', /No other filters applied/);
    assert.equal(within(region).queryAllByRole('link').length, 0);
  });

  it('lists each filter with a link that removes only that filter', () => {
    render(
      <AppliedFilters
        window={window24h}
        values={{ application: 'Zoom', protocol: 'tcp', port: '443' }}
      />,
    );
    const remove = screen.getByRole('link', { name: 'Remove filter Application: Zoom' });
    assert.equal(remove.getAttribute('href'), '/traffic/flows?preset=24h&protocol=tcp&port=443');
    const clear = screen.getByRole('link', { name: 'Clear all filters' });
    assert.equal(clear.getAttribute('href'), '/traffic/flows?preset=24h');
  });

  it('renders untrusted filter text as text', () => {
    render(<AppliedFilters window={window24h} values={{ application: '<img src=x onerror=alert(1)>' }} />);
    assert.equal(document.querySelector('img'), null);
    assert.ok(screen.getByText(/<img src=x/));
  });

  it('shows a custom window in UTC', () => {
    const custom = resolveTrafficWindow({ from: '2026-10-10T08:30', to: '2026-10-11T08:30' }, NOW, 31);
    render(<AppliedFilters window={custom} values={{}} />);
    assert.match(screen.getByRole('region', { name: /Applied filters/i }).textContent ?? '', /2026-10-10 08:30 UTC to 2026-10-11 08:30 UTC/);
  });
});
