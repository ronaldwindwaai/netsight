import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen } from '@testing-library/react';

import { OverviewStatusStrip } from '@/components/overview-status-strip';
import type { DeviceHealthSummary } from '@/lib/api-contracts';

afterEach(() => cleanup());

const SUMMARY: DeviceHealthSummary = {
  total: 3,
  by_status: [
    { status: 'healthy', count: 2 },
    { status: 'critical', count: 1 },
  ],
  freshness: { state: 'fresh', observed_at: null, source: 'librenms' },
};

describe('OverviewStatusStrip', () => {
  it('links each non-empty status to the device list filtered to it', () => {
    render(<OverviewStatusStrip summary={SUMMARY} />);
    const critical = screen.getByRole('link', { name: /1 critical/ });
    assert.equal(critical.getAttribute('href'), '/devices?status=critical');
    assert.equal(screen.getByRole('link', { name: /2 healthy/ }).getAttribute('href'), '/devices?status=healthy');
  });

  it('shows empty statuses as plain text, not dead links', () => {
    render(<OverviewStatusStrip summary={SUMMARY} />);
    assert.equal(screen.queryByRole('link', { name: /offline/ }), null);
    assert.ok(screen.getByText('offline 0'));
  });

  it('renders nothing when the summary is unavailable', () => {
    const { container } = render(<OverviewStatusStrip summary={null} />);
    assert.equal(container.childElementCount, 0);
  });
});
