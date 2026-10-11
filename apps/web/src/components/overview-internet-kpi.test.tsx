import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen } from '@testing-library/react';

import { OverviewInternetKpi } from '@/components/overview-internet-kpi';
import type { InternetResponse } from '@/lib/api-contracts-internet';
import {
  failureState,
  interfaceFixture,
  linkFixture,
  okState,
  responseFixture,
} from '@/test/internet-fixtures';

afterEach(() => cleanup());

const NONE = { state: 'unknown', basis: 'unknown' } as const;

describe('the overview Internet card shows real data or stays explicit', () => {
  it('keeps the explicit not-connected surface when no link is declared', () => {
    const { container } = render(
      <OverviewInternetKpi state={okState(responseFixture({ state: 'not-connected', links: [], failover: NONE }))} />,
    );
    assert.match(container.textContent ?? '', /Internet/);
    assert.match(container.textContent ?? '', /Not connected/);
    assert.match(container.textContent ?? '', /WAN telemetry unavailable/);
    assert.equal(screen.queryAllByRole('link').length, 0);
    assert.ok(container.querySelector('.overview-kpi--unknown'));
  });

  it('shows status, throughput and utilisation from the source, linking to the Internet page', () => {
    render(<OverviewInternetKpi state={okState(responseFixture())} />);
    const link = screen.getByRole('link', { name: /Internet: Up\./ });
    assert.equal(link.getAttribute('href'), '/internet');
    assert.match(link.textContent ?? '', /100 Mbps down/);
    assert.match(link.textContent ?? '', /20 Mbps up/);
    assert.match(link.textContent ?? '', /10% utilised/);
  });

  it('never shows a number the source did not report', () => {
    const silent = linkFixture({
      interface: interfaceFixture({ rx_bps: null, tx_bps: null, utilisation_pct: null }),
    });
    const { container } = render(<OverviewInternetKpi state={okState(responseFixture({ links: [silent] }))} />);
    assert.match(container.textContent ?? '', /Throughput not reported/);
    assert.doesNotMatch(container.textContent ?? '', /\b0 (bps|Mbps)\b|\b0%/);
  });

  it('labels stale interface values instead of showing a live gauge', () => {
    const stale = linkFixture({
      interface: interfaceFixture({
        freshness: { state: 'stale', observed_at: '2026-10-11T07:00:00Z', source: 'librenms' },
      }),
    });
    const { container } = render(<OverviewInternetKpi state={okState(responseFixture({ links: [stale] }))} />);
    assert.match(container.textContent ?? '', /stale/i);
  });

  it('says restricted, not empty, when the role cannot read the WAN', () => {
    const { container } = render(<OverviewInternetKpi state={failureState<InternetResponse>('forbidden', 403)} />);
    assert.match(container.textContent ?? '', /Restricted/);
    assert.match(container.textContent ?? '', /Your role cannot read WAN telemetry/);
    assert.equal(screen.queryAllByRole('link').length, 0);
  });

  it('is unknown, not healthy, when the read failed', () => {
    const { container } = render(<OverviewInternetKpi state={failureState<InternetResponse>('error', 500)} />);
    assert.match(container.textContent ?? '', /Unknown/);
    assert.match(container.textContent ?? '', /WAN telemetry could not be read/);
    assert.doesNotMatch(container.textContent ?? '', /\bUp\b/);
  });

  it('names a failover and all-down in words', () => {
    const down = linkFixture({ status: 'down' });
    const backup = linkFixture({ id: 'lte-1', name: 'LTE', role: 'backup', status: 'up' });
    const failedOver = render(
      <OverviewInternetKpi
        state={okState(responseFixture({ links: [down, backup], failover: { state: 'failed-over', basis: 'inferred' } }))}
      />,
    );
    assert.match(failedOver.container.textContent ?? '', /Failed over/);
    cleanup();
    const allDown = render(
      <OverviewInternetKpi
        state={okState(
          responseFixture({
            links: [down, { ...backup, status: 'down' }],
            failover: { state: 'all-down', basis: 'inferred' },
          }),
        )}
      />,
    );
    assert.match(allDown.container.textContent ?? '', /Every declared link is down/);
  });
});
