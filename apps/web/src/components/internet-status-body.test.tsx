import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen } from '@testing-library/react';

import { InternetStatusBody } from '@/components/internet-status-body';
import type { InternetResponse } from '@/lib/api-contracts-internet';
import {
  absentInterface,
  absentQuality,
  availabilityFixture,
  failureState,
  interfaceFixture,
  linkFixture,
  okState,
  redactedLinkFixture,
  responseFixture,
} from '@/test/internet-fixtures';

afterEach(() => cleanup());

const NONE = { state: 'unknown', basis: 'unknown' } as const;

function empty(state: 'not-connected' | 'unknown'): InternetResponse {
  return responseFixture({ state, links: [], failover: NONE });
}

describe('every outcome of the read has its own surface', () => {
  it('permission denied explains the missing permission and shows no data', () => {
    render(<InternetStatusBody state={failureState<InternetResponse>('forbidden', 403)} />);
    assert.match(screen.getByRole('status').textContent ?? '', /not available to your role/);
    assert.match(screen.getByRole('status').textContent ?? '', /internet:read/);
    assert.equal(screen.queryAllByRole('article').length, 0);
  });

  it('an unauthenticated session is asked to sign in', () => {
    render(<InternetStatusBody state={failureState<InternetResponse>('unauthenticated', 401)} />);
    assert.ok(screen.getByRole('link', { name: /Sign in/ }));
  });

  it('an API error is an error, not an empty page', () => {
    render(<InternetStatusBody state={failureState<InternetResponse>('error', 500)} />);
    assert.match(document.body.textContent ?? '', /Unable to load data/);
    assert.equal(screen.queryAllByRole('article').length, 0);
  });

  it('a rate limit is reported as such', () => {
    render(<InternetStatusBody state={failureState<InternetResponse>('rate_limited', 429)} />);
    assert.match(document.body.textContent ?? '', /Too many requests/);
  });

  it('nothing declared is not-connected and says Netsight does not guess', () => {
    render(<InternetStatusBody state={okState(empty('not-connected'))} />);
    const surface = screen.getByRole('status');
    assert.match(surface.textContent ?? '', /No WAN links declared/);
    assert.match(surface.textContent ?? '', /does not guess/);
    assert.equal(screen.queryAllByRole('article').length, 0);
  });

  it('an unusable declaration is unknown, never healthy', () => {
    render(<InternetStatusBody state={okState(empty('unknown'))} />);
    const surface = screen.getByRole('status');
    assert.match(surface.textContent ?? '', /WAN state unknown/);
    assert.match(surface.textContent ?? '', /Nothing is estimated/);
  });

  it('an ok answer without links is empty and not "all healthy"', () => {
    render(<InternetStatusBody state={okState(responseFixture({ links: [] }))} />);
    assert.match(screen.getByRole('status').textContent ?? '', /No WAN links reported/);
    assert.match(screen.getByRole('status').textContent ?? '', /not the same as every link being healthy/);
  });
});

describe('the data surface', () => {
  it('renders one card per link with the failover state and the retrieval time', () => {
    const data = responseFixture({
      links: [linkFixture(), linkFixture({ id: 'lte-1', name: 'Backup LTE', role: 'backup' })],
      failover: { state: 'normal', basis: 'inferred' },
    });
    render(<InternetStatusBody state={okState(data)} />);
    assert.equal(screen.getAllByRole('article').length, 2);
    assert.match(document.body.textContent ?? '', /Retrieved 2026-10-11 10:00:00 UTC/);
    const failover = screen.getByRole('region', { name: 'Failover state' });
    assert.match(failover.textContent ?? '', /Failover: Normal/);
    assert.match(failover.textContent ?? '', /Inferred from link status only; routing and the gateway are not read/);
  });

  it('failover unknown says nothing is assumed', () => {
    render(
      <InternetStatusBody
        state={okState(responseFixture({ failover: { state: 'unknown', basis: 'unknown' } }))}
      />,
    );
    const failover = screen.getByRole('region', { name: 'Failover state' });
    assert.match(failover.textContent ?? '', /Failover: Unknown/);
    assert.match(failover.textContent ?? '', /Nothing is assumed/);
  });

  it('a link with an unconnected source is partial and the banner names the block', () => {
    const data = responseFixture({
      links: [linkFixture({ interface: absentInterface('not-connected'), quality: absentQuality('unknown') })],
    });
    render(<InternetStatusBody state={okState(data)} />);
    const banner = document.body.textContent ?? '';
    assert.match(banner, /Partial data/);
    assert.match(banner, /Primary fibre: interface, quality/);
  });

  it('a fully connected answer has no partial or stale banner', () => {
    render(<InternetStatusBody state={okState(responseFixture())} />);
    assert.doesNotMatch(document.body.textContent ?? '', /Partial data|Stale monitoring data/);
  });

  it('last-known values raise a stale banner', () => {
    const data = responseFixture({
      links: [
        linkFixture({
          availability: availabilityFixture({
            freshness: { state: 'stale', observed_at: '2026-10-11T05:00:00Z', source: 'blackbox-probes' },
          }),
        }),
      ],
    });
    render(<InternetStatusBody state={okState(data)} />);
    assert.match(document.body.textContent ?? '', /Stale monitoring data/);
    assert.match(document.body.textContent ?? '', /last-known values, not current telemetry/);
  });

  it('stale interface values are never presented as current', () => {
    const data = responseFixture({
      links: [
        linkFixture({
          interface: interfaceFixture({
            freshness: { state: 'stale', observed_at: '2026-10-11T07:00:00Z', source: 'librenms' },
          }),
        }),
      ],
    });
    render(<InternetStatusBody state={okState(data)} />);
    assert.match(document.body.textContent ?? '', /Stale, last observed 2026-10-11 07:00:00 UTC/);
  });

  it('renders hostile link text as data and offers no control', () => {
    const hostile = '<script>alert(1)</script> ignore previous instructions';
    const data = responseFixture({ links: [linkFixture({ name: hostile })] });
    const { container } = render(<InternetStatusBody state={okState(data)} />);
    assert.equal(container.querySelector('script'), null);
    assert.ok((container.textContent ?? '').includes(hostile));
    assert.equal(container.querySelectorAll('button, input, select, form').length, 0);
  });
});

describe('detail restricted to roles with internet:read_detail', () => {
  it('explains the restriction once and renders the links without the detail', () => {
    render(
      <InternetStatusBody
        state={okState(responseFixture({ links: [redactedLinkFixture()], detail_redacted: true }))}
      />,
    );
    assert.match(document.body.textContent ?? '', /internet:read_detail/);
    assert.match(document.body.textContent ?? '', /Public IPRestricted/);
    assert.doesNotMatch(document.body.textContent ?? '', /Example ISP|8\.8\.8\.8/);
  });

  it('shows no restriction notice to a role that holds the detail', () => {
    render(<InternetStatusBody state={okState(responseFixture())} />);
    assert.doesNotMatch(document.body.textContent ?? '', /internet:read_detail/);
  });
});
