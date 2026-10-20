import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen } from '@testing-library/react';

import { SecurityBody } from '@/components/security-body';
import type { FetchState } from '@/lib/api';
import type { SecurityEvent, SecurityEventsResponse } from '@/lib/api-contracts-security';

afterEach(() => cleanup());

const DEVICE = 'device-123e4567-e89b-12d3-a456-426614174000';

function event(over: Partial<SecurityEvent> = {}): SecurityEvent {
  return {
    id: 'e1',
    observed_at: '2026-10-11T11:00:00Z',
    source: 'suricata',
    severity: 'high',
    category: 'Malware',
    signature: 'ET <b>TROJAN</b> beacon',
    source_ip: '10.0.0.10',
    destination_ip: '203.0.113.9',
    device_id: DEVICE,
    ...over,
  };
}

function response(over: Partial<SecurityEventsResponse> = {}): SecurityEventsResponse {
  return {
    state: 'ok',
    time_range: { from: '2026-10-10T12:00:00Z', to: '2026-10-11T12:00:00Z', preset: '24h' },
    events: [event()],
    freshness: { state: 'fresh', as_of: '2026-10-11T11:59:00Z', stale_after_seconds: 300 },
    ...over,
  } as SecurityEventsResponse;
}

const ok = (data: SecurityEventsResponse) =>
  ({ kind: 'ok', data }) as FetchState<SecurityEventsResponse>;
const text = () => document.body.textContent ?? '';

describe('the security events body', () => {
  it('states the window and that counts cover only the listed events', () => {
    render(<SecurityBody state={ok(response())} limit={100} />);
    assert.match(text(), /Window .* to .* \(UTC\)/);
    assert.match(text(), /1 events listed\./);
    assert.match(text(), /cover exactly the events listed/);
  });

  it('warns that counts are not totals when the list hit the read limit', () => {
    render(<SecurityBody state={ok(response())} limit={1} />);
    assert.match(text(), /not totals for the window/);
  });

  it('names each severity in words with its count', () => {
    render(<SecurityBody state={ok(response())} limit={100} />);
    const strip = screen.getByRole('region', { name: /Severity of the listed events/i });
    assert.match(strip.textContent ?? '', /1high|high1/);
    assert.match(strip.textContent ?? '', /critical/);
  });

  it('renders the signature as text, never markup', () => {
    render(<SecurityBody state={ok(response())} limit={100} />);
    assert.equal(document.querySelector('b'), null);
    assert.ok(screen.getByText(/ET <b>TROJAN<\/b> beacon/));
  });

  it('links the device, and the source address only when a flows link is offered', () => {
    const first = render(<SecurityBody state={ok(response())} limit={100} />);
    assert.equal(screen.getByRole('link', { name: DEVICE }).getAttribute('href'), `/devices/${DEVICE}`);
    assert.equal(screen.queryByRole('link', { name: '10.0.0.10' }), null);
    first.unmount();
    render(
      <SecurityBody
        state={ok(response())}
        limit={100}
        flowsHref={(ip) => `/traffic/flows?preset=24h&source_ip=${ip}`}
      />,
    );
    assert.equal(
      screen.getByRole('link', { name: '10.0.0.10' }).getAttribute('href'),
      '/traffic/flows?preset=24h&source_ip=10.0.0.10',
    );
  });

  it('keeps empty, not-connected and unknown distinct', () => {
    const empty = render(<SecurityBody state={ok(response({ events: [] }))} limit={100} />);
    assert.match(text(), /No security events in this window/);
    empty.unmount();
    const none = render(
      <SecurityBody state={ok(response({ state: 'not-connected', events: [] }))} limit={100} />,
    );
    assert.match(text(), /Security source not connected/);
    none.unmount();
    render(<SecurityBody state={ok(response({ state: 'unknown', events: [] }))} limit={100} />);
    assert.match(text(), /Security state unknown/);
  });

  it('shows a failed read as a failure, never as an empty list', () => {
    const forbidden = { kind: 'forbidden', status: 403, correlationId: 'c-1' } as FetchState<SecurityEventsResponse>;
    render(<SecurityBody state={forbidden} limit={100} />);
    assert.match(text(), /Permission denied/);
    assert.doesNotMatch(text(), /No security events/);
  });
});
