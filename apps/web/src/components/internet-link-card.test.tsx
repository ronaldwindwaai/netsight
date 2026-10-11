import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen, within } from '@testing-library/react';

import { InternetLinkCard } from '@/components/internet-link-card';
import {
  absentAvailability,
  absentInterface,
  absentQuality,
  availabilityFixture,
  interfaceFixture,
  linkFixture,
  qualityFixture,
  redactedLinkFixture,
} from '@/test/internet-fixtures';

afterEach(() => cleanup());

function block(name: RegExp): HTMLElement {
  return screen.getByRole('region', { name });
}

describe('a WAN link with every source connected', () => {
  it('shows source-reported values, each block naming its source and freshness', () => {
    render(<InternetLinkCard link={linkFixture()} />);
    const wan = block(/Interface for this link/);
    assert.match(wan.textContent ?? '', /Source: LibreNMS/);
    assert.match(wan.textContent ?? '', /Fresh, observed 2026-10-11 09:59:00 UTC \(librenms\)/);
    assert.match(wan.textContent ?? '', /Capacity1 Gbps/);
    assert.match(wan.textContent ?? '', /Download \(in\)100 Mbps/);
    assert.match(wan.textContent ?? '', /Upload \(out\)20 Mbps/);
    assert.match(wan.textContent ?? '', /Utilisation10%/);
    assert.match(wan.textContent ?? '', /Public IP8\.8\.8\.8/);

    const quality = block(/Quality, last 15 min for this link/);
    assert.match(quality.textContent ?? '', /Source: stored probe samples/);
    assert.match(quality.textContent ?? '', /Latency12\.5 ms/);
    assert.match(quality.textContent ?? '', /Jitter1\.5 ms/);
    assert.match(quality.textContent ?? '', /Packet loss0%/);
    assert.match(quality.textContent ?? '', /DNSPass, 20\.1 ms/);

    const availability = block(/Availability, 24 h for this link/);
    assert.match(availability.textContent ?? '', /Uptime99\.95%/);
    assert.match(availability.textContent ?? '', /Outage nowNone observed/);
    assert.match(availability.textContent ?? '', /Time without a probe round is unknown, not up/);
  });

  it('labels the operator declarations as configured, not measured', () => {
    render(<InternetLinkCard link={linkFixture()} />);
    const card = screen.getByRole('article', { name: 'WAN link Primary fibre' });
    assert.match(
      card.textContent ?? '',
      /Configured by an administrator \(not measured\): ISP Example ISP; gateway 192\.0\.2\.1; probe location branch/,
    );
    assert.match(card.textContent ?? '', /Primary/);
  });

  it('carries the status as a word and an icon, not only a colour', () => {
    render(<InternetLinkCard link={linkFixture({ status: 'down' })} />);
    const badge = screen.getByText('Down');
    assert.ok(badge.querySelector('i.bi') !== null || badge.parentElement?.querySelector('i.bi') !== null);
    assert.match(badge.className, /badge/);
  });

  it('says a backup link is a backup', () => {
    render(<InternetLinkCard link={linkFixture({ role: 'backup', name: 'LTE' })} />);
    assert.match(screen.getByRole('article', { name: 'WAN link LTE' }).textContent ?? '', /Backup/);
  });
});

describe('a missing value is never a zero', () => {
  it('prints "Not reported" for every value the source left out', () => {
    const link = linkFixture({
      interface: interfaceFixture({
        oper_status: null,
        capacity_bps: null,
        rx_bps: null,
        tx_bps: null,
        utilisation_pct: null,
        public_ip: null,
      }),
      quality: qualityFixture({
        latency_ms: null,
        jitter_ms: null,
        loss_pct: null,
        dns_status: null,
        dns_latency_ms: null,
      }),
      availability: availabilityFixture({ uptime_pct: null, coverage_pct: 0 }),
      configured: { isp: null, gateway: null, probe_location: null },
    });
    render(<InternetLinkCard link={link} />);
    const wan = block(/Interface for this link/);
    assert.match(wan.textContent ?? '', /Capacity\s*Not reported/);
    assert.match(wan.textContent ?? '', /Download \(in\)Not reported/);
    assert.match(wan.textContent ?? '', /Public IPNot reported/);
    assert.doesNotMatch(wan.textContent ?? '', /\b0 (bps|Mbps)\b/);
    const quality = block(/Quality/);
    assert.match(quality.textContent ?? '', /LatencyNot reported/);
    assert.match(quality.textContent ?? '', /Packet lossNot reported/);
    assert.match(quality.textContent ?? '', /DNSNot reported/);
    assert.match(block(/Availability/).textContent ?? '', /UptimeNot reported/);
    assert.match(
      screen.getByRole('article').textContent ?? '',
      /ISP Not reported; gateway Not reported; probe location Not reported/,
    );
  });

  it('shows a measured zero as a zero', () => {
    render(
      <InternetLinkCard
        link={linkFixture({ interface: interfaceFixture({ rx_bps: 0, tx_bps: 0, utilisation_pct: 0 }) })}
      />,
    );
    assert.match(block(/Interface/).textContent ?? '', /Download \(in\)0 bps/);
  });
});

describe('an absent or failing source is stated, not hidden', () => {
  it('interface not connected', () => {
    render(<InternetLinkCard link={linkFixture({ interface: absentInterface('not-connected') })} />);
    const wan = block(/Interface/);
    assert.match(wan.textContent ?? '', /Interface source not connected/);
    assert.doesNotMatch(wan.textContent ?? '', /Download|Capacity|Public IP/);
  });

  it('interface unknown', () => {
    render(<InternetLinkCard link={linkFixture({ interface: absentInterface('unknown') })} />);
    assert.match(block(/Interface/).textContent ?? '', /Interface state unknown/);
  });

  it('probe samples not connected and unreadable', () => {
    render(
      <InternetLinkCard
        link={linkFixture({
          quality: absentQuality('not-connected'),
          availability: absentAvailability('unknown'),
        })}
      />,
    );
    assert.match(block(/Quality/).textContent ?? '', /Probe samples not connected/);
    assert.match(block(/Availability/).textContent ?? '', /Availability unknown/);
    assert.doesNotMatch(block(/Availability/).textContent ?? '', /Uptime\d/);
  });

  it('no samples in the window is empty, not a healthy zero', () => {
    render(
      <InternetLinkCard
        link={linkFixture({
          quality: qualityFixture({
            latency_ms: null,
            jitter_ms: null,
            loss_pct: null,
            dns_status: null,
            dns_latency_ms: null,
            sample_count: 0,
            freshness: { state: 'unknown', observed_at: null, source: 'blackbox-probes' },
          }),
        })}
      />,
    );
    const quality = block(/Quality/);
    assert.match(quality.textContent ?? '', /No probe samples yet/);
    assert.doesNotMatch(quality.textContent ?? '', /Packet loss0%/);
  });
});

describe('stale and in-progress states', () => {
  it('labels last-known values as stale', () => {
    render(
      <InternetLinkCard
        link={linkFixture({
          interface: interfaceFixture({
            freshness: { state: 'stale', observed_at: '2026-10-11T07:00:00Z', source: 'librenms' },
          }),
        })}
      />,
    );
    const wan = block(/Interface/);
    assert.match(wan.textContent ?? '', /Stale, last observed 2026-10-11 07:00:00 UTC/);
    assert.match(wan.textContent ?? '', /last-known values, not current telemetry/);
  });

  it('announces an outage in progress with its start and duration', () => {
    render(
      <InternetLinkCard
        link={linkFixture({
          status: 'down',
          availability: availabilityFixture({
            current_outage_started_at: '2026-10-11T09:50:00Z',
            current_outage_seconds: 600,
          }),
        })}
      />,
    );
    const alert = within(block(/Availability/)).getByRole('alert');
    assert.match(alert.textContent ?? '', /Outage in progress since 2026-10-11 09:50:00 UTC \(10 min\)/);
    assert.match(block(/Availability/).textContent ?? '', /Outage nowYes/);
  });
});

describe('operator and source text is data only', () => {
  it('renders hostile names, ISP and addresses as plain text', () => {
    const hostile = '<img src=x onerror=alert(1)>';
    const { container } = render(
      <InternetLinkCard
        link={linkFixture({
          name: hostile,
          configured: { isp: hostile, gateway: hostile, probe_location: null },
          interface: interfaceFixture({ public_ip: hostile }),
        })}
      />,
    );
    assert.equal(container.querySelector('img'), null);
    assert.equal(container.querySelector('script'), null);
    assert.ok((container.textContent ?? '').includes(hostile));
  });

  it('is read-only: no button, input or form', () => {
    const { container } = render(<InternetLinkCard link={linkFixture()} />);
    assert.equal(container.querySelectorAll('button, input, select, textarea, form, a').length, 0);
  });
});

describe('a link read by a role without internet:read_detail', () => {
  it('says the detail is restricted instead of "Not reported"', () => {
    render(<InternetLinkCard link={redactedLinkFixture()} detailRedacted />);
    const wan = block(/Interface for this link/);
    const text = wan.textContent ?? '';
    assert.match(text, /Download \(in\)Restricted/);
    assert.match(text, /Upload \(out\)Restricted/);
    assert.match(text, /UtilisationRestricted/);
    assert.match(text, /Public IPRestricted/);
    assert.doesNotMatch(text, /Not reported/);
    // status, capacity and the probe blocks are still shown
    assert.match(text, /Operational statusup/);
    assert.match(text, /Capacity1 Gbps/);
    assert.match(block(/Quality, last 15 min for this link/).textContent ?? '', /Latency12\.5 ms/);
    const card = screen.getByRole('article', { name: 'WAN link Primary fibre' });
    assert.match(card.textContent ?? '', /ISP and gateway restricted/);
    assert.doesNotMatch(card.textContent ?? '', /Example ISP|192\.0\.2\.1|8\.8\.8\.8/);
  });

  it('still reports a genuinely missing value as not reported for a role with the detail', () => {
    const link = linkFixture({ interface: interfaceFixture({ rx_bps: null, public_ip: null }) });
    render(<InternetLinkCard link={link} />);
    const text = block(/Interface for this link/).textContent ?? '';
    assert.match(text, /Download \(in\)Not reported/);
    assert.match(text, /Public IPNot reported/);
    assert.doesNotMatch(text, /Restricted/);
  });
});
