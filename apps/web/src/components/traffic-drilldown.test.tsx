import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen } from '@testing-library/react';

import { AnomaliesBody } from '@/components/anomalies-body';
import { ApplicationsBody } from '@/components/applications-body';
import { DestinationsBody } from '@/components/destinations-body';
import { FlowExplorerBody } from '@/components/flow-explorer-body';
import { flowsDrillHref, resolveTrafficWindow } from '@/lib/traffic-view';
import {
  anomaliesFixture,
  anomalyFixture,
  applicationFixture,
  applicationsFixture,
  destinationFixture,
  destinationsFixture,
  firstSeenFixture,
  flowFixture,
  flowsFixture,
  okState,
} from '@/test/traffic-fixtures';

afterEach(() => cleanup());

const NOW = new Date('2026-10-11T12:00:00Z');
const window24h = resolveTrafficWindow({}, NOW, 31);
const hrefOf = (name: string | RegExp) => screen.getByRole('link', { name }).getAttribute('href');

describe('flow rows drill into related views', () => {
  const linkTo = (extra: Record<string, string>) =>
    flowsDrillHref(window24h, extra, { detail: true });
  const access = { people: true, devices: true };

  it('links the source and destination addresses to the narrowed flows and the device to inventory', () => {
    render(
      <FlowExplorerBody state={okState(flowsFixture({ flows: [flowFixture()] }))} filtered={false} linkTo={linkTo} access={access} />,
    );
    assert.equal(hrefOf('10.0.0.10'), '/traffic/flows?preset=24h&source_ip=10.0.0.10');
    assert.equal(hrefOf('203.0.113.9'), '/traffic/flows?preset=24h&destination_ip=203.0.113.9');
    assert.match(hrefOf('PC-001') ?? '', /^\/devices\/device-/);
  });

  it('renders plain text for an address the linker refuses (invalid text)', () => {
    const state = okState(flowsFixture({ flows: [flowFixture({ source_ip: 'not an ip' })] }));
    render(<FlowExplorerBody state={state} filtered={false} linkTo={linkTo} />);
    assert.equal(screen.queryByRole('link', { name: 'not an ip' }), null);
    assert.ok(screen.getByText('not an ip'));
  });

  it('renders plain addresses when no linker is given', () => {
    render(<FlowExplorerBody state={okState(flowsFixture({ flows: [flowFixture()] }))} filtered={false} />);
    assert.equal(screen.queryByRole('link', { name: '10.0.0.10' }), null);
  });
});

describe('applications link to their flows', () => {
  it('links an application name to the application filter', () => {
    render(
      <ApplicationsBody
        state={okState(applicationsFixture({ items: [applicationFixture({ application: 'Zoom' })] }))}
        window={window24h}
      />,
    );
    assert.equal(hrefOf('Zoom'), '/traffic/flows?preset=24h&application=Zoom');
  });

  it('keeps the name as text when it cannot be a valid filter', () => {
    render(
      <ApplicationsBody
        state={okState(applicationsFixture({ items: [applicationFixture({ application: 'a\u0007b' })] }))}
        window={window24h}
      />,
    );
    assert.equal(screen.queryAllByRole('link').length, 0);
  });
});

describe('destinations link to their flows', () => {
  const state = okState(destinationsFixture({ items: [destinationFixture()] }));

  it('offers address, ASN and country links to a role with the detail permission', () => {
    render(<DestinationsBody state={state} window={window24h} detail />);
    assert.equal(hrefOf('203.0.113.9'), '/traffic/flows?preset=24h&destination_ip=203.0.113.9');
    assert.equal(hrefOf('AS64500'), '/traffic/flows?preset=24h&asn=64500');
    assert.equal(hrefOf('ZA'), '/traffic/flows?preset=24h&country=ZA');
  });

  it('never links an address filter the role would be refused, but still links ASN and country', () => {
    render(<DestinationsBody state={state} window={window24h} detail={false} />);
    assert.equal(screen.queryByRole('link', { name: '203.0.113.9' }), null);
    assert.equal(hrefOf('AS64500'), '/traffic/flows?preset=24h&asn=64500');
  });
});

describe('anomalies link to the flows of the hour', () => {
  it('offers no link for an application anomaly with no application name', () => {
    const item = anomalyFixture({ subject: { kind: 'application', label: null } });
    render(<AnomaliesBody state={okState(anomaliesFixture({ anomalies: [item] }))} window={window24h} detail />);
    assert.equal(screen.queryByRole('link', { name: /Inspect the flows/ }), null);
  });

  it('shows a first-seen row without an address as plain text', () => {
    const row = firstSeenFixture({ address: null });
    render(<AnomaliesBody state={okState(anomaliesFixture({ first_seen: [row] }))} window={window24h} detail />);
    assert.ok(screen.getByText('Address not reported'));
    assert.equal(screen.queryByRole('link', { name: 'Address not reported' }), null);
  });

  it('links a total-traffic anomaly to exactly that UTC hour', () => {
    render(<AnomaliesBody state={okState(anomaliesFixture())} window={window24h} detail />);
    assert.equal(
      hrefOf(/Inspect the flows in this hour/),
      '/traffic/flows?from=2026-10-11T02%3A00%3A00Z&to=2026-10-11T03%3A00%3A00Z',
    );
  });

  it('narrows an application anomaly to that application', () => {
    const item = anomalyFixture({ subject: { kind: 'application', label: 'Zoom' } });
    render(<AnomaliesBody state={okState(anomaliesFixture({ anomalies: [item] }))} window={window24h} detail />);
    assert.match(hrefOf(/for this application/) ?? '', /&application=Zoom$/);
  });

  it('links a first-seen destination only to a role with the detail permission', () => {
    const { unmount } = render(<AnomaliesBody state={okState(anomaliesFixture())} window={window24h} detail />);
    assert.equal(hrefOf('198.51.100.7'), '/traffic/flows?preset=24h&destination_ip=198.51.100.7');
    unmount();
    render(<AnomaliesBody state={okState(anomaliesFixture())} window={window24h} detail={false} />);
    assert.equal(screen.queryByRole('link', { name: '198.51.100.7' }), null);
  });
});
