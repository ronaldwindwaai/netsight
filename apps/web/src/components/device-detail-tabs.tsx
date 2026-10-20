'use client';

import Link from 'next/link';
import { Tabs } from '@adminlte/react';

import { DataFailure } from '@/components/data-state';
import {
  DeviceIdentityFacts,
  RelatedLinksCard,
  RelatedTab,
} from '@/components/device-related-panels';
import { InterfaceTable } from '@/components/interface-table';
import { FreshnessBadge, StatusBadge } from '@/components/status-badge';
import type { Device, InterfaceListResponse } from '@/lib/api-contracts';
import type { FetchState } from '@/lib/api';

function valueOrPending(value: string | null | undefined): string {
  return value || 'Not tracked yet';
}

/**
 * Diagnostics tab: read-only blackbox runs open on the diagnostics page with
 * this device's hostname pre-selected. No run is ever started from the device
 * page itself.
 */
function DiagnosticsTab({ device }: { device: Device }) {
  const hostname = device.hostname;
  if (hostname === null) {
    return (
      <div className="py-4 text-body-secondary">
        <i className="bi bi-slash-circle me-2" aria-hidden="true" />
        This device has no hostname or address recorded, so there is nothing to diagnose. The
        monitoring source did not report one.
      </div>
    );
  }
  return (
    <div className="py-3">
      <p className="text-body-secondary">
        Run a read-only blackbox diagnostic for {hostname}. Checks are bounded and only probe the
        configured allow-list.
      </p>
      <Link
        className="btn btn-sm btn-outline-primary"
        href={`/diagnostics?target=${encodeURIComponent(hostname)}`}
      >
        <i className="bi bi-clipboard2-pulse me-1" aria-hidden="true" />
        Run diagnostics
      </Link>
    </div>
  );
}

/**
 * Interfaces tab.
 *
 * Renders real source data when the API provides it and an explicit failure
 * state otherwise. An empty interface list is a valid result, not an error;
 * an unavailable source is never shown as zero interfaces.
 */
function InterfacesPanel({ state }: { state: FetchState<InterfaceListResponse> }) {
  if (state.kind !== 'ok') {
    return (
      <>
        <DataFailure state={state} />
        <div className="py-3">
          <div className="py-3 text-body-secondary">
          <i className="bi bi-plug me-2" aria-hidden="true" />
          Interface telemetry is not yet connected for this device.
        </div>
        </div>
      </>
    );
  }

  if (state.data.total === 0) {
    return (
      <div className="py-4 text-body-secondary">
        <i className="bi bi-check2-circle me-2" aria-hidden="true" />
        The monitoring source reported no interfaces for this device.
      </div>
    );
  }

  return <InterfaceTable interfaces={state.data.items} total={state.data.total} />;
}

export function DeviceDetailTabs({
  device,
  interfaces,
}: {
  device: Device;
  interfaces: FetchState<InterfaceListResponse>;
}) {
  return (
    <Tabs
      items={[
        {
          label: 'Summary',
          children: (
            <>
            <dl className="device-summary mb-0 py-3">
              <div>
                <dt>Status</dt>
                <dd>
                  <StatusBadge status={device.status} />
                </dd>
              </div>
              <div>
                <dt>Hostname</dt>
                <dd>{valueOrPending(device.hostname)}</dd>
              </div>
              <div>
                <dt>Type</dt>
                <dd>{valueOrPending(device.type)}</dd>
              </div>
              <div>
                <dt>Primary IP</dt>
                <dd>{device.ip_addresses[0] ?? 'Not tracked yet'}</dd>
              </div>
              <div>
                <dt>Site</dt>
                <dd>{valueOrPending(device.site_id)}</dd>
              </div>
              <div>
                <dt>Freshness</dt>
                <dd>
                  <FreshnessBadge state={device.freshness.state} />
                </dd>
              </div>
            </dl>
            <DeviceIdentityFacts device={device} />
            <RelatedLinksCard device={device} />
            </>
          ),
        },
        { label: 'Interfaces', children: <InterfacesPanel state={interfaces} /> },
        {
          label: 'Traffic',
          children: <RelatedTab device={device} ids={['flows', 'map']} missing="Per-device traffic telemetry" />,
        },
        {
          label: 'Security',
          children: <RelatedTab device={device} ids={['alerts', 'incidents']} missing="Per-device security evidence" />,
        },
        {
          label: 'Config',
          children: <RelatedTab device={device} ids={['config']} missing="Per-device configuration history" />,
        },
        {
          label: 'Incidents',
          children: <RelatedTab device={device} ids={['incidents', 'alerts']} missing="Per-device incident linkage" />,
        },
        { label: 'Diagnostics', children: <DiagnosticsTab device={device} /> },
      ]}
    />
  );
}
