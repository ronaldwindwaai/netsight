'use client';

import { Tabs } from '@adminlte/react';

import { DataFailure } from '@/components/data-state';
import { InterfaceTable } from '@/components/interface-table';
import { FreshnessBadge, StatusBadge } from '@/components/status-badge';
import type { Device, InterfaceListResponse } from '@/lib/api-contracts';
import type { FetchState } from '@/lib/api';

function valueOrPending(value: string | null | undefined): string {
  return value || 'Not tracked yet';
}

function Pending({ label }: { label: string }) {
  return (
    <div className="py-4 text-body-secondary">
      <i className="bi bi-plug me-2" aria-hidden="true" />
      {label} is not yet connected for this device.
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
          <Pending label="Interface telemetry" />
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
          ),
        },
        { label: 'Interfaces', children: <InterfacesPanel state={interfaces} /> },
        { label: 'Traffic', children: <Pending label="Traffic telemetry" /> },
        { label: 'Security', children: <Pending label="Security evidence" /> },
        { label: 'Config', children: <Pending label="Configuration history" /> },
        { label: 'Incidents', children: <Pending label="Incident linkage" /> },
        { label: 'Diagnostics', children: <Pending label="Read-only diagnostics" /> },
      ]}
    />
  );
}
