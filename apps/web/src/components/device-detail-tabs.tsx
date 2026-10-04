'use client';

import { Tabs } from '@adminlte/react';

import { FreshnessBadge, StatusBadge } from '@/components/status-badge';
import type { Device } from '@/lib/api-contracts';

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

export function DeviceDetailTabs({ device }: { device: Device }) {
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
        { label: 'Interfaces', children: <Pending label="Interface telemetry" /> },
        { label: 'Traffic', children: <Pending label="Traffic telemetry" /> },
        { label: 'Security', children: <Pending label="Security evidence" /> },
        { label: 'Config', children: <Pending label="Configuration history" /> },
        { label: 'Incidents', children: <Pending label="Incident linkage" /> },
        { label: 'Diagnostics', children: <Pending label="Read-only diagnostics" /> },
      ]}
    />
  );
}
