/**
 * Counts-only cards for the roles that hold the summary rung (Management; Technician for findings).
 * They show numbers and nothing that names an asset, address, endpoint or person. A figure that is
 * not reported is "Not reported", never zero, and no count is shown for a state that is not ok.
 */
import { Card } from '@adminlte/react';

import { DataFailure } from '@/components/data-state';
import { SourceNotices } from '@/components/source-notices';
import { StateSurface, StoreStateSurface } from '@/components/state-surface';
import type { InventorySummaryResponse } from '@/lib/api-contracts-inventory';
import type { IpamSummary } from '@/lib/api-contracts-ipam';
import type { UnknownDeviceSummary } from '@/lib/api-contracts-unknown-devices';
import type { FetchState } from '@/lib/api-response';
import { formatUtcTimestamp } from '@/lib/format-time';
import { classLabel, NOT_REPORTED } from '@/lib/inventory-view';
import { severityPresentation, statePresentation } from '@/lib/unknown-device-view';

function Stat({ label, value }: { label: string; value: number | null }) {
  return (
    <div className="col-6 col-md-3">
      <div className="small text-body-secondary">{label}</div>
      <div className="fs-4 fw-semibold">{value === null ? <span className="fs-6 text-body-secondary">{NOT_REPORTED}</span> : value}</div>
    </div>
  );
}

function failureOrNull<T>(state: FetchState<T>, noun: string, permission: string) {
  if (state.kind === 'ok') return null;
  if (state.kind === 'forbidden') {
    return (
      <StateSurface
        icon="bi bi-shield-lock"
        title={`${noun} are not available to your role`}
        detail={`Reading even the counts needs the ${permission} permission, which your role does not hold.`}
      />
    );
  }
  return <DataFailure state={state} />;
}

export function InventorySummaryCard({ state }: { state: FetchState<InventorySummaryResponse> }) {
  const failed = failureOrNull(state, 'Inventory counts', 'inventory:read-summary');
  if (failed !== null || state.kind !== 'ok') return failed;
  const { data } = state;
  if (data.state !== 'ok' || data.summary === null) {
    return <StoreStateSurface state={data.state === 'unknown' ? 'unknown' : 'not-connected'} noun="counts" store="NetBox" />;
  }
  const summary = data.summary;
  return (
    <>
      <SourceNotices sources={data.sources} />
      <Card title="Inventory at a glance" icon="bi bi-boxes" variant="outline" theme="primary">
        <div className="row g-3">
          <Stat label="Assets" value={summary.total} />
          <Stat label="Known to NetBox" value={summary.known} />
          <Stat label="Seen by telemetry only" value={summary.unknown} />
        </div>
        <h3 className="h6 mt-3">By class</h3>
        <ul className="mb-2">
          {summary.by_class.map((row) => (
            <li key={row.asset_class}>
              {classLabel(row.asset_class)}: {row.count}
            </li>
          ))}
        </ul>
        <p className="small text-body-secondary mb-0">
          Counts only, as of {formatUtcTimestamp(data.generated_at)}. Your role does not see individual
          assets.
        </p>
      </Card>
    </>
  );
}

export function IpamSummaryCard({ state }: { state: FetchState<IpamSummary> }) {
  const failed = failureOrNull(state, 'IPAM counts', 'ipam:read-summary');
  if (failed !== null || state.kind !== 'ok') return failed;
  const { data } = state;
  if (data.state !== 'ok' || data.counts === null) {
    return <StoreStateSurface state={data.state === 'unknown' ? 'unknown' : 'not-connected'} noun="counts" store="NetBox" />;
  }
  const counts = data.counts;
  return (
    <>
      <SourceNotices sources={data.sources} />
      <Card title="IPAM at a glance" icon="bi bi-diagram-2" variant="outline" theme="primary">
        <div className="row g-3">
          <Stat label="Prefixes" value={counts.prefixes} />
          <Stat label="VLANs" value={counts.vlans} />
          <Stat label="NetBox addresses" value={counts.addresses} />
          <Stat label="Reserved ranges" value={counts.reserved_ranges} />
          <Stat label="Active addresses" value={counts.active_addresses} />
          <Stat label="Stale addresses" value={counts.stale_addresses} />
          <Stat label="Activity unknown" value={counts.unknown_activity_addresses} />
          <Stat label="Seen but not in NetBox" value={counts.discovered_only_addresses} />
        </div>
        {data.telemetry.state !== 'ok' ? (
          <p className="small text-body-secondary mt-3 mb-0">
            No telemetry could be read, so active and stale are not judged: they read Not reported.
          </p>
        ) : null}
        <p className="small text-body-secondary mt-2 mb-0">
          Counts only, as of {formatUtcTimestamp(data.generated_at)}. Your role does not see individual
          prefixes or addresses.
        </p>
      </Card>
    </>
  );
}

export function FindingsSummaryCard({ state }: { state: FetchState<UnknownDeviceSummary> }) {
  const failed = failureOrNull(state, 'Unknown-device counts', 'unknown-devices:read-summary');
  if (failed !== null || state.kind !== 'ok') return failed;
  const { data } = state;
  if (data.state !== 'ok' || data.counts === null) {
    return <StoreStateSurface state={data.state === 'unknown' ? 'unknown' : 'not-connected'} noun="findings" store="Finding store" />;
  }
  const counts = data.counts;
  return (
    <Card title="Unknown devices at a glance" icon="bi bi-patch-question" variant="outline" theme="primary">
      <div className="row g-3">
        <Stat label="Open findings" value={counts.open} />
      </div>
      <h3 className="h6 mt-3">By state</h3>
      <ul className="mb-2">
        {counts.by_state.map((row) => (
          <li key={row.state}>
            {statePresentation(row.state).label}: {row.count}
          </li>
        ))}
      </ul>
      <h3 className="h6">By severity</h3>
      <ul className="mb-2">
        {counts.by_severity.map((row) => (
          <li key={row.severity}>
            {severityPresentation(row.severity).label}: {row.count}
          </li>
        ))}
      </ul>
      <p className="small text-body-secondary mb-0">
        Counts only, as of {formatUtcTimestamp(data.generated_at)}. Your role does not see the devices
        themselves.
      </p>
    </Card>
  );
}
