/**
 * One asset with the provenance of every field, for every outcome of the read. Each field shows the
 * NetBox reading and the telemetry reading side by side, so a conflict is visible, and says where the
 * value shown came from. Untrusted source text is rendered as text.
 */
import Link from 'next/link';
import { Card } from '@adminlte/react';

import { DataFailure } from '@/components/data-state';
import { ClassBadge, ProvenanceBadge, ReconcileBadge } from '@/components/inventory-parts';
import { SourceLine, SourceNotices } from '@/components/source-notices';
import { StateSurface, StoreStateSurface } from '@/components/state-surface';
import { StatusBadge } from '@/components/status-badge';
import type { InventoryDetail, InventoryField } from '@/lib/api-contracts-inventory';
import type { FetchState } from '@/lib/api-response';
import { formatUtcTimestamp } from '@/lib/format-time';
import { NOT_REPORTED, classBasisText, classLabel, sourceLabel } from '@/lib/inventory-view';

function Reading({ value }: { value: string | null }) {
  return value === null ? (
    <span className="text-body-secondary">{NOT_REPORTED}</span>
  ) : (
    <span className="text-break">{value}</span>
  );
}

const FIELD_ROWS: ReadonlyArray<{ key: 'name' | 'site' | 'ip_address' | 'mac_address'; label: string }> = [
  { key: 'name', label: 'Name' },
  { key: 'site', label: 'Site' },
  { key: 'ip_address', label: 'IP address' },
  { key: 'mac_address', label: 'MAC address' },
];

function FieldTable({ fields }: { fields: Record<string, InventoryField> }) {
  return (
    <table className="table table-sm mb-0">
      <caption className="visually-hidden">Field readings by source</caption>
      <thead>
        <tr>
          <th scope="col">Field</th>
          <th scope="col">Value shown</th>
          <th scope="col">NetBox (intended)</th>
          <th scope="col">Telemetry (discovered)</th>
        </tr>
      </thead>
      <tbody>
        {FIELD_ROWS.map(({ key, label }) => {
          const field = fields[key];
          return (
            <tr key={key}>
              <th scope="row">{label}</th>
              <td>
                <Reading value={field.value} /> <ProvenanceBadge provenance={field.provenance} />
              </td>
              <td>
                <Reading value={field.netbox} />
              </td>
              <td>
                <Reading value={field.discovered} />
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

export function InventoryDetailBody({ state }: { state: FetchState<InventoryDetail> }) {
  if (state.kind !== 'ok') {
    if (state.kind === 'forbidden') {
      return (
        <StateSurface
          icon="bi bi-shield-lock"
          title="Asset detail is not available to your role"
          detail="Reading one asset needs the inventory:read permission, which your role does not hold."
        />
      );
    }
    if (state.kind === 'not_found') {
      return (
        <StateSurface
          icon="bi bi-question-circle"
          title="Asset not found"
          detail="No asset with this identifier is in the current inventory. It may have been removed from NetBox, or it was only ever a discovery result that has gone."
        />
      );
    }
    return <DataFailure state={state} />;
  }
  const { data } = state;
  if (data.state !== 'ok' || data.item === null) {
    return (
      <div>
        <StoreStateSurface state={data.state === 'unknown' ? 'unknown' : 'not-connected'} noun="the asset" store="NetBox" />
        <SourceLine sources={data.sources} formatTime={formatUtcTimestamp} />
      </div>
    );
  }
  const item = data.item;
  return (
    <>
      <SourceNotices sources={data.sources} />
      <div className="row g-3">
        <div className="col-12 col-lg-7">
          <Card title="Fields and their provenance" icon="bi bi-journal-check" variant="outline" theme="primary" bodyClass="p-0">
            <FieldTable
              fields={{
                name: item.name,
                site: item.site,
                ip_address: item.ip_address,
                mac_address: item.mac_address,
              }}
            />
            <p className="small text-body-secondary px-3 py-2 mb-0">
              NetBox is the authority for intended state. Where telemetry reports a different value the
              NetBox value is shown and both readings are listed.
            </p>
          </Card>
        </div>
        <div className="col-12 col-lg-5">
          <Card title="Classification" icon="bi bi-tags" variant="outline" theme="secondary">
            <p className="mb-1">
              <ClassBadge value={item.asset_class} />{' '}
              <span className="visually-hidden">{classLabel(item.asset_class)}</span>
            </p>
            <p className="small text-body-secondary">{classBasisText(item.class_basis)}</p>
            <dl className="row small mb-0">
              <dt className="col-5">NetBox role</dt>
              <dd className="col-7 text-break">{item.role ?? NOT_REPORTED}</dd>
              <dt className="col-5">Device type</dt>
              <dd className="col-7 text-break">{item.device_type ?? NOT_REPORTED}</dd>
              <dt className="col-5">Intended status</dt>
              <dd className="col-7">{item.intended_status ?? NOT_REPORTED}</dd>
              <dt className="col-5">Observed status</dt>
              <dd className="col-7">
                {item.observed_status === null ? NOT_REPORTED : <StatusBadge status={item.observed_status} />}
              </dd>
            </dl>
          </Card>
          <Card title="Reconciliation" icon="bi bi-arrow-left-right" variant="outline" theme="secondary">
            <p className="mb-1">
              <ReconcileBadge status={item.reconcile.status} />
            </p>
            {item.reconcile.detail !== null ? (
              <p className="small mb-1 text-break">{item.reconcile.detail}</p>
            ) : null}
            <p className="small text-body-secondary mb-0">
              From the same comparison as the reconciliation findings; NetBox is never changed.
            </p>
          </Card>
          <Card title="Where this asset is known" icon="bi bi-database" variant="outline" theme="secondary">
            <ul className="mb-0">
              {item.sources.map((alias) => (
                <li key={alias.source}>
                  {sourceLabel(alias.source)}: <code className="text-break">{alias.native_id}</code>
                </li>
              ))}
            </ul>
          </Card>
        </div>
      </div>
      <Card title="Related views" icon="bi bi-link-45deg" variant="outline" theme="secondary">
        <ul className="list-unstyled small mb-0">
          <li className="mb-2">
            <Link href={`/devices/${encodeURIComponent(item.id)}`}>Open the monitored device record</Link>
            <span className="d-block text-body-secondary">Exists only where monitoring also knows this asset; otherwise it reports not found.</span>
          </li>
          <li className="mb-2">
            <Link href={`/network/map?focus=${encodeURIComponent(item.id)}`}>Show on network map</Link>
            <span className="d-block text-body-secondary">Selects the asset when the topology source reports it.</span>
          </li>
          {item.ip_address.value !== null ? (
            <li className="mb-2">
              <Link href={`/traffic/flows?source_ip=${encodeURIComponent(item.ip_address.value)}`}>
                Flows from {item.ip_address.value}
              </Link>
              <span className="d-block text-body-secondary">Flow Explorer filtered to this address; an address is not an identity.</span>
            </li>
          ) : null}
          <li>
            <Link href="/ipam">IP address management</Link>
            <span className="d-block text-body-secondary">Prefixes and address usage; not filtered to this asset.</span>
          </li>
        </ul>
      </Card>
      <p className="mt-3">
        <Link href="/inventory">
          <i className="bi bi-arrow-left me-1" aria-hidden="true" />
          Back to the inventory
        </Link>
      </p>
      <SourceLine sources={data.sources} formatTime={formatUtcTimestamp} />
    </>
  );
}
