import { Alert, Card, Table } from '@adminlte/react';
import type { TableColumn } from '@adminlte/react';
import Link from 'next/link';
import { DataFailure } from '@/components/data-state';
import { Pager } from '@/components/pager';
import { StateSurface, StoreStateSurface } from '@/components/state-surface';
import type { ConfigurationNode, ConfigurationRead, ConfigurationVersion } from '@/lib/api-contracts-configuration';
import type { FetchState } from '@/lib/api-response';
import { formatUtcTimestamp } from '@/lib/format-time';

type Row = ConfigurationNode | ConfigurationVersion;
export function ConfigurationSurface<T extends Row>({ state, children, baseHref = "/config" }: {
  state: FetchState<ConfigurationRead<T>>; children: React.ReactNode; baseHref?: string;
}) {
  if (state.kind !== 'ok') return <DataFailure state={state} />;
  const data = state.data;
  if (data.state === 'unknown' || data.state === 'not-connected') return <StoreStateSurface state={data.state} noun="configuration backups" store="Oxidized" />;
  const pageHref = (page: number) => `${baseHref}${baseHref.includes("?") ? "&" : "?"}page=${page}`;
  return <>
    <p className="small text-body-secondary">Source: Oxidized · Read at {formatUtcTimestamp(data.observed_at!)}</p>
    {data.state === 'partial' ? <Alert theme="warning" title="Incomplete source data">{data.skipped} source rows could not be used. {data.truncated ? 'The source exceeds the 2,000-row limit.' : 'Other rows are shown below.'}</Alert> : null}
    {data.items.length === 0 ? <StateSurface icon="bi bi-archive" title="No backup records" detail="Oxidized returned no records for this read. This does not establish that device configuration is healthy." /> : children}
    <Pager label="Configuration pages" hrefs={{previous: data.page > 1 ? pageHref(data.page - 1) : null, next: data.has_more ? pageHref(data.page + 1) : null}} />
  </>;
}
const nodeColumns: TableColumn<ConfigurationNode>[] = [
  { key: 'name', header: 'Device', render: item => <Link href={`/config/changes?node=${encodeURIComponent(item.id)}`}>{item.name}</Link> },
  { key: 'group', header: 'Group', render: item => item.group ?? 'Not reported' },
  { key: 'model', header: 'Model', render: item => item.model ?? 'Not reported' },
  { key: 'backup_status', header: 'Last attempt', render: item => <span>{item.backup_status}</span> },
  { key: 'last_attempt_at', header: 'Attempt time', render: item => item.last_attempt_at ? formatUtcTimestamp(item.last_attempt_at) : 'Not reported' },
  { key: 'backup_freshness', header: 'Backup freshness', render: item => <span>{item.backup_freshness}</span> },
];
const versionColumns: TableColumn<ConfigurationVersion>[] = [
  { key: 'id', header: 'Version', render: item => <code className="text-break">{item.id}</code> },
  { key: 'saved_at', header: 'Saved at', render: item => formatUtcTimestamp(item.saved_at) },
];
export function ConfigurationNodesBody({ state }: { state: FetchState<ConfigurationRead<ConfigurationNode>> }) {
  return <Card title="Configuration backups"><ConfigurationSurface state={state}>
    {state.kind === 'ok' ? <>
      {state.data.items.some(i => i.backup_freshness === 'stale') ? <Alert theme="warning" title="Stale backups">At least one successful backup is older than 24 hours. Live configuration may differ.</Alert> : null}
      <div className="d-none d-md-block"><Table columns={nodeColumns} data={state.data.items} rowKey={item => item.id} /></div>
      <ul className="list-group list-group-flush d-md-none" aria-label="Configuration backups">
        {state.data.items.map(item => <li className="list-group-item px-0" key={item.id}>
          <Link href={`/config/changes?node=${encodeURIComponent(item.id)}`}>{item.name}</Link>
          <dl className="row small mt-2 mb-0">
            <dt className="col-5">Group / model</dt><dd className="col-7 text-break">{item.group ?? 'Not reported'} / {item.model ?? 'Not reported'}</dd>
            <dt className="col-5">Last attempt</dt><dd className="col-7">{item.backup_status}</dd>
            <dt className="col-5">Attempt time</dt><dd className="col-7">{item.last_attempt_at ? formatUtcTimestamp(item.last_attempt_at) : 'Not reported'}</dd>
            <dt className="col-5">Freshness</dt><dd className="col-7">{item.backup_freshness}</dd>
          </dl>
        </li>)}
      </ul>
    </> : null}
  </ConfigurationSurface></Card>;
}
export function ConfigurationVersionsBody({ state, nodeId }: { state: FetchState<ConfigurationRead<ConfigurationVersion>>; nodeId: string }) {
  return <Card title="Saved versions"><ConfigurationSurface state={state} baseHref={`/config/changes?node=${encodeURIComponent(nodeId)}`}>
    {state.kind === 'ok' ? <>
      <div className="d-none d-md-block"><Table columns={versionColumns} data={state.data.items} rowKey={item => item.id} /></div>
      <ol className="list-group list-group-flush d-md-none" aria-label="Saved configuration versions">
        {state.data.items.map(item => <li className="list-group-item px-0" key={item.id}>
          <code className="d-block text-break">{item.id}</code>
          <span className="small text-body-secondary">Saved at {formatUtcTimestamp(item.saved_at)}</span>
        </li>)}
      </ol>
    </> : null}
  </ConfigurationSurface></Card>;
}
