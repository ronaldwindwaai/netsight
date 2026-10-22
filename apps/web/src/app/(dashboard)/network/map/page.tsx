import { AppCard } from '@/components/app-card';
import { AppContent } from '@/components/app-content';

import { DataFailure, FreshnessNotice } from '@/components/data-state';
import { TopologyView } from '@/components/topology-graph';
import { apiGet } from '@/lib/api';
import { parseTopologyResponse, type TopologyResponse } from '@/lib/api-contracts';
import { resolveFocus } from '@/lib/topology-view';

function EmptySurface({
  icon,
  title,
  detail,
}: {
  icon: string;
  title: string;
  detail: string;
}) {
  return (
    <div className="text-center py-5">
      <i className={`bi ${icon} fs-2 text-body-secondary`} aria-hidden="true" />
      <h2 className="h5 mt-3">{title}</h2>
      <p className="mb-0 text-body-secondary">{detail}</p>
    </div>
  );
}

function GraphEvidence({ topology, focus }: { topology: TopologyResponse; focus: string | null }) {
  const labels = new Map(
    topology.nodes.map((node) => [node.device_id, node.name ?? node.device_id]),
  );
  const label = (deviceId: string) => labels.get(deviceId) ?? deviceId;
  const reconciled = topology.nodes.every((node) => node.reconciled);
  const findings = topology.nodes.filter((node) => node.finding !== null);
  const reconciliationNote = (node: (typeof topology.nodes)[number]) => {
    if (node.finding) return `reconciliation: ${node.finding.kind}`;
    return reconciled ? 'reconciliation: checked, no findings' : 'reconciliation: not checked';
  };
  return (
    <>
      <TopologyView topology={topology} focus={focus} />
      <div className="d-flex flex-wrap gap-2 mb-3" role="list" aria-label="Topology nodes">
        {topology.nodes.map((node) => (
          <span
            key={node.device_id}
            role="listitem"
            className="badge bg-secondary-subtle text-body border"
            title={`${node.device_id} — ${reconciliationNote(node)}`}
          >
            <i className="bi bi-hdd-network me-1" aria-hidden="true" />
            {node.name ?? node.device_id}
            {node.finding ? (
              <i
                className="bi bi-exclamation-triangle text-warning ms-1"
                aria-hidden="true"
              />
            ) : null}
          </span>
        ))}
      </div>
      {!reconciled ? (
        <p className="small text-body-secondary">
          <i className="bi bi-info-circle me-1" aria-hidden="true" />
          Reconciliation not checked: the discovery source was unavailable, so no
          intent-vs-discovery findings are shown for this graph.
        </p>
      ) : findings.length > 0 ? (
        <div className="mb-3" role="status" aria-label="Reconciliation findings">
          <p className="small text-warning mb-1">
            <i className="bi bi-exclamation-triangle me-1" aria-hidden="true" />
            Reconciliation findings on this graph:
          </p>
          <ul className="list-unstyled small mb-0">
            {findings.map((node) => (
              <li key={node.device_id} className="mb-1">
                <span title={node.device_id} className="fw-semibold">
                  {node.name ?? node.device_id}
                </span>
                {': '}
                <span className="text-body-secondary">{node.finding?.detail}</span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      <AppCard title="Explicit links" icon="bi bi-diagram-3" variant="outline" theme="primary" bodyClass="p-0">
        <div className="table-responsive">
          <table className="table table-sm mb-0">
            <thead>
              <tr>
                <th scope="col">Source device</th>
                <th scope="col">Target device</th>
                <th scope="col">Link evidence</th>
                <th scope="col">Observed</th>
              </tr>
            </thead>
            <tbody>
              {topology.edges.length === 0 ? (
                <tr>
                  <td colSpan={4} className="text-body-secondary">
                    No explicit links reported by the connected topology source.
                  </td>
                </tr>
              ) : (
                topology.edges.map((edge, index) => (
                  <tr key={`${index}:${edge.source_device_id}->${edge.target_device_id}:${edge.source}`}>
                    <td>
                      <span title={edge.source_device_id}>{label(edge.source_device_id)}</span>
                    </td>
                    <td>
                      <span title={edge.target_device_id}>{label(edge.target_device_id)}</span>
                    </td>
                    <td>
                      <span className="badge bg-info-subtle text-info-emphasis border">
                        {edge.source.toUpperCase()}
                      </span>
                    </td>
                    <td className="text-body-secondary">
                      {edge.observed_at ?? 'observation time unknown'}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </AppCard>
    </>
  );
}

export default async function MapPage({
  searchParams,
}: {
  searchParams: Promise<{ focus?: string | string[] }>;
}) {
  const state = await apiGet('/api/v1/topology', parseTopologyResponse);
  const topology = state.kind === 'ok' ? state.data : null;
  const focus = topology === null ? null : resolveFocus((await searchParams).focus, topology);

  return (
    <AppContent
      title="Live network map"
      breadcrumbs={[{ label: 'Overview', href: '/overview' }, { label: 'Map' }]}
    >
      <div className="page-intro">
        <p className="text-body-secondary mb-0">
          Only explicitly reported links (LLDP/CDP/routing/switching/NetBox/manual) are drawn.
          Netsight never infers connections it cannot evidence.
        </p>
      </div>

      {state.kind !== 'ok' ? <DataFailure state={state} /> : null}
      {topology ? <FreshnessNotice freshness={topology.freshness} /> : null}

      <AppCard
        className="operational-card operational-card--primary"
        title="Topology"
        icon="bi bi-diagram-3"
        variant="outline"
        theme="primary"
        tools={
          topology ? (
            <span className="badge bg-secondary-subtle text-body border">{topology.state}</span>
          ) : null
        }
      >
        {topology === null ? (
          <EmptySurface
            icon="bi-cloud-slash"
            title="Topology unavailable"
            detail="The topology surface cannot be shown until the API responds with a canonical graph state."
          />
        ) : topology.state === 'not-connected' ? (
          <EmptySurface
            icon="bi-bezier2"
            title="Topology source not connected"
            detail="Connect and reconcile a topology source (LLDP/CDP/NetBox cables) before Netsight can draw network relationships."
          />
        ) : topology.state === 'unknown' ? (
          <EmptySurface
            icon="bi-question-circle"
            title="Topology state unknown"
            detail="A topology source is configured but its current state could not be confirmed. No graph is drawn."
          />
        ) : (
          <GraphEvidence topology={topology} focus={focus} />
        )}
      </AppCard>
    </AppContent>
  );
}
