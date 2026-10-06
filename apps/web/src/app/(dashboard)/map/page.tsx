import { AppContent, Card } from '@adminlte/react';

import { DataFailure, FreshnessNotice } from '@/components/data-state';
import { apiGet } from '@/lib/api';
import { parseTopologyResponse, type TopologyResponse } from '@/lib/api-contracts';

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

function GraphEvidence({ topology }: { topology: TopologyResponse }) {
  return (
    <>
      <div className="d-flex flex-wrap gap-2 mb-3" aria-label="Topology nodes">
        {topology.nodes.map((node) => (
          <span key={node.device_id} className="badge bg-secondary-subtle text-body border">
            <i className="bi bi-hdd-network me-1" aria-hidden="true" />
            {node.device_id}
          </span>
        ))}
      </div>
      <Card title="Explicit links" icon="bi bi-diagram-3" variant="outline" theme="primary" bodyClass="p-0">
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
                topology.edges.map((edge) => (
                  <tr key={`${edge.source_device_id}->${edge.target_device_id}:${edge.source}`}>
                    <td>{edge.source_device_id}</td>
                    <td>{edge.target_device_id}</td>
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
      </Card>
    </>
  );
}

export default async function MapPage() {
  const state = await apiGet('/api/v1/topology', parseTopologyResponse);
  const topology = state.kind === 'ok' ? state.data : null;

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

      <Card
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
          <GraphEvidence topology={topology} />
        )}
      </Card>
    </AppContent>
  );
}
