import Link from 'next/link';

import type { TopologyNode, TopologyResponse } from '@/lib/api-contracts';
import { itemHref } from '@/lib/inventory-view';
import { neighboursOf, nodeLabel, reconciliationText } from '@/lib/topology-view';

export function TopologyLegend() {
  return (
    <ul className="topology-legend list-inline small text-body-secondary mb-2" aria-label="Map legend">
      <li className="list-inline-item">
        <svg aria-hidden="true" width="22" height="14">
          <rect x="1" y="1" width="20" height="12" rx="3" className="topology-node" strokeWidth="1" />
        </svg>{' '}
        Device
      </li>
      <li className="list-inline-item">
        <svg aria-hidden="true" width="22" height="14">
          <line x1="0" y1="7" x2="22" y2="7" className="topology-edge" strokeWidth="2" />
        </svg>{' '}
        Explicit link reported by a source
      </li>
      <li className="list-inline-item">
        <svg aria-hidden="true" width="22" height="14">
          <rect x="1" y="1" width="20" height="12" rx="3" className="topology-node topology-node--finding" strokeWidth="1.5" />
        </svg>{' '}
        Dashed outline with warning mark: reconciliation finding
      </li>
      <li className="list-inline-item">
        <svg aria-hidden="true" width="22" height="14">
          <rect x="1" y="1" width="20" height="12" rx="3" className="topology-node topology-node--selected" strokeWidth="2" />
        </svg>{' '}
        Selected
      </li>
      <li className="list-inline-item">
        Device health is not drawn: the topology source reports links, not status.
      </li>
    </ul>
  );
}

export function TopologySidePanel({
  topology,
  node,
  onSelect,
  onClear,
}: {
  topology: TopologyResponse;
  node: TopologyNode | null;
  onSelect: (deviceId: string) => void;
  onClear: () => void;
}) {
  if (node === null) {
    return (
      <aside aria-label="Selected device" className="topology-panel border rounded p-3 small text-body-secondary">
        <i className="bi bi-cursor me-1" aria-hidden="true" />
        Select a device (click it, or focus it and press Enter) to see its links and open it. Press
        Escape to clear.
      </aside>
    );
  }
  const neighbours = neighboursOf(topology, node.device_id);
  return (
    <aside aria-label="Selected device" className="topology-panel border rounded p-3 small">
      <div className="d-flex justify-content-between align-items-start gap-2">
        <h3 className="h6 mb-1 text-break">{nodeLabel(node)}</h3>
        <button type="button" className="btn-close" aria-label="Clear selection" onClick={onClear} />
      </div>
      <p className="mb-2 text-body-secondary text-break">
        <code>{node.device_id}</code>
      </p>
      <p className="mb-2">
        <span className="fw-semibold">Reconciliation: </span>
        {reconciliationText(node)}
        {node.finding ? <span className="d-block text-body-secondary text-break">{node.finding.detail}</span> : null}
      </p>
      <p className="fw-semibold mb-1">
        {neighbours.length} explicit {neighbours.length === 1 ? 'link' : 'links'}
      </p>
      {neighbours.length === 0 ? (
        <p className="text-body-secondary">No source reports a link for this device. It is not inferred.</p>
      ) : (
        <ul className="list-unstyled mb-2">
          {neighbours.map((n, index) => (
            <li key={`${index}:${n.deviceId}`} className="mb-1">
              <button type="button" className="btn btn-link btn-sm p-0 text-start text-break" onClick={() => onSelect(n.deviceId)}>
                {n.name}
              </button>{' '}
              <span className="badge bg-info-subtle text-info-emphasis border">{n.source.toUpperCase()}</span>
              <span className="d-block text-body-secondary">{n.observedAt ?? 'observation time unknown'}</span>
            </li>
          ))}
        </ul>
      )}
      <div className="d-flex flex-wrap gap-2">
        <Link className="btn btn-sm btn-outline-primary" href={`/devices/${encodeURIComponent(node.device_id)}`}>
          <i className="bi bi-hdd-network me-1" aria-hidden="true" />
          Open device
        </Link>
        <Link className="btn btn-sm btn-outline-secondary" href={itemHref(node.device_id)}>
          <i className="bi bi-boxes me-1" aria-hidden="true" />
          Inventory
        </Link>
      </div>
    </aside>
  );
}
