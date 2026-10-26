import type { TopologyResponse } from './api-contracts.ts';
import type { FetchState } from './api-response.ts';

export type OverviewTopology =
  | { kind: 'graph'; topology: TopologyResponse }
  | { kind: 'surface'; title: string; detail: string };

/**
 * What the overview's map card shows. The graph is drawn only from an explicit `ok` topology with
 * nodes; every other state keeps its own wording, so "not connected", "could not be read" and
 * "nothing reported" are never shown as one another or as an empty map.
 */
export function overviewTopology(state: FetchState<TopologyResponse>): OverviewTopology {
  if (state.kind !== 'ok') {
    return {
      kind: 'surface',
      title: 'Topology could not be read',
      detail: 'The topology request failed. Open the network map for the reason.',
    };
  }
  const topology = state.data;
  if (topology.state === 'not-connected') {
    return {
      kind: 'surface',
      title: 'Topology is not yet connected',
      detail: 'Connect and reconcile a topology source before Netsight can draw network relationships.',
    };
  }
  if (topology.state === 'unknown') {
    return {
      kind: 'surface',
      title: 'Topology is unknown',
      detail: 'The topology source is configured but could not be read, so nothing is drawn.',
    };
  }
  if (topology.nodes.length === 0) {
    return {
      kind: 'surface',
      title: 'No explicit links reported',
      detail: 'The topology source answered but reported no devices with links.',
    };
  }
  return { kind: 'graph', topology };
}
