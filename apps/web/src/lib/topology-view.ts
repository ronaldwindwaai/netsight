import type { TopologyEdgeSource, TopologyNode, TopologyResponse } from './api-contracts.ts';

const DEVICE_ID = /^device-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const MAX_SEARCH = 64;

export interface Neighbour {
  deviceId: string;
  name: string;
  source: TopologyEdgeSource;
  observedAt: string | null;
}

export function nodeLabel(node: Pick<TopologyNode, 'device_id' | 'name'>): string {
  return node.name ?? node.device_id;
}

/** Every explicit link that touches a node, seen from that node; links to unknown nodes are skipped. */
export function neighboursOf(topology: TopologyResponse, deviceId: string): Neighbour[] {
  const labels = new Map(topology.nodes.map((node) => [node.device_id, nodeLabel(node)]));
  return topology.edges.flatMap((edge) => {
    const other =
      edge.source_device_id === deviceId
        ? edge.target_device_id
        : edge.target_device_id === deviceId
          ? edge.source_device_id
          : null;
    const name = other === null ? undefined : labels.get(other);
    if (other === null || name === undefined) return [];
    return [{ deviceId: other, name, source: edge.source, observedAt: edge.observed_at }];
  });
}

/** Case-insensitive match on the name or id; an empty query matches nothing (it is "no search"). */
export function matchNodes(nodes: readonly TopologyNode[], query: string): TopologyNode[] {
  const needle = query.trim().slice(0, MAX_SEARCH).toLocaleLowerCase();
  if (needle.length === 0) return [];
  return nodes.filter((node) =>
    [node.name, node.device_id].some((value) => value?.toLocaleLowerCase().includes(needle)),
  );
}

/** A focus parameter is only honoured when it names a node of this graph. */
export function resolveFocus(raw: string | string[] | undefined, topology: TopologyResponse): string | null {
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (typeof value !== 'string' || !DEVICE_ID.test(value)) return null;
  return topology.nodes.some((node) => node.device_id === value) ? value : null;
}

export function reconciliationText(node: TopologyNode): string {
  if (node.finding !== null) {
    return node.finding.kind === 'missing-discovered'
      ? 'Finding: intended in NetBox but not discovered'
      : 'Finding: intended and observed status disagree';
  }
  return node.reconciled ? 'Checked, no findings' : 'Not checked (discovery source unavailable)';
}
