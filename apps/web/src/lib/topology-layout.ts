import type { TopologyResponse } from './api-contracts.ts';

export const NODE_W = 150;
export const NODE_H = 44;
const LAYER_GAP = 110;
const NODE_GAP = 32;
export const MIN_SCALE = 0.3;
export const MAX_SCALE = 2.5;

export interface Positioned {
  id: string;
  name: string;
  x: number;
  y: number;
}

export interface CanvasState {
  scale: number;
  offsetX: number;
  offsetY: number;
}

/** Deterministic layered layout: BFS layers per connected component. */
export function layout(topology: TopologyResponse): Positioned[] {
  const adjacency = new Map<string, Set<string>>();
  for (const node of topology.nodes) adjacency.set(node.device_id, new Set());
  for (const edge of topology.edges) {
    adjacency.get(edge.source_device_id)?.add(edge.target_device_id);
    adjacency.get(edge.target_device_id)?.add(edge.source_device_id);
  }

  const names = new Map(topology.nodes.map((n) => [n.device_id, n.name]));
  const placed: Positioned[] = [];
  const seen = new Set<string>();
  let originY = 0;

  const sortedIds = [...adjacency.keys()].sort();
  for (const root of sortedIds) {
    if (seen.has(root)) continue;
    // BFS layers from the highest-degree unvisited node in this component.
    const component: string[] = [];
    const queue = [root];
    seen.add(root);
    while (queue.length > 0) {
      const current = queue.shift() as string;
      component.push(current);
      for (const neighbour of [...(adjacency.get(current) ?? [])].sort()) {
        if (!seen.has(neighbour)) {
          seen.add(neighbour);
          queue.push(neighbour);
        }
      }
    }
    const degree = (id: string) => adjacency.get(id)?.size ?? 0;
    const start = component.reduce((best, id) =>
      degree(id) > degree(best) ? id : best,
    );
    const layers: string[][] = [];
    const layerOf = new Map<string, number>([[start, 0]]);
    const layerQueue = [start];
    while (layerQueue.length > 0) {
      const current = layerQueue.shift() as string;
      const depth = layerOf.get(current) as number;
      const next = (layers[depth] ??= []);
      if (!next.includes(current)) next.push(current);
      for (const neighbour of [...(adjacency.get(current) ?? [])].sort()) {
        if (layerOf.get(neighbour) === undefined) {
          layerOf.set(neighbour, depth + 1);
          layerQueue.push(neighbour);
        }
      }
    }
    layers.forEach((layer, depth) => {
      layer.sort();
      const width = layer.length * (NODE_W + NODE_GAP) - NODE_GAP;
      layer.forEach((id, index) => {
        placed.push({
          id,
          name: names.get(id) ?? id,
          x: index * (NODE_W + NODE_GAP) - width / 2,
          y: originY + depth * (NODE_H + LAYER_GAP),
        });
      });
    });
    originY += (Math.max(layers.length, 1) - 1) * (NODE_H + LAYER_GAP) + NODE_H + 90;
  }
  return placed;
}

export function bounds(positions: Positioned[]) {
  if (positions.length === 0) return { minX: -200, minY: -80, maxX: 200, maxY: 80 };
  return positions.reduce(
    (box, p) => ({
      minX: Math.min(box.minX, p.x),
      minY: Math.min(box.minY, p.y),
      maxX: Math.max(box.maxX, p.x + NODE_W),
      maxY: Math.max(box.maxY, p.y + NODE_H),
    }),
    { minX: Infinity, minY: Infinity, maxX: -Infinity, maxY: -Infinity },
  );
}


export const VIEW_W = 960;
export const VIEW_H = 520;

function clampScale(scale: number): number {
  return Math.min(Math.max(scale, MIN_SCALE), MAX_SCALE);
}

/** The view that fits the whole graph with a margin; never zoomed in past 150%. */
export function fitView(box: ReturnType<typeof bounds>): CanvasState {
  const width = box.maxX - box.minX + 80;
  const height = box.maxY - box.minY + 80;
  const scale = Math.min(Math.max(Math.min(VIEW_W / width, VIEW_H / height), MIN_SCALE), 1.5);
  return {
    scale,
    offsetX: -box.minX * scale + (VIEW_W - width * scale) / 2 + 40 * scale,
    offsetY: -box.minY * scale + (VIEW_H - height * scale) / 2 + 40 * scale,
  };
}

/** The same scale with the node's centre at the middle of the canvas. */
export function centreOn(node: Positioned, scale: number): CanvasState {
  const next = clampScale(scale);
  return {
    scale: next,
    offsetX: VIEW_W / 2 - (node.x + NODE_W / 2) * next,
    offsetY: VIEW_H / 2 - (node.y + NODE_H / 2) * next,
  };
}

export function zoomAround(view: CanvasState, factor: number): CanvasState {
  const scale = clampScale(view.scale * factor);
  const ratio = scale / view.scale;
  return {
    scale,
    offsetX: VIEW_W / 2 - (VIEW_W / 2 - view.offsetX) * ratio,
    offsetY: VIEW_H / 2 - (VIEW_H / 2 - view.offsetY) * ratio,
  };
}
