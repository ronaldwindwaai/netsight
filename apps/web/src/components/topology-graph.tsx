'use client';

import { useCallback, useMemo, useRef, useState } from 'react';

import type { TopologyResponse } from '@/lib/api-contracts';

/**
 * Explicit-link topology canvas.
 *
 * Only the edges the source reported are drawn — layout never invents a
 * relationship. The adjacent rendered link table remains the accessible
 * text equivalent; this canvas carries a summary label for screen readers.
 */

const NODE_W = 150;
const NODE_H = 44;
const LAYER_GAP = 110;
const NODE_GAP = 32;
const MIN_SCALE = 0.3;
const MAX_SCALE = 2.5;

interface Positioned {
  id: string;
  name: string;
  x: number;
  y: number;
}

interface CanvasState {
  scale: number;
  offsetX: number;
  offsetY: number;
}

/** Deterministic layered layout: BFS layers per connected component. */
function layout(topology: TopologyResponse): Positioned[] {
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

function bounds(positions: Positioned[]) {
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

export function TopologyGraph({ topology }: { topology: TopologyResponse }) {
  const positions = useMemo(() => layout(topology), [topology]);
  const box = useMemo(() => bounds(positions), [positions]);

  const [view, setView] = useState<CanvasState>({ scale: 1, offsetX: 0, offsetY: 0 });
  const [selected, setSelected] = useState<string | null>(null);
  const dragRef = useRef<{ x: number; y: number; ox: number; oy: number } | null>(null);
  const frameRef = useRef<number | null>(null);

  const fit = useCallback(() => {
    const width = box.maxX - box.minX + 80;
    const height = box.maxY - box.minY + 80;
    const scale = Math.min(Math.max(Math.min(960 / width, 520 / height), MIN_SCALE), 1.5);
    setView({
      scale,
      offsetX: -box.minX * scale + (960 - width * scale) / 2 + 40 * scale,
      offsetY: -box.minY * scale + (520 - height * scale) / 2 + 40 * scale,
    });
  }, [box]);

  const zoom = useCallback((factor: number) => {
    setView((current) => {
      const scale = Math.min(Math.max(current.scale * factor, MIN_SCALE), MAX_SCALE);
      // Zoom towards the canvas centre.
      const ratio = scale / current.scale;
      return {
        scale,
        offsetX: 480 - (480 - current.offsetX) * ratio,
        offsetY: 260 - (260 - current.offsetY) * ratio,
      };
    });
  }, []);

  const onPointerDown = (event: React.PointerEvent<SVGSVGElement>) => {
    event.currentTarget.setPointerCapture(event.pointerId);
    dragRef.current = {
      x: event.clientX,
      y: event.clientY,
      ox: view.offsetX,
      oy: view.offsetY,
    };
  };

  const onPointerMove = (event: React.PointerEvent<SVGSVGElement>) => {
    const drag = dragRef.current;
    if (!drag) return;
    const dx = event.clientX - drag.x;
    const dy = event.clientY - drag.y;
    if (frameRef.current !== null) cancelAnimationFrame(frameRef.current);
    frameRef.current = requestAnimationFrame(() =>
      setView((current) => ({ ...current, offsetX: drag.ox + dx, offsetY: drag.oy + dy })),
    );
  };

  const onPointerUp = (event: React.PointerEvent<SVGSVGElement>) => {
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
    dragRef.current = null;
  };

  const onWheel = (event: React.WheelEvent<SVGSVGElement>) => {
    zoom(event.deltaY < 0 ? 1.12 : 1 / 1.12);
  };

  if (topology.nodes.length === 0) return null;

  const byId = new Map(positions.map((p) => [p.id, p]));
  const edges = topology.edges.flatMap((edge, index) => {
    const from = byId.get(edge.source_device_id);
    const to = byId.get(edge.target_device_id);
    if (!from || !to) return [];
    return [
      {
        key: `${index}:${edge.source_device_id}->${edge.target_device_id}`,
        x1: from.x + NODE_W / 2,
        y1: from.y + NODE_H / 2,
        x2: to.x + NODE_W / 2,
        y2: to.y + NODE_H / 2,
        label: `${edge.source.toUpperCase()} link${
          edge.observed_at ? ` observed ${edge.observed_at}` : ' (observation time unknown)'
        }`,
      },
    ];
  });

  return (
    <div className="topology-canvas border rounded mb-3" style={{ position: 'relative' }}>
      <div className="btn-group position-absolute m-2" style={{ zIndex: 1 }}>
        <button
          type="button"
          className="btn btn-sm btn-light border"
          onClick={() => zoom(1.2)}
          aria-label="Zoom in"
        >
          <i className="bi bi-plus-lg" aria-hidden="true" />
        </button>
        <button
          type="button"
          className="btn btn-sm btn-light border"
          onClick={() => zoom(1 / 1.2)}
          aria-label="Zoom out"
        >
          <i className="bi bi-dash-lg" aria-hidden="true" />
        </button>
        <button
          type="button"
          className="btn btn-sm btn-light border"
          onClick={fit}
          aria-label="Fit graph to view"
        >
          <i className="bi bi-arrows-angle-expand" aria-hidden="true" />
        </button>
      </div>
      <span className="badge bg-secondary-subtle text-body border position-absolute m-2 end-0">
        {Math.round(view.scale * 100)}%
      </span>
      <svg
        viewBox="0 0 960 520"
        role="img"
        aria-label={`Topology graph with ${topology.nodes.length} nodes and ${edges.length} explicit links`}
        style={{ width: '100%', height: 'auto', cursor: 'grab', touchAction: 'none' }}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onWheel={onWheel}
      >
        <g transform={`translate(${view.offsetX} ${view.offsetY}) scale(${view.scale})`}>
          {edges.map((edge) => (
            <g key={edge.key}>
              <line
                x1={edge.x1}
                y1={edge.y1}
                x2={edge.x2}
                y2={edge.y2}
                className="topology-edge"
                strokeWidth={2}
              >
                <title>{edge.label}</title>
              </line>
            </g>
          ))}
          {positions.map((node) => {
            const isSelected = selected === node.id;
            return (
              <g
                key={node.id}
                transform={`translate(${node.x} ${node.y})`}
                onPointerUp={() => setSelected((current) => (current === node.id ? null : node.id))}
                style={{ cursor: 'pointer' }}
              >
                <title>{node.id}</title>
                <rect
                  width={NODE_W}
                  height={NODE_H}
                  rx={6}
                  className={`topology-node${isSelected ? ' topology-node--selected' : ''}`}
                  strokeWidth={isSelected ? 2 : 1}
                />
                <text
                  x={NODE_W / 2}
                  y={NODE_H / 2 + 1}
                  textAnchor="middle"
                  dominantBaseline="middle"
                  className="topology-node__label"
                  fontSize={12}
                >
                  {node.name.length > 20 ? `${node.name.slice(0, 19)}…` : node.name}
                </text>
              </g>
            );
          })}
        </g>
      </svg>
    </div>
  );
}
