'use client';

import { useMemo, useRef, useState } from 'react';
import type { KeyboardEvent, PointerEvent, WheelEvent } from 'react';

import { TopologyLegend, TopologySidePanel } from '@/components/topology-side-panel';
import type { TopologyResponse } from '@/lib/api-contracts';
import {
  NODE_H,
  NODE_W,
  bounds,
  centreOn,
  fitView,
  isVisible,
  layout,
  zoomAround,
  VIEW_H,
  VIEW_W,
} from '@/lib/topology-layout';
import type { CanvasState, Positioned } from '@/lib/topology-layout';
import { matchNodes, neighboursOf, nodeLabel, reconciliationText } from '@/lib/topology-view';

/**
 * Explicit-link topology canvas.
 *
 * Only the edges the source reported are drawn; layout never invents a relationship. The rendered
 * link table beside it stays the text equivalent. Nodes are keyboard operable (Tab, Enter/Space,
 * Escape), the canvas pans with the arrow keys and zooms with + and -, and selection opens a side
 * panel with the device's links and its drill-downs.
 */

const PAN_STEP = 48;
const WHEEL_ZOOM = 1.12;
const BUTTON_ZOOM = 1.2;
const DRAG_THRESHOLD_PX = 4;

interface Drag {
  x: number;
  y: number;
  ox: number;
  oy: number;
}

function truncated(name: string): string {
  return name.length > 20 ? `${name.slice(0, 19)}…` : name;
}

function nodeClass(selected: boolean, finding: boolean, dim: boolean, match: boolean): string {
  return [
    'topology-node',
    selected ? 'topology-node--selected' : '',
    finding ? 'topology-node--finding' : '',
    dim ? 'topology-node--dim' : '',
    match ? 'topology-node--match' : '',
  ]
    .filter(Boolean)
    .join(' ');
}

function ZoomControls({
  scale,
  onZoom,
  onFit,
}: {
  scale: number;
  onZoom: (factor: number) => void;
  onFit: () => void;
}) {
  return (
    <div className="d-flex align-items-center gap-2">
      <div className="btn-group" role="group" aria-label="Zoom controls">
        <button type="button" className="btn btn-sm btn-outline-secondary" onClick={() => onZoom(BUTTON_ZOOM)} aria-label="Zoom in">
          <i className="bi bi-plus-lg" aria-hidden="true" />
        </button>
        <button type="button" className="btn btn-sm btn-outline-secondary" onClick={() => onZoom(1 / BUTTON_ZOOM)} aria-label="Zoom out">
          <i className="bi bi-dash-lg" aria-hidden="true" />
        </button>
        <button type="button" className="btn btn-sm btn-outline-secondary" onClick={onFit} aria-label="Fit graph to view">
          <i className="bi bi-arrows-angle-expand" aria-hidden="true" />
        </button>
      </div>
      <span className="badge bg-secondary-subtle text-body border" aria-label={`Zoom ${Math.round(scale * 100)} percent`}>
        {Math.round(scale * 100)}%
      </span>
    </div>
  );
}

/**
 * The graph for a given `?focus=`. The focus is only the initial selection, so a change of focus on
 * client navigation (same page, new query) must remount the graph or the new focus would be ignored.
 */
export function TopologyView({ topology, focus }: { topology: TopologyResponse; focus: string | null }) {
  return <TopologyGraph key={focus ?? 'none'} topology={topology} initialSelected={focus} />;
}

export function TopologyGraph({
  topology,
  initialSelected = null,
}: {
  topology: TopologyResponse;
  initialSelected?: string | null;
}) {
  const positions = useMemo(() => layout(topology), [topology]);
  const box = useMemo(() => bounds(positions), [positions]);
  const byId = useMemo(() => new Map(positions.map((p) => [p.id, p])), [positions]);
  const nodesById = useMemo(() => new Map(topology.nodes.map((n) => [n.device_id, n])), [topology]);

  const [selected, setSelected] = useState<string | null>(initialSelected);
  const [query, setQuery] = useState('');
  const [view, setView] = useState<CanvasState>(() => {
    const focus = initialSelected === null ? undefined : byId.get(initialSelected);
    return focus ? centreOn(focus, 1) : fitView(box);
  });
  const dragRef = useRef<Drag | null>(null);
  // True once the current press has travelled past the drag threshold, so the click that follows a
  // pan is not read as selecting the node under the pointer. Reset on every pointer-down.
  const movedRef = useRef(false);

  const matches = useMemo(() => new Set(matchNodes(topology.nodes, query).map((n) => n.device_id)), [topology, query]);
  const searching = query.trim().length > 0;
  const adjacent = useMemo(
    () => (selected === null ? new Set<string>() : new Set(neighboursOf(topology, selected).map((n) => n.deviceId))),
    [topology, selected],
  );

  if (topology.nodes.length === 0) return null;

  const select = (deviceId: string, centre = false) => {
    setSelected(deviceId);
    const target = byId.get(deviceId);
    if (centre && target) setView((current) => centreOn(target, current.scale));
  };
  const toggle = (deviceId: string) => (selected === deviceId ? setSelected(null) : select(deviceId));

  const onPointerDown = (event: PointerEvent<SVGSVGElement>) => {
    if (event.button !== 0) return;
    movedRef.current = false;
    dragRef.current = { x: event.clientX, y: event.clientY, ox: view.offsetX, oy: view.offsetY };
  };
  const onPointerMove = (event: PointerEvent<SVGSVGElement>) => {
    const drag = dragRef.current;
    if (!drag) return;
    if (event.buttons === 0) {
      // The button was released outside the canvas (or the pointer was cancelled) without a
      // pointer-up reaching us; drop the stale drag instead of panning on hover.
      dragRef.current = null;
      return;
    }
    const dx = event.clientX - drag.x;
    const dy = event.clientY - drag.y;
    if (!movedRef.current) {
      if (Math.hypot(dx, dy) < DRAG_THRESHOLD_PX) return;
      movedRef.current = true;
      event.currentTarget.setPointerCapture(event.pointerId);
    }
    setView((current) => ({ ...current, offsetX: drag.ox + dx, offsetY: drag.oy + dy }));
  };
  const onPointerUp = (event: PointerEvent<SVGSVGElement>) => {
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
    dragRef.current = null;
  };
  const onWheel = (event: WheelEvent<SVGSVGElement>) => {
    setView((current) => zoomAround(current, event.deltaY < 0 ? WHEEL_ZOOM : 1 / WHEEL_ZOOM));
  };

  const pan = (dx: number, dy: number) =>
    setView((current) => ({ ...current, offsetX: current.offsetX + dx, offsetY: current.offsetY + dy }));
  const onKeyDown = (event: KeyboardEvent<SVGSVGElement>) => {
    const handlers: Record<string, () => void> = {
      ArrowLeft: () => pan(PAN_STEP, 0),
      ArrowRight: () => pan(-PAN_STEP, 0),
      ArrowUp: () => pan(0, PAN_STEP),
      ArrowDown: () => pan(0, -PAN_STEP),
      '+': () => setView((c) => zoomAround(c, BUTTON_ZOOM)),
      '=': () => setView((c) => zoomAround(c, BUTTON_ZOOM)),
      '-': () => setView((c) => zoomAround(c, 1 / BUTTON_ZOOM)),
      '0': () => setView(fitView(box)),
      Escape: () => setSelected(null),
    };
    const handler = handlers[event.key];
    if (!handler) return;
    event.preventDefault();
    handler();
  };
  // Keyboard focus must never leave the focused node off screen: bring it into view.
  const onNodeFocus = (position: Positioned) => {
    if (!isVisible(position, view)) setView((current) => centreOn(position, current.scale));
  };
  const onNodeKeyDown = (event: KeyboardEvent<SVGGElement>, deviceId: string) => {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    event.preventDefault();
    event.stopPropagation();
    toggle(deviceId);
  };
  const onSearchKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key !== 'Enter') return;
    event.preventDefault();
    const first = topology.nodes.find((n) => matches.has(n.device_id));
    if (first) select(first.device_id, true);
  };

  const edges = topology.edges.flatMap((edge, index) => {
    const from = byId.get(edge.source_device_id);
    const to = byId.get(edge.target_device_id);
    if (!from || !to) return [];
    const active = selected !== null && (edge.source_device_id === selected || edge.target_device_id === selected);
    return [{ edge, from, to, active, key: `${index}:${edge.source_device_id}->${edge.target_device_id}` }];
  });
  const selectedNode = selected === null ? null : (nodesById.get(selected) ?? null);

  return (
    <div className="row g-3 mb-3">
      <div className="col-12 col-xl-9">
        <TopologyLegend />
        <div className="d-flex flex-wrap align-items-end justify-content-between gap-2 mb-2">
          <div>
            <label className="form-label small mb-1" htmlFor="topology-search">
              Find a device on the map
            </label>
            <input
              id="topology-search"
              type="search"
              className="form-control form-control-sm"
              maxLength={64}
              placeholder="Name or id, Enter to select"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              onKeyDown={onSearchKeyDown}
            />
            <span className="small text-body-secondary" role="status">
              {searching ? `${matches.size} of ${topology.nodes.length} devices match` : `${topology.nodes.length} devices`}
            </span>
          </div>
          <ZoomControls
            scale={view.scale}
            onZoom={(factor) => setView((current) => zoomAround(current, factor))}
            onFit={() => setView(fitView(box))}
          />
        </div>
        <div className="topology-canvas border rounded">
          <svg
            viewBox={`0 0 ${VIEW_W} ${VIEW_H}`}
            role="group"
            tabIndex={0}
            aria-label={`Topology graph with ${topology.nodes.length} nodes and ${edges.length} explicit links. Arrow keys pan, plus and minus zoom, 0 fits, Tab moves between devices.`}
            style={{ width: '100%', height: 'auto', cursor: 'grab', touchAction: 'none' }}
            onPointerDown={onPointerDown}
            onPointerMove={onPointerMove}
            onPointerUp={onPointerUp}
            onPointerCancel={onPointerUp}
            onWheel={onWheel}
            onKeyDown={onKeyDown}
          >
            <g transform={`translate(${view.offsetX} ${view.offsetY}) scale(${view.scale})`}>
              {edges.map(({ edge, from, to, active, key }) => (
                <line
                  key={key}
                  x1={from.x + NODE_W / 2}
                  y1={from.y + NODE_H / 2}
                  x2={to.x + NODE_W / 2}
                  y2={to.y + NODE_H / 2}
                  className={`topology-edge${active ? ' topology-edge--active' : ''}`}
                  strokeWidth={active ? 3 : 2}
                >
                  <title>{`${edge.source.toUpperCase()} link${edge.observed_at ? ` observed ${edge.observed_at}` : ' (observation time unknown)'}`}</title>
                </line>
              ))}
              {positions.map((position) => (
                <NodeShape
                  key={position.id}
                  position={position}
                  selected={selected === position.id}
                  linked={adjacent.has(position.id)}
                  dim={searching && !matches.has(position.id)}
                  match={searching && matches.has(position.id)}
                  node={nodesById.get(position.id)}
                  onToggle={() => {
                    if (movedRef.current) return;
                    toggle(position.id);
                  }}
                  onKeyDown={(event) => onNodeKeyDown(event, position.id)}
                  onFocus={() => onNodeFocus(position)}
                />
              ))}
            </g>
          </svg>
        </div>
      </div>
      <div className="col-12 col-xl-3">
        <TopologySidePanel
          topology={topology}
          node={selectedNode}
          onSelect={(deviceId) => select(deviceId, true)}
          onClear={() => setSelected(null)}
        />
      </div>
    </div>
  );
}

function NodeShape({
  position,
  node,
  selected,
  linked,
  dim,
  match,
  onToggle,
  onKeyDown,
  onFocus,
}: {
  position: Positioned;
  node: TopologyResponse['nodes'][number] | undefined;
  selected: boolean;
  linked: boolean;
  dim: boolean;
  match: boolean;
  onToggle: () => void;
  onKeyDown: (event: KeyboardEvent<SVGGElement>) => void;
  onFocus: () => void;
}) {
  const finding = node?.finding != null;
  const name = node ? nodeLabel(node) : position.name;
  const summary = node ? reconciliationText(node) : 'Reconciliation unknown';
  return (
    <g
      transform={`translate(${position.x} ${position.y})`}
      role="button"
      tabIndex={0}
      aria-pressed={selected}
      aria-label={`${name}. ${summary}.${linked ? ' Linked to the selected device.' : ''}`}
      className="topology-node-group"
      onClick={onToggle}
      onKeyDown={onKeyDown}
      onFocus={onFocus}
      style={{ cursor: 'pointer' }}
    >
      <title>{`${position.id}\n${summary}`}</title>
      <rect
        width={NODE_W}
        height={NODE_H}
        rx={6}
        className={nodeClass(selected, finding, dim, match)}
        strokeWidth={selected || linked ? 2 : 1}
      />
      <text
        x={NODE_W / 2}
        y={NODE_H / 2 + 1}
        textAnchor="middle"
        dominantBaseline="middle"
        className="topology-node__label"
        fontSize={12}
      >
        {truncated(name)}
      </text>
      {finding ? (
        <text x={NODE_W - 12} y={14} textAnchor="middle" className="topology-node__flag" fontSize={13} aria-hidden="true">
          ⚠
        </text>
      ) : null}
    </g>
  );
}
