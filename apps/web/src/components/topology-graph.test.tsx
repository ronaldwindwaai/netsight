import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';

import { TopologyGraph, TopologyView } from '@/components/topology-graph';
import type { TopologyResponse } from '@/lib/api-contracts';
import { VIEW_W } from '@/lib/topology-layout';

// jsdom has no pointer capture; a real browser does. Stub it so the handlers can run.
const proto = globalThis.SVGElement.prototype as unknown as Record<string, unknown>;
proto.setPointerCapture ??= () => undefined;
proto.releasePointerCapture ??= () => undefined;
proto.hasPointerCapture ??= () => false;

afterEach(() => cleanup());

const A = 'device-6f1c2a9e-0b1d-5c3e-8f4a-123456789aaa';
const B = 'device-6f1c2a9e-0b1d-5c3e-8f4a-123456789bbb';
const C = 'device-6f1c2a9e-0b1d-5c3e-8f4a-123456789ccc';

const TOPOLOGY = {
  state: 'ok',
  freshness: { state: 'fresh', observed_at: null, source: null },
  nodes: [
    { device_id: A, name: 'Core-1', reconciled: true, finding: null },
    { device_id: B, name: 'Access-2', reconciled: false, finding: null },
    { device_id: C, name: 'Edge-3', reconciled: true, finding: { kind: 'missing-discovered', detail: 'Not seen by discovery' } },
  ],
  edges: [
    { source_device_id: A, target_device_id: B, source: 'lldp', observed_at: null },
    { source_device_id: C, target_device_id: A, source: 'netbox', observed_at: null },
  ],
} as TopologyResponse;

const node = (name: RegExp) =>
  screen.getAllByRole('button', { name }).find((el) => el.hasAttribute('aria-pressed')) as HTMLElement;

describe('TopologyGraph', () => {
  it('shows a legend and an empty selection prompt before anything is selected', () => {
    render(<TopologyGraph topology={TOPOLOGY} />);
    assert.ok(screen.getByRole('list', { name: 'Map legend' }));
    assert.match(screen.getByRole('complementary', { name: 'Selected device' }).textContent ?? '', /Select a device/);
  });

  it('exposes nodes as keyboard operable buttons that state their reconciliation in words', () => {
    render(<TopologyGraph topology={TOPOLOGY} />);
    assert.match(node(/Edge-3/).getAttribute('aria-label') ?? '', /Finding: intended in NetBox but not discovered/);
    assert.match(node(/Access-2/).getAttribute('aria-label') ?? '', /Not checked/);
    assert.equal(node(/Core-1/).getAttribute('tabindex'), '0');
  });

  it('selects with Enter, lists links and offers drill-downs, and clears with Escape', () => {
    render(<TopologyGraph topology={TOPOLOGY} />);
    fireEvent.keyDown(node(/Core-1/), { key: 'Enter' });
    const panel = screen.getByRole('complementary', { name: 'Selected device' });
    assert.match(panel.textContent ?? '', /2 explicit links/);
    assert.equal(within(panel).getByRole('link', { name: /Open device/ }).getAttribute('href'), `/devices/${A}`);
    assert.equal(within(panel).getByRole('link', { name: /Inventory/ }).getAttribute('href'), `/inventory/${A}`);
    assert.equal(node(/Core-1/).getAttribute('aria-pressed'), 'true');
    fireEvent.keyDown(screen.getByRole('group', { name: /Topology graph/ }), { key: 'Escape' });
    assert.match(panel.textContent ?? '', /Select a device/);
  });

  it('moves the selection to a neighbour from the panel', () => {
    render(<TopologyGraph topology={TOPOLOGY} />);
    fireEvent.click(node(/Core-1/));
    fireEvent.click(screen.getByRole('button', { name: 'Edge-3' }));
    assert.equal(node(/Edge-3/).getAttribute('aria-pressed'), 'true');
    assert.match(screen.getByRole('complementary').textContent ?? '', /Not seen by discovery/);
  });

  it('searches, reports the match count and selects the first match on Enter', () => {
    render(<TopologyGraph topology={TOPOLOGY} />);
    const search = screen.getByRole('searchbox');
    fireEvent.change(search, { target: { value: 'access' } });
    assert.match(document.body.textContent ?? '', /1 of 3 devices match/);
    fireEvent.keyDown(search, { key: 'Enter' });
    assert.equal(node(/Access-2/).getAttribute('aria-pressed'), 'true');
    fireEvent.change(search, { target: { value: 'nothing' } });
    assert.match(document.body.textContent ?? '', /0 of 3 devices match/);
  });

  it('opens with the focused device selected', () => {
    render(<TopologyGraph topology={TOPOLOGY} initialSelected={B} />);
    assert.equal(node(/Access-2/).getAttribute('aria-pressed'), 'true');
  });

  it('zooms with the controls and the keyboard', () => {
    render(<TopologyGraph topology={TOPOLOGY} />);
    const before = screen.getByLabelText(/^Zoom \d+ percent/).textContent;
    fireEvent.click(screen.getByRole('button', { name: 'Zoom in' }));
    const after = screen.getByLabelText(/^Zoom \d+ percent/).textContent;
    assert.notEqual(before, after);
    fireEvent.keyDown(screen.getByRole('group', { name: /Topology graph/ }), { key: '0' });
    assert.equal(screen.getByLabelText(/^Zoom \d+ percent/).textContent, before);
  });

  it('re-applies a changed focus on client navigation instead of keeping the old selection', () => {
    const { rerender } = render(<TopologyView topology={TOPOLOGY} focus={A} />);
    assert.equal(node(/Core-1/).getAttribute('aria-pressed'), 'true');
    rerender(<TopologyView topology={TOPOLOGY} focus={B} />);
    assert.equal(node(/Access-2/).getAttribute('aria-pressed'), 'true');
    assert.equal(node(/Core-1/).getAttribute('aria-pressed'), 'false');
    rerender(<TopologyView topology={TOPOLOGY} focus={null} />);
    assert.equal(node(/Access-2/).getAttribute('aria-pressed'), 'false');
  });

  it('ends a drag on pointer cancel and ignores moves once no button is held', () => {
    render(<TopologyGraph topology={TOPOLOGY} />);
    const svg = screen.getByRole('group', { name: /Topology graph/ });
    const transform = () => svg.querySelector('g')?.getAttribute('transform');
    const start = transform();
    fireEvent.pointerDown(svg, { button: 0, buttons: 1, clientX: 10, clientY: 10, pointerId: 1 });
    fireEvent.pointerCancel(svg, { pointerId: 1 });
    fireEvent.pointerMove(svg, { buttons: 1, clientX: 200, clientY: 200, pointerId: 1 });
    assert.equal(transform(), start, 'a cancelled drag must not keep panning');
    fireEvent.pointerDown(svg, { button: 0, buttons: 1, clientX: 10, clientY: 10, pointerId: 2 });
    fireEvent.pointerMove(svg, { buttons: 0, clientX: 300, clientY: 300, pointerId: 2 });
    assert.equal(transform(), start, 'hovering with no button held must not pan');
  });

  it('brings a focused node that is off screen back into view', () => {
    render(<TopologyGraph topology={TOPOLOGY} />);
    const svg = screen.getByRole('group', { name: /Topology graph/ });
    const transform = () => svg.querySelector('g')?.getAttribute('transform') ?? '';
    for (let i = 0; i < 40; i += 1) fireEvent.keyDown(svg, { key: 'ArrowLeft' });
    const panned = transform();
    fireEvent.focus(node(/Core-1/));
    assert.notEqual(transform(), panned);
    const offsetX = Number(/translate\((-?[\d.]+)/.exec(transform())?.[1]);
    assert.ok(offsetX < VIEW_W && offsetX > -VIEW_W);
  });
});
