import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';

import { TopologyGraph } from '@/components/topology-graph';
import type { TopologyResponse } from '@/lib/api-contracts';

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

const node = (name: RegExp) => screen.getByRole('button', { name });

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
});
