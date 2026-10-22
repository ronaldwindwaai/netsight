import assert from 'node:assert/strict';
import test from 'node:test';

import {
  aroundInstantFlowsHref,
  flowsDrillHref,
  hourFlowsHref,
  resolveTrafficWindow,
} from './traffic-view.ts';

const NOW = new Date('2026-10-11T12:00:00Z');
const WINDOW = resolveTrafficWindow({}, NOW, 31);
const DETAIL = { detail: true };
const NO_DETAIL = { detail: false };

test('flowsDrillHref keeps the window and adds a validated filter', () => {
  assert.equal(
    flowsDrillHref(WINDOW, { application: 'Zoom' }, NO_DETAIL),
    '/traffic/flows?preset=24h&application=Zoom',
  );
});

test('flowsDrillHref encodes reserved characters in a value', () => {
  assert.equal(
    flowsDrillHref(WINDOW, { application: 'a&b#c' }, NO_DETAIL),
    '/traffic/flows?preset=24h&application=a%26b%23c',
  );
});

test('flowsDrillHref refuses empty filters, malformed values and address filters without detail', () => {
  assert.equal(flowsDrillHref(WINDOW, {}, DETAIL), null);
  assert.equal(flowsDrillHref(WINDOW, { source_ip: 'not an ip' }, DETAIL), null);
  assert.equal(flowsDrillHref(WINDOW, { country: 'za' }, DETAIL), null);
  assert.equal(flowsDrillHref(WINDOW, { source_ip: '10.0.0.1' }, NO_DETAIL), null);
  assert.notEqual(flowsDrillHref(WINDOW, { source_ip: '10.0.0.1' }, DETAIL), null);
});

test('hourFlowsHref builds a canonical UTC range and applies filters', () => {
  assert.equal(
    hourFlowsHref('2026-10-11T02:00:00Z', '2026-10-11T03:00:00Z', {}, DETAIL),
    '/traffic/flows?from=2026-10-11T02%3A00%3A00Z&to=2026-10-11T03%3A00%3A00Z',
  );
  assert.match(
    hourFlowsHref('2026-10-11T02:00:00Z', '2026-10-11T03:00:00Z', { application: 'a&b#c' }, DETAIL) ?? '',
    /&application=a%26b%23c$/,
  );
});

test('hourFlowsHref converts an offset timestamp to UTC instead of truncating it', () => {
  assert.equal(
    hourFlowsHref('2026-10-11T04:00:00+02:00', '2026-10-11T05:30:00.500+02:00', {}, DETAIL),
    '/traffic/flows?from=2026-10-11T02%3A00%3A00Z&to=2026-10-11T03%3A30%3A00Z',
  );
});

test('hourFlowsHref refuses invalid, reversed or empty ranges and refused filters', () => {
  assert.equal(hourFlowsHref('nope', '2026-10-11T03:00:00Z', {}, DETAIL), null);
  assert.equal(hourFlowsHref('2026-10-11T02:00:00Z', 'nope', {}, DETAIL), null);
  assert.equal(hourFlowsHref('2026-10-11T03:00:00Z', '2026-10-11T02:00:00Z', {}, DETAIL), null);
  assert.equal(hourFlowsHref('2026-10-11T02:00:00Z', '2026-10-11T02:00:00Z', {}, DETAIL), null);
  assert.equal(
    hourFlowsHref('2026-10-11T02:00:00Z', '2026-10-11T03:00:00Z', { destination_ip: '10.0.0.1' }, NO_DETAIL),
    null,
  );
});

test('aroundInstantFlowsHref centres the window on the event', () => {
  assert.equal(
    aroundInstantFlowsHref('2026-10-11T11:00:00Z', 30, { source_ip: '10.0.0.10' }, DETAIL),
    '/traffic/flows?from=2026-10-11T10%3A30%3A00Z&to=2026-10-11T11%3A30%3A00Z&source_ip=10.0.0.10',
  );
  assert.equal(aroundInstantFlowsHref('nope', 30, {}, DETAIL), null);
});
