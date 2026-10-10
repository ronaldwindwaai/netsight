import assert from 'node:assert/strict';
import test from 'node:test';

import { parseDiagnosticSession } from './api-contracts-diagnostic-session.ts';
import type { DiagnosticSession } from './api-contracts-diagnostic-session.ts';
import { buildInstance, loadDiagnosticSessionVectors } from './contract-vectors.ts';
import { sessionFixture, unnarrowedSession } from '../test/diagnostic-fixtures.ts';
import {
  SESSION_STALE_AFTER_MS,
  basisLabel,
  changeScopeLabel,
  locationOutcome,
  parseListOffset,
  partialSections,
  pathHopLabel,
  sessionAge,
  sessionApiPath,
  sessionHref,
  sessionListPath,
  tierLabel,
} from './diagnostic-session-view.ts';

const VECTORS = loadDiagnosticSessionVectors();

function baseSession(): DiagnosticSession {
  const instance = buildInstance(VECTORS.diagnostic_session, { name: 'base', valid: true });
  const parsed = parseDiagnosticSession(instance);
  assert.notEqual(parsed, null);
  return parsed as DiagnosticSession;
}

const ID = 'diagnostic-1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d';

test('only a well-formed session id produces a link or an API path', () => {
  assert.equal(sessionHref(ID), `/diagnostics/${ID}`);
  assert.equal(sessionApiPath(ID), `/api/v1/diagnostics/${ID}`);
  for (const bad of ['', 'diagnostic-1', `${ID}/../x`, `${ID}?x=1`, '../etc', ID.toUpperCase(), 'incident-x']) {
    assert.equal(sessionHref(bad), null, bad);
    assert.equal(sessionApiPath(bad), null, bad);
  }
});

test('the list path carries bounded paging only', () => {
  assert.equal(sessionListPath(0), '/api/v1/diagnostics?limit=20&offset=0');
  assert.equal(sessionListPath(40), '/api/v1/diagnostics?limit=20&offset=40');
});

test('a list offset from the address is parsed defensively', () => {
  assert.equal(parseListOffset(undefined), 0);
  assert.equal(parseListOffset('40'), 40);
  assert.equal(parseListOffset(['40', '60']), 0);
  for (const bad of ['-1', '1.5', 'abc', '99999', '', ' 5', '1e3', '0x10']) {
    assert.equal(parseListOffset(bad), 0, bad);
  }
});

test('labels name every enumerated value and nothing is shown healthy by default', () => {
  assert.equal(basisLabel('observed'), 'Observed');
  assert.equal(basisLabel('inferred'), 'Inferred');
  assert.equal(basisLabel('unknown'), 'Unknown');
  assert.equal(tierLabel('access-switch'), 'Access switch');
  assert.equal(changeScopeLabel('target'), 'Recorded against this target');
  assert.match(changeScopeLabel('time-window'), /not matched to the target/);
});

test('a location outcome never reads as healthy without a measurement', () => {
  const rows = baseSession().locations;
  const byName = Object.fromEntries(rows.map((row) => [row.location, locationOutcome(row)]));
  assert.equal(byName['cloud-external'].tone, 'fail');
  assert.equal(byName['server-vlan'].tone, 'pass');
  for (const name of ['user-lan', 'branch', 'wifi', 'remote-site']) {
    assert.equal(byName[name].tone, 'none', name);
    assert.match(byName[name].label, /Not connected/);
    assert.doesNotMatch(byName[name].detail, /healthy|ok|reachable/i);
  }
  const unanswered = locationOutcome({
    ...rows[1],
    state: 'unknown',
    status: null,
    unknown_checks: 2,
    check_ids: ['a', 'b'],
  });
  assert.equal(unanswered.tone, 'unknown');
  assert.match(unanswered.detail, /not assumed healthy/);
});

test('a session is stale after the freshness window and the age is never negative', () => {
  const completed = '2026-10-10T08:00:05Z';
  const at = Date.parse(completed);
  assert.deepEqual(sessionAge(completed, at + 60_000), { stale: false, minutes: 1 });
  assert.equal(sessionAge(completed, at + SESSION_STALE_AFTER_MS).stale, true);
  assert.deepEqual(sessionAge(completed, at - 5 * 60_000), { stale: false, minutes: 0 });
  assert.equal(sessionAge('nonsense', at).stale, true);
});

test('partial sections list exactly what is not available', () => {
  const session = baseSession();
  assert.deepEqual(partialSections(session), ['Probe locations without a source']);
  const degraded: DiagnosticSession = {
    ...session,
    path: { state: 'unknown', observed_at: null, hops: [], links: [] },
    recent_changes: { ...session.recent_changes, state: 'unknown', items: [], sources: [
      { source: 'incidents', state: 'unknown' },
      { source: 'alerts', state: 'not-connected' },
      { source: 'configuration-changes', state: 'not-connected' },
    ] },
  };
  assert.deepEqual(partialSections(degraded), [
    'Probe locations without a source',
    'Path',
    'Recent changes',
  ]);
});

test('hop labels describe the explicit topology only', () => {
  const hops = baseSession().path.hops;
  const user = hops.find((hop) => hop.tier === 'user');
  const firewall = hops.find((hop) => hop.tier === 'firewall');
  assert.ok(user && firewall);
  assert.match(pathHopLabel(user), /Unknown/);
  assert.match(pathHopLabel(firewall), /fw-01/);
  assert.match(pathHopLabel(firewall), /suspected/i);
});

test('the component-test fixtures satisfy the contract parser', () => {
  for (const fixture of [sessionFixture(), unnarrowedSession()]) {
    assert.deepEqual(parseDiagnosticSession(structuredClone(fixture)), fixture);
  }
});
