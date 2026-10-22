import assert from 'node:assert/strict';
import test from 'node:test';

import { overviewIncidentRequest } from './overview-incidents.ts';

test('a summary-only role reads the summary endpoint', () => {
  assert.deepEqual(overviewIncidentRequest(['incidents:read-summary']), {
    kind: 'summary',
    path: '/api/v1/incidents/summary?limit=50',
  });
});

test('a full-read role reads the full endpoint, even if it also holds the summary permission', () => {
  const expected = { kind: 'full', path: '/api/v1/incidents?limit=50' };
  assert.deepEqual(overviewIncidentRequest(['incidents:read']), expected);
  assert.deepEqual(overviewIncidentRequest(['incidents:read-summary', 'incidents:read']), expected);
});

test('a role with no incident permission makes no request', () => {
  assert.equal(overviewIncidentRequest([]), null);
  assert.equal(overviewIncidentRequest(['traffic:read', 'diagnostics:read']), null);
});

test('an unread session attempts the full read and lets the API decide', () => {
  assert.deepEqual(overviewIncidentRequest(null), { kind: 'full', path: '/api/v1/incidents?limit=50' });
});
