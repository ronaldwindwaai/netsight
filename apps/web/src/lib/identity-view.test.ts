import assert from 'node:assert/strict';
import test from 'node:test';

import type { FetchState } from './api-response.ts';
import type {
  Attribution,
  EntityRef,
  IdentityLink,
  SourceStatus,
  UserListResponse,
} from './api-contracts-identity.ts';
import {
  attributionHeadline,
  basisPresentation,
  confidenceText,
  detailPath,
  entityText,
  evidenceKindLabel,
  listPath,
  listSurface,
  lookupPath,
  pageHrefs,
  parseLookup,
  parsePage,
  reasonText,
  relationLabel,
  sourceProblems,
  validityText,
} from './identity-view.ts';

const PERSON: EntityRef = {
  type: 'person',
  id: 'person-11111111-1111-4111-8111-111111111111',
  label: 'Alice Example',
};
const IP: EntityRef = { type: 'ip', id: '10.0.0.10', label: null };

function okState<T>(data: T): FetchState<T> {
  return { kind: 'ok', data, correlationId: 'c' };
}

function failure<T>(kind: Exclude<FetchState<T>['kind'], 'ok'>): FetchState<T> {
  return { kind, code: 'X', message: 'm', correlationId: 'c', status: null } as FetchState<T>;
}

test('a basis is always a word and an icon, never colour alone, and unknown is never styled as fine', () => {
  const seen = new Set<string>();
  for (const basis of ['observed', 'inferred', 'unknown'] as const) {
    const view = basisPresentation(basis);
    assert.ok(view.label.length > 0 && view.icon.startsWith('bi-') && view.explanation.length > 0);
    seen.add(view.label);
  }
  assert.deepEqual([...seen], ['Observed', 'Inferred', 'Unknown']);
  assert.notEqual(basisPresentation('unknown').theme, 'success');
  assert.notEqual(basisPresentation('inferred').theme, 'success');
});

test('every reason has a plain-language sentence that does not assert identity', () => {
  const reasons = [
    'declared-assignment',
    'indirect-evidence',
    'low-confidence',
    'name-match',
    'conflicting-evidence',
    'no-evidence',
    'expired',
    'multiple-candidates',
    'shared-address',
    'vpn-no-session',
    'guest-network',
    'ip-only',
    'source-unavailable',
    'restricted',
  ] as const;
  for (const reason of reasons) {
    const text = reasonText(reason);
    assert.ok(text.length > 20, reason);
    assert.doesNotMatch(text, /^(is|was) /i);
  }
  assert.match(reasonText('shared-address'), /many/i);
  assert.match(reasonText('ip-only'), /not .*identity|alone/i);
  assert.equal(reasonText(null), '');
});

test('entities render as text: the label when there is one, a typed id otherwise', () => {
  assert.equal(entityText(PERSON), 'Alice Example');
  assert.equal(entityText(IP), '10.0.0.10');
  assert.equal(entityText(null), 'Not identified');
  const hostile = { ...PERSON, label: '<img src=x onerror=alert(1)>' };
  assert.equal(entityText(hostile), '<img src=x onerror=alert(1)>');
  assert.match(entityText({ type: 'person', id: PERSON.id, label: null }), /Unnamed person/);
});

test('relations and evidence kinds have readable labels', () => {
  assert.equal(relationLabel('ip-mac'), 'IP address to MAC address');
  assert.equal(relationLabel('identity'), 'Who is behind it');
  assert.equal(evidenceKindLabel('radius-session'), 'RADIUS / 802.1X session');
  assert.equal(evidenceKindLabel('asset-assignment'), 'Asset register assignment');
});

test('confidence is a percentage, never invented for an unknown link', () => {
  assert.equal(confidenceText(0.95), '95%');
  assert.equal(confidenceText(0.7), '70%');
  assert.equal(confidenceText(null), 'Not reported');
  assert.equal(confidenceText(Number.NaN), 'Not reported');
});

function link(overrides: Partial<IdentityLink>): IdentityLink {
  return {
    relation: 'identity',
    source: IP,
    target: PERSON,
    basis: 'observed',
    confidence: 0.95,
    valid_from: '2026-10-11T10:00:00Z',
    valid_to: '2026-10-11T13:00:00Z',
    as_of: '2026-10-11T12:00:00Z',
    reason: null,
    evidence: [],
    ambiguous: false,
    candidates: [],
    ...overrides,
  };
}

test('a link states its window and an unknown link states none', () => {
  assert.equal(
    validityText(link({})),
    'Valid from 2026-10-11 10:00:00 UTC until 2026-10-11 13:00:00 UTC',
  );
  assert.equal(
    validityText(link({ basis: 'unknown', target: null, confidence: null, valid_from: null, valid_to: null })),
    'No validity window',
  );
});

function attribution(overrides: Partial<Attribution>): Attribution {
  return { basis: 'unknown', reason: 'ip-only', ambiguous: false, links: [], candidates: [], ...overrides };
}

test('the headline never states an uncertain correlation as fact', () => {
  const observed = attributionHeadline(attribution({ basis: 'observed', reason: null, links: [link({})] }));
  assert.equal(observed.title, 'Observed: Alice Example');
  const inferred = attributionHeadline(
    attribution({
      basis: 'inferred',
      reason: 'declared-assignment',
      links: [link({ basis: 'inferred', confidence: 0.7, reason: 'declared-assignment' })],
    }),
  );
  assert.match(inferred.title, /^Inferred: possibly Alice Example/);
  assert.match(inferred.detail, /declared|assigned/i);
  const none = attributionHeadline(attribution({}));
  assert.equal(none.title, 'Not identified');
  const ambiguous = attributionHeadline(
    attribution({
      reason: 'conflicting-evidence',
      ambiguous: true,
      candidates: [
        { entity: PERSON, basis: 'observed', confidence: 0.95, evidence: [] },
        { entity: { ...PERSON, id: 'person-22222222-2222-4222-8222-222222222222', label: 'Bob Example' }, basis: 'inferred', confidence: 0.7, evidence: [] },
      ],
    }),
  );
  assert.equal(ambiguous.title, 'Ambiguous: 2 possible people');
  assert.doesNotMatch(ambiguous.title, /Alice|Bob/);
  const restricted = attributionHeadline(attribution({ reason: 'restricted' }));
  assert.equal(restricted.title, 'Person withheld');
});

function source(overrides: Partial<SourceStatus>): SourceStatus {
  return {
    source: 'wazuh',
    state: 'ok',
    record_count: 3,
    truncated: false,
    freshness: { state: 'fresh', observed_at: '2026-10-11T11:55:00Z', source: 'wazuh' },
    ...overrides,
  };
}

test('source problems list sources that are not ok or are stale, without inventing detail', () => {
  const problems = sourceProblems([
    source({}),
    source({ source: 'netbox', state: 'not-connected', freshness: { state: 'unknown', observed_at: null, source: null } }),
    source({ source: 'radius', state: 'unknown', freshness: { state: 'unknown', observed_at: null, source: null } }),
    source({ source: 'dhcp', freshness: { state: 'stale', observed_at: '2026-10-11T08:00:00Z', source: 'dhcp' } }),
  ]);
  assert.deepEqual(
    problems.map((p) => [p.source, p.kind]),
    [
      ['netbox', 'not-connected'],
      ['radius', 'unknown'],
      ['dhcp', 'stale'],
    ],
  );
});

test('list surfaces separate permission, failure, not-connected, unknown, empty and data', () => {
  const base: UserListResponse = {
    state: 'ok',
    as_of: '2026-10-11T12:00:00Z',
    window: { from: '2026-10-10T12:00:00Z', to: '2026-10-11T12:00:00Z' },
    sources: [source({})],
    items: [],
    page: 1,
    page_size: 25,
    total: 0,
  };
  assert.equal(listSurface(failure('forbidden')), 'permission');
  assert.equal(listSurface(failure('unauthenticated')), 'failure');
  assert.equal(listSurface(failure('error')), 'failure');
  assert.equal(listSurface(failure('rate_limited')), 'failure');
  assert.equal(listSurface(okState({ ...base, state: 'not-connected', sources: [source({ state: 'not-connected' })] })), 'not-connected');
  assert.equal(listSurface(okState({ ...base, state: 'unknown', sources: [source({ state: 'unknown' })] })), 'unknown');
  assert.equal(listSurface(okState(base)), 'empty');
  assert.equal(
    listSurface(
      okState({
        ...base,
        items: [
          {
            id: PERSON.id,
            display_name: 'Alice Example',
            account_count: 1,
            assigned_device_count: 0,
            session_count: 0,
            presence: 'unknown',
            last_evidence_at: null,
          },
        ],
        total: 1,
      }),
    ),
    'data',
  );
});

test('paths are server-bounded and only ever built from validated values', () => {
  assert.equal(listPath(1, 25), '/api/v1/users?page=1&page_size=25');
  assert.equal(listPath(0, 25), '/api/v1/users?page=1&page_size=25');
  assert.equal(listPath(5000, 500), '/api/v1/users?page=1000&page_size=100');
  assert.equal(detailPath(PERSON.id), `/api/v1/users/${PERSON.id}`);
  assert.equal(detailPath('alice@example.com'), null);
  assert.equal(detailPath('../../auth/session'), null);
  assert.equal(detailPath(`${PERSON.id}/../x`), null);
});

test('page parameters are parsed defensively', () => {
  assert.equal(parsePage(undefined), 1);
  assert.equal(parsePage('3'), 3);
  assert.equal(parsePage(['4', '5']), 4);
  for (const bad of ['0', '-1', 'abc', '1.5', '1001', '', '  ', '１２']) {
    assert.equal(parsePage(bad), 1, bad);
  }
});

test('paging links keep to the pages that exist', () => {
  assert.deepEqual(pageHrefs(1, 25, 10), { previous: null, next: null });
  assert.deepEqual(pageHrefs(1, 25, 60), { previous: null, next: '/users?page=2' });
  assert.deepEqual(pageHrefs(2, 25, 60), { previous: '/users?page=1', next: '/users?page=3' });
  assert.deepEqual(pageHrefs(3, 25, 60), { previous: '/users?page=2', next: null });
});

test('a lookup needs exactly one valid subject and never reaches the API otherwise', () => {
  assert.deepEqual(parseLookup({ kind: 'ip', value: ' 10.0.0.10 ' }), {
    ok: true,
    kind: 'ip',
    value: '10.0.0.10',
  });
  assert.deepEqual(parseLookup({}), { ok: false, reason: 'empty' });
  assert.deepEqual(parseLookup({ kind: 'ip', value: '' }), { ok: false, reason: 'empty' });
  assert.deepEqual(parseLookup({ kind: 'email', value: 'a@b.c' }), { ok: false, reason: 'invalid' });
  assert.deepEqual(parseLookup({ kind: 'ip', value: 'x'.repeat(200) }), { ok: false, reason: 'invalid' });
  assert.deepEqual(parseLookup({ kind: ['ip', 'mac'], value: '1' }), { ok: false, reason: 'invalid' });
  assert.deepEqual(parseLookup({ kind: 'ip', value: ['a', 'b'] }), { ok: false, reason: 'invalid' });
});

test('a lookup path encodes the value and carries a single subject', () => {
  assert.equal(lookupPath({ ok: true, kind: 'ip', value: '10.0.0.10' }), '/api/v1/identity/resolve?ip=10.0.0.10');
  assert.equal(
    lookupPath({ ok: true, kind: 'hostname', value: 'a&mac=b#c d' }),
    '/api/v1/identity/resolve?hostname=a%26mac%3Db%23c%20d',
  );
});
