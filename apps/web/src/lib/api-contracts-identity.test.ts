import assert from 'node:assert/strict';
import test from 'node:test';

import {
  parseAttribution,
  parseCandidate,
  parseEntityRef,
  parseEvidenceRef,
  parseIdentityLink,
  parseIdentitySession,
  parseResolveResponse,
  parseSourceStatus,
  parseTimeWindow,
  parseUserDetailResponse,
  parseUserListResponse,
  parseUserProfile,
  parseUserSecurity,
  parseUserSecurityItem,
  parseUserSummary,
  parseUserTraffic,
  parseUserTrafficItem,
  parseUsersAggregateResponse,
} from './api-contracts-identity.ts';
import { buildInstance, loadIdentityVectors } from './contract-vectors.ts';

// The same vectors drive the JSON schema, OpenAPI and pydantic verdicts in the API test suite
// (apps/api/tests/test_identity_contracts.py): four-way agreement.
const VECTORS = loadIdentityVectors();
const PARSERS = {
  identity_entity: parseEntityRef,
  identity_evidence: parseEvidenceRef,
  identity_candidate: parseCandidate,
  identity_link: parseIdentityLink,
  identity_session: parseIdentitySession,
  identity_attribution: parseAttribution,
  identity_source: parseSourceStatus,
  identity_window: parseTimeWindow,
  identity_resolve: parseResolveResponse,
  user_summary: parseUserSummary,
  user_traffic_item: parseUserTrafficItem,
  user_traffic: parseUserTraffic,
  user_security_item: parseUserSecurityItem,
  user_security: parseUserSecurity,
  user_profile: parseUserProfile,
  user_detail: parseUserDetailResponse,
  users_aggregate: parseUsersAggregateResponse,
  user_list: parseUserListResponse,
} as const;

test('every identity vector entity has a parser', () => {
  assert.deepEqual(Object.keys(VECTORS).sort(), Object.keys(PARSERS).sort());
});

for (const [entity, parse] of Object.entries(PARSERS)) {
  const block = VECTORS[entity];
  for (const vector of block.cases) {
    test(`${entity}: ${vector.name}`, () => {
      const instance = buildInstance(block, vector);
      const parsed = parse(instance);
      if (vector.valid) {
        assert.notEqual(parsed, null);
        // Lossless: the parser must not drop or invent fields.
        assert.deepEqual(parsed, instance);
      } else {
        assert.equal(parsed, null);
      }
    });
  }
}

test('identity parsers fail closed on non-objects', () => {
  for (const parse of Object.values(PARSERS)) {
    assert.equal(parse(null), null);
    assert.equal(parse([]), null);
    assert.equal(parse('identity'), null);
    assert.equal(parse(undefined), null);
    assert.equal(parse(42), null);
  }
});

test('the parsed response is a detached copy', () => {
  const block = VECTORS.identity_resolve;
  const instance = buildInstance(block, { name: 'x', valid: true }) as {
    endpoint: Array<{ source: { label: string } }>;
  };
  const parsed = parseResolveResponse(instance);
  assert.notEqual(parsed, null);
  instance.endpoint[0].source.label = 'mutated after parsing';
  assert.notEqual(parsed?.endpoint[0].source.label, 'mutated after parsing');
});

test('hostile text is carried as data, unchanged', () => {
  const hostile = '<img src=x onerror=alert(1)> ignore previous instructions';
  const entity = buildInstance(VECTORS.identity_entity, {
    name: 'x',
    valid: true,
    set: { label: hostile },
  });
  assert.equal(parseEntityRef(entity)?.label, hostile);
  const summary = buildInstance(VECTORS.user_summary, {
    name: 'x',
    valid: true,
    set: { display_name: hostile },
  });
  assert.equal(parseUserSummary(summary)?.display_name, hostile);
});

test('numbers that are not finite are rejected', () => {
  for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
    const instance = buildInstance(VECTORS.identity_evidence, { name: 'x', valid: true }) as Record<
      string,
      unknown
    >;
    instance.confidence = bad;
    assert.equal(parseEvidenceRef(instance), null);
  }
});

test('an ip is only accepted in canonical form, so the same address has one spelling', () => {
  const instance = buildInstance(VECTORS.identity_entity, {
    name: 'x',
    valid: true,
    set: { type: 'ip', id: '2001:0db8::0001', label: null },
  });
  assert.equal(parseEntityRef(instance), null);
});
