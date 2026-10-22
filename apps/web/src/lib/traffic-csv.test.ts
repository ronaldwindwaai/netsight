import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { applicationCsvRows, destinationCsvRows } from './traffic-csv.ts';
import type { ApplicationRow, DestinationRow } from './api-contracts-traffic-lists.ts';

const destination = (over: Partial<DestinationRow>): DestinationRow =>
  ({
    rank: 1,
    address: '203.0.113.9',
    scope: 'external',
    visibility: 'shown',
    domain: 'example.test',
    asn: 64500,
    country: 'GB',
    first_seen: '2026-10-20T10:00:00Z',
    last_seen: '2026-10-21T10:00:00Z',
    bytes: 2048,
    packets: 10,
    share: 0.25,
    endpoints: 4,
    users: null,
    reputation: 'unlisted',
    ...over,
  }) as DestinationRow;

describe('destinationCsvRows', () => {
  it('exports what the page shows, with the source-reported domain as plain text', () => {
    const rows = destinationCsvRows([destination({ domain: '=HYPERLINK("x")' })]);
    assert.deepEqual(rows[0].slice(0, 5), ['203.0.113.9', '=HYPERLINK("x")', 'AS64500', 'GB', 'shown']);
  });

  it('leaves every withheld value empty rather than inventing one', () => {
    const rows = destinationCsvRows([
      destination({
        visibility: 'withheld',
        domain: null,
        asn: null,
        country: null,
        first_seen: null,
        last_seen: null,
        bytes: null,
        packets: null,
        share: null,
        endpoints: null,
      }),
    ]);
    assert.deepEqual(rows[0], ['203.0.113.9', '', '', '', 'withheld', '', '', '', '', '', 'unlisted']);
  });
});

describe('applicationCsvRows', () => {
  it('exports name, category, volume and policy fields', () => {
    const row = {
      rank: 1,
      application: '@odd',
      category: null,
      visibility: 'shown',
      bytes: 10,
      packets: 1,
      share: 0.5,
      endpoints: 3,
      users: null,
      trend: { state: 'up', previous_bytes: null, change_ratio: null },
      risk: 'unknown',
      approval: 'unknown',
    } as unknown as ApplicationRow;
    const [out] = applicationCsvRows([row]);
    assert.equal(out[0], '@odd');
    assert.equal(out[1], '');
    assert.deepEqual(out.slice(2, 4), ['shown', 10]);
  });
});
