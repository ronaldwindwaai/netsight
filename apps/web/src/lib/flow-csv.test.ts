import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { toCsv } from './csv.ts';
import { FLOW_CSV_HEADERS, flowCsvRows } from './flow-csv.ts';
import type { TrafficFlow } from './api-contracts-traffic-flows.ts';

const flow = (over: Partial<TrafficFlow> = {}): TrafficFlow => ({
  observed_at: '2026-10-21T10:00:00Z',
  source_ip: '10.0.0.5',
  source_device_id: null,
  destination_ip: '203.0.113.9',
  destination_host: 'example.test',
  protocol: 'tcp',
  destination_port: 443,
  bytes: 2048,
  packets: null,
  direction: 'outbound',
  application: 'HTTPS',
  attribution: null,
  ...over,
});

const ALL = { people: true, devices: true };

describe('flowCsvRows', () => {
  it('has one cell per header and exports unreported values as empty cells', () => {
    const [row] = flowCsvRows([flow()], ALL);
    assert.equal(row.length, FLOW_CSV_HEADERS.length);
    assert.equal(row[FLOW_CSV_HEADERS.indexOf('Packets')], '');
    assert.equal(row[FLOW_CSV_HEADERS.indexOf('Bytes')], 2048);
  });

  it('keeps source-reported text as data for the csv util to neutralise', () => {
    const [row] = flowCsvRows([flow({ application: '=cmd()' })], ALL);
    assert.equal(row[FLOW_CSV_HEADERS.indexOf('Application')], '=cmd()');
  });

  it('withholds people and device labels the viewer may not open', () => {
    const attributed = flow({
      attribution: {
        basis: 'observed', reason: null, confidence: 0.9, ambiguous: false,
        person: { id: 'u1', label: 'Alice' }, device: { id: 'd1', label: 'laptop' },
      } as unknown as TrafficFlow['attribution'],
    });
    const [open] = flowCsvRows([attributed], ALL);
    const [closed] = flowCsvRows([attributed], { people: false, devices: false });
    assert.equal(open[FLOW_CSV_HEADERS.indexOf('Person')], 'Alice');
    assert.equal(closed[FLOW_CSV_HEADERS.indexOf('Person')], '');
    assert.equal(closed[FLOW_CSV_HEADERS.indexOf('Attributed device')], '');
  });

  it('writes a hostile source value with a leading quote through toCsv', () => {
    const rows = flowCsvRows([flow({ application: '=HYPERLINK("http://evil.test")', destination_host: '@evil' })], ALL);
    const lines = toCsv(FLOW_CSV_HEADERS, rows).split('\r\n');
    assert.ok(lines[1].includes(`"'=HYPERLINK(""http://evil.test"")"`));
    assert.ok(lines[1].includes(",'@evil,"));
    assert.ok(!lines[1].includes(',=HYPERLINK'));
  });
});
