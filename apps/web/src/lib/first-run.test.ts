import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { firstRunChecklist, isSourceNotConfigured } from './first-run.ts';
import type { FetchState } from './api-response.ts';

const failure = (kind: 'source_unavailable' | 'forbidden' | 'error', message: string): FetchState<never> => ({
  kind,
  code: 'X',
  message,
  correlationId: 'c',
  status: 503,
});
const notConfigured = failure('source_unavailable', 'LibreNMS source is not configured');
const ok = (state: string) =>
  ({ kind: 'ok', correlationId: 'c', data: { state } }) as unknown as FetchState<{ state: string }>;

describe('isSourceNotConfigured', () => {
  it('recognises the API refusal for an unconfigured source only', () => {
    assert.equal(isSourceNotConfigured(notConfigured), true);
    assert.equal(isSourceNotConfigured(failure('source_unavailable', 'LibreNMS request timed out')), false);
    assert.equal(isSourceNotConfigured(failure('forbidden', 'source is not configured')), false);
    assert.equal(isSourceNotConfigured(ok('ok')), false);
    assert.equal(isSourceNotConfigured(null), false);
  });
});

describe('firstRunChecklist', () => {
  const none = {
    devices: notConfigured,
    security: ok('not-connected'),
    traffic: ok('not-connected'),
    internet: ok('not-connected'),
  };

  it('is shown when the device source is not configured', () => {
    const list = firstRunChecklist(none);
    assert.equal(list.show, true);
    assert.equal(list.items[0].id, 'librenms');
    assert.equal(list.items[0].status, 'not-connected');
  });

  it('is hidden once devices are readable, and when a configured source is merely failing', () => {
    assert.equal(firstRunChecklist({ ...none, devices: ok('ok') }).show, false);
    assert.equal(firstRunChecklist({ ...none, devices: failure('source_unavailable', 'timed out') }).show, false);
  });

  it('reports each checkable source honestly and never invents a state', () => {
    const list = firstRunChecklist({ devices: notConfigured, security: null, traffic: ok('ok'), internet: ok('unknown') });
    const status = Object.fromEntries(list.items.map((item) => [item.id, item.status]));
    assert.equal(status.wazuh, 'restricted');
    assert.equal(status.akvorado, 'connected');
    assert.equal(status.blackbox, 'unknown');
    assert.equal(status.netbox, 'unchecked');
    assert.equal(status.oxidized, 'unchecked');
  });

  it('lists read-only sources only, each with a documentation path', () => {
    for (const item of firstRunChecklist(none).items) {
      assert.match(item.docs, /^docs\/04-integrations\/[A-Z-]+\.md$/);
      assert.doesNotMatch(`${item.purpose} ${item.setup}`, /write|push|deploy|reconfigure/i);
    }
  });
});
