import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen, within } from '@testing-library/react';

import { FirstRunChecklist } from '@/components/first-run-checklist';
import { firstRunChecklist } from '@/lib/first-run';
import type { FetchState } from '@/lib/api-response';

afterEach(() => cleanup());

const notConfigured: FetchState<never> = {
  kind: 'source_unavailable',
  code: 'SOURCE_UNAVAILABLE',
  message: 'LibreNMS source is not configured',
  correlationId: 'c',
  status: 503,
};
const notConnected = { kind: 'ok', correlationId: 'c', data: { state: 'not-connected' } } as unknown as FetchState<{
  state: string;
}>;

describe('FirstRunChecklist', () => {
  it('lists each source with its status as text, a guide path and a page link', () => {
    render(
      <FirstRunChecklist
        checklist={firstRunChecklist({ devices: notConfigured, security: notConnected, traffic: null, internet: notConnected })}
      />,
    );
    const region = screen.getByRole('region', { name: 'Connect your first data source' });
    const items = within(region).getAllByRole('listitem');
    assert.equal(items.length, 6);
    assert.match(items[0].textContent ?? '', /LibreNMS.*Not connected/);
    assert.match(items[3].textContent ?? '', /Wazuh.*Not connected/);
    assert.match(items[4].textContent ?? '', /Akvorado.*Not shown to your role/);
    assert.equal(within(items[0]).getByRole('link', { name: 'Devices page' }).getAttribute('href'), '/devices');
    assert.match(items[0].textContent ?? '', /docs\/04-integrations\/LIBRENMS\.md/);
  });

  it('renders nothing once the device source is configured', () => {
    const { container } = render(
      <FirstRunChecklist
        checklist={firstRunChecklist({
          devices: { kind: 'ok', correlationId: 'c', data: {} } as unknown as FetchState<unknown>,
          security: null,
          traffic: null,
          internet: notConnected,
        })}
      />,
    );
    assert.equal(container.childElementCount, 0);
  });
});
