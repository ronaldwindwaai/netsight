import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen } from '@testing-library/react';

import { UnknownDeviceDetailBody } from '@/components/unknown-device-detail-body';
import { findingDetail, okState, timeline } from '@/test/step8-fixtures';

afterEach(() => cleanup());

describe('finding detail is not a dead end', () => {
  it('links to inventory, flows, the map and IPAM using only values the endpoint has', () => {
    render(<UnknownDeviceDetailBody state={okState(findingDetail())} actions={null} timeline={okState(timeline())} />);
    const hrefs = screen.getAllByRole('link').map((a) => a.getAttribute('href') ?? '');
    assert.ok(hrefs.some((h) => h.startsWith('/inventory?q=')));
    assert.ok(hrefs.includes('/traffic/flows?source_ip=10.0.5.9'));
    assert.ok(hrefs.includes('/network/map'));
    assert.ok(hrefs.includes('/ipam'));
    assert.match(document.body.textContent ?? '', /not filtered to this endpoint/);
  });
});
