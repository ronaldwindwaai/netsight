import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen } from '@testing-library/react';

import { UserDetailBody } from '@/components/user-detail-body';
import { NO_ENTITY_ACCESS, entityHref } from '@/lib/identity-view';
import { ALICE, DEVICE, IP, detailFixture, okState } from '@/test/identity-fixtures';

afterEach(() => cleanup());

describe('entity links', () => {
  it('maps people and devices to their pages and leaves other kinds as text', () => {
    const all = { people: true, devices: true };
    assert.equal(entityHref(ALICE, all), `/users/${encodeURIComponent(ALICE.id)}`);
    assert.equal(entityHref(DEVICE, all), `/devices/${encodeURIComponent(DEVICE.id)}`);
    assert.equal(entityHref(IP, all), null);
  });

  it('offers no link without the matching permission, and denies by default', () => {
    assert.equal(entityHref(ALICE), null);
    assert.equal(entityHref(DEVICE, NO_ENTITY_ACCESS), null);
    assert.equal(entityHref(ALICE, { people: false, devices: true }), null);
    assert.equal(entityHref(DEVICE, { people: true, devices: false }), null);
  });

  it('a role without inventory:read sees an assigned device as text', () => {
    render(<UserDetailBody state={okState(detailFixture())} access={{ people: true, devices: false }} />);
    const group = screen.getByRole('group', { name: 'Assigned devices' });
    assert.equal(group.querySelector('a[href^="/devices/"]'), null);
  });

  it('an assigned device links to its device page', () => {
    render(<UserDetailBody state={okState(detailFixture())} access={{ people: true, devices: true }} />);
    const group = screen.getByRole('group', { name: 'Assigned devices' });
    const link = group.querySelector(`a[href="/devices/${encodeURIComponent(DEVICE.id)}"]`);
    assert.ok(link, 'the device name is a link');
  });
});

describe('the traffic panel on a person', () => {
  it('links an attributed address to its flows only for a role that may filter by address', () => {
    const first = render(<UserDetailBody state={okState(detailFixture())} />);
    assert.equal(screen.queryByRole('link', { name: '10.0.0.10' }), null);
    first.unmount();
    render(<UserDetailBody state={okState(detailFixture())} inspectFlows />);
    const href = screen.getByRole('link', { name: '10.0.0.10' }).getAttribute('href') ?? '';
    assert.match(href, /^\/traffic\/flows\?from=2026-10-11T11%3A00%3A00Z&to=.*&source_ip=10\.0\.0\.10$/);
  });
});
