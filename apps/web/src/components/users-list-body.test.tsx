import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen, within } from '@testing-library/react';

import { UsersListBody } from '@/components/users-list-body';
import type { UserListResponse } from '@/lib/api-contracts-identity';
import {
  ALICE,
  BOB,
  HOSTILE,
  failureState,
  listFixture,
  okState,
  source,
  sourceNotConnected,
  sourceUnknown,
  summary,
} from '@/test/identity-fixtures';

afterEach(() => cleanup());

function body(state: ReturnType<typeof okState<UserListResponse>> | ReturnType<typeof failureState<UserListResponse>>, page = 1) {
  return <UsersListBody state={state} page={page} pageSize={25} />;
}

describe('every outcome of the read has its own surface', () => {
  it('permission denied explains the missing permission and shows no data', () => {
    render(body(failureState<UserListResponse>('forbidden', 403)));
    const text = screen.getByRole('status').textContent ?? '';
    assert.match(text, /not available to your role/);
    assert.match(text, /users:read/);
    assert.equal(screen.queryAllByRole('table').length, 0);
  });

  it('an unauthenticated session is asked to sign in', () => {
    render(body(failureState<UserListResponse>('unauthenticated', 401)));
    assert.ok(screen.getByRole('link', { name: /Sign in/ }));
  });

  it('an API error is an error, not an empty list', () => {
    render(body(failureState<UserListResponse>('error', 500)));
    assert.match(document.body.textContent ?? '', /Unable to load data/);
    assert.equal(screen.queryAllByRole('table').length, 0);
  });

  it('a rate limit is reported as such', () => {
    render(body(failureState<UserListResponse>('rate_limited', 429)));
    assert.match(document.body.textContent ?? '', /Too many requests/);
  });

  it('nothing configured is not-connected and never a count of zero people', () => {
    render(body(okState(listFixture({ state: 'not-connected', items: [], total: 0, sources: [sourceNotConnected('wazuh'), sourceNotConnected('netbox')] }))));
    const text = screen.getByRole('status').textContent ?? '';
    assert.match(text, /not connected/i);
    assert.match(text, /not the same as having none/);
    assert.equal(screen.queryAllByRole('table').length, 0);
    assert.doesNotMatch(document.body.textContent ?? '', /\b0 people\b/);
    assert.match(document.body.textContent ?? '', /wazuh/);
  });

  it('a failing source is unknown and nothing is estimated', () => {
    render(body(okState(listFixture({ state: 'unknown', items: [], total: 0, sources: [sourceUnknown('wazuh')] }))));
    const text = screen.getByRole('status').textContent ?? '';
    assert.match(text, /state unknown/i);
    assert.match(text, /Nothing is estimated/);
  });

  it('an ok read with nobody is empty and says that is not the same as nobody existing', () => {
    render(body(okState(listFixture({ items: [], total: 0 }))));
    const text = screen.getByRole('status').textContent ?? '';
    assert.match(text, /No people found in the evidence/);
    assert.match(text, /not proof that nobody/i);
  });
});

describe('the data surface', () => {
  it('lists each person with a link to the profile and the basis of their presence', () => {
    render(body(okState(listFixture())));
    const table = screen.getByRole('table');
    const rows = within(table).getAllByRole('row');
    assert.equal(rows.length, 3); // header + two people
    const alice = within(table).getByRole('link', { name: 'Alice Example' });
    assert.equal(alice.getAttribute('href'), `/users/${ALICE.id}`);
    assert.equal(within(table).getByRole('link', { name: 'Bob Example' }).getAttribute('href'), `/users/${BOB.id}`);
    const aliceRow = rows[1].textContent ?? '';
    assert.match(aliceRow, /Observed/);
    assert.match(aliceRow, /Current session/);
    const bobRow = rows[2].textContent ?? '';
    assert.match(bobRow, /Unknown/);
    assert.match(bobRow, /No session evidence/);
    assert.doesNotMatch(bobRow, /offline/i);
  });

  it('shows when the evidence was read and the window it covers', () => {
    render(body(okState(listFixture())));
    const text = document.body.textContent ?? '';
    assert.match(text, /as of 2026-10-11 12:00:00 UTC/i);
    assert.match(text, /2 people/);
  });

  it('renders hostile names as text and keeps the link target a person id', () => {
    const state = okState(listFixture({ items: [summary({ display_name: HOSTILE })], total: 1 }));
    const { container } = render(body(state));
    assert.ok((container.textContent ?? '').includes(HOSTILE));
    assert.equal(container.querySelector('img'), null);
    assert.ok(screen.getByRole('link', { name: HOSTILE }).getAttribute('href')?.startsWith('/users/person-'));
  });

  it('an unnamed person is labelled, never blank', () => {
    render(body(okState(listFixture({ items: [summary({ display_name: null })], total: 1 }))));
    assert.ok(screen.getByRole('link', { name: 'Unnamed person' }));
  });

  it('a partial read names the source that failed and keeps showing what was read', () => {
    render(body(okState(listFixture({ sources: [source(), sourceUnknown('netbox')] }))));
    assert.match(document.body.textContent ?? '', /netbox: could not be read/);
    assert.equal(screen.getAllByRole('row').length, 3);
  });

  it('a stale source is called out', () => {
    const stale = source({ freshness: { state: 'stale', observed_at: '2026-10-11T08:00:00Z', source: 'wazuh' } });
    render(body(okState(listFixture({ sources: [stale] }))));
    assert.match(document.body.textContent ?? '', /wazuh: last evidence 2026-10-11 08:00:00 UTC/);
  });

  it('pages only where more people exist', () => {
    render(body(okState(listFixture({ total: 60, page: 2 })), 2));
    const nav = screen.getByRole('navigation', { name: 'People pages' });
    assert.equal(within(nav).getByRole('link', { name: /Previous/ }).getAttribute('href'), '/users?page=1');
    assert.equal(within(nav).getByRole('link', { name: /Next/ }).getAttribute('href'), '/users?page=3');
  });

  it('has no pager when everyone fits on the page', () => {
    render(body(okState(listFixture())));
    assert.equal(screen.queryAllByRole('navigation', { name: 'People pages' }).length, 0);
  });

  it('shows no behaviour, risk or activity score: none exists as data', () => {
    render(body(okState(listFixture())));
    assert.doesNotMatch(document.body.textContent ?? '', /behaviou?r|risk score|at risk|anomal/i);
  });
});
