import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it } from 'node:test';

import { act, cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { SEARCH_URL_DEBOUNCE_MS, useListUrlState } from '@/components/use-list-url-state';
import type { ListSpec } from '@/lib/list-url-state';
import { locationSpy } from '@/test/next-navigation-stub';

const SPEC = { filters: { status: ['ok', 'bad'] }, sortKeys: ['name'] } as const satisfies ListSpec;

function Harness() {
  const { state, update, clear } = useListUrlState(SPEC);
  return (
    <div>
      <input aria-label="search" onChange={(e) => update({ q: e.target.value }, 'replace')} value={state.q} />
      <button onClick={() => update({ filters: { status: 'bad' } })} type="button">bad</button>
      <button onClick={() => update({ sort: { key: 'name', direction: 'asc' } })} type="button">sort</button>
      <button onClick={clear} type="button">clear</button>
      <output>{`${state.filters.status ?? 'all'}|${state.sort?.key ?? '-'}`}</output>
    </div>
  );
}

const input = () => screen.getByLabelText('search') as HTMLInputElement;
const settle = () => act(() => new Promise<void>((resolve) => setTimeout(resolve, SEARCH_URL_DEBOUNCE_MS + 50)));

beforeEach(() => {
  locationSpy.deferred = true;
});
afterEach(() => {
  cleanup();
  locationSpy.deferred = false;
  window.history.replaceState(null, '', '/');
});

describe('useListUrlState', () => {
  it('keeps every typed character, including leading and inner spaces, while the URL lags', async () => {
    render(<Harness />);
    await userEvent.type(input(), ' ab cd');
    assert.equal(input().value, ' ab cd');
    await settle();
    assert.equal(input().value, ' ab cd');
    assert.equal(new URLSearchParams(window.location.search).get('q'), ' ab cd');
  });

  it('does not write the URL on every keystroke', async () => {
    render(<Harness />);
    await userEvent.type(input(), 'abc', { delay: null });
    assert.equal(window.location.search, '');
    await settle();
    assert.equal(window.location.search, '?q=abc');
  });

  it('searching replaces history and a status choice pushes it', async () => {
    const before = window.history.length;
    render(<Harness />);
    await userEvent.type(input(), 'abc');
    await settle();
    assert.equal(window.history.length, before, 'typing adds no history entry');
    await userEvent.click(screen.getByRole('button', { name: 'bad' }));
    assert.equal(window.history.length, before + 1, 'a chip adds one entry');
    assert.equal(new URLSearchParams(window.location.search).get('q'), 'abc', 'the typed text rides along');
  });

  it('Back restores the search text the URL held', async () => {
    window.history.replaceState(null, '', '/?q=first');
    render(<Harness />);
    await userEvent.click(screen.getByRole('button', { name: 'bad' }));
    await userEvent.clear(input());
    await userEvent.type(input(), 'second');
    await settle();
    assert.equal(window.location.search, '?q=second&status=bad');
    window.history.back();
    await waitFor(() => assert.equal(input().value, 'first'));
    assert.equal(screen.getByRole('status').textContent, 'all|-');
  });

  it('ignores invalid URL parameters: unknown status, unknown sort key', () => {
    window.history.replaceState(null, '', '/?status=nope&sort=-bogus&q=ok');
    render(<Harness />);
    assert.equal(screen.getByRole('status').textContent, 'all|-');
    assert.equal(input().value, 'ok');
  });

  it('truncates an over-long q from the URL', () => {
    window.history.replaceState(null, '', `/?q=${'x'.repeat(300)}`);
    render(<Harness />);
    assert.equal(input().value.length, 128);
  });

  describe('paging', () => {
    const params = () => new URLSearchParams(window.location.search);

    it('a search resets to page 1 through the router and keeps page_size, filters and sort', async () => {
      window.history.replaceState(null, '', '/?page=3&page_size=100&status=bad&sort=name');
      render(<Harness />);
      await userEvent.type(input(), 'ab');
      await settle();
      assert.equal(params().get('page'), null);
      assert.equal(params().get('page_size'), '100');
      assert.equal(params().get('q'), 'ab');
      assert.equal(params().get('status'), 'bad');
      assert.equal(params().get('sort'), 'name');
    });

    it('a filter change and Clear filters reset to page 1', async () => {
      window.history.replaceState(null, '', '/?page=2&page_size=25');
      render(<Harness />);
      await userEvent.click(screen.getByRole('button', { name: 'bad' }));
      assert.equal(params().get('page'), null);
      assert.equal(params().get('page_size'), '25');
      window.history.replaceState(null, '', '/?page=4&q=x&status=bad');
      await userEvent.click(screen.getByRole('button', { name: 'clear' }));
      assert.equal(params().get('page'), null);
      assert.equal(params().get('status'), null);
    });

    it('sorting keeps the current page', async () => {
      window.history.replaceState(null, '', '/?page=2');
      render(<Harness />);
      await userEvent.click(screen.getByRole('button', { name: 'sort' }));
      assert.equal(params().get('page'), '2');
      assert.equal(params().get('sort'), 'name');
    });
  });
});
