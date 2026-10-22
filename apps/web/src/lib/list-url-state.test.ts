import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { listStateToSearch, parseListState, toggleSort } from './list-url-state.ts';
import type { ListSpec, ListState } from './list-url-state.ts';

const SPEC: ListSpec = {
  filters: { status: ['healthy', 'critical'], severity: ['low', 'high'] },
  sortKeys: ['name', 'status'],
};

function parse(query: string): ListState {
  return parseListState(new URLSearchParams(query), SPEC);
}

describe('parseListState', () => {
  it('defaults to an empty, unsorted state', () => {
    assert.deepEqual(parse(''), { q: '', filters: {}, sort: null });
  });

  it('reads search text, allowed filters and an ascending sort', () => {
    assert.deepEqual(parse('q=core&status=critical&sort=name'), {
      q: 'core',
      filters: { status: 'critical' },
      sort: { key: 'name', direction: 'asc' },
    });
  });

  it('reads a leading minus as descending', () => {
    assert.deepEqual(parse('sort=-status').sort, { key: 'status', direction: 'desc' });
  });

  it('ignores filter values, sort keys and filters it does not know', () => {
    assert.deepEqual(parse('status=bogus&sort=-evil&other=1'), { q: '', filters: {}, sort: null });
  });

  it('keeps typed spaces (it feeds a controlled input) and caps the search text', () => {
    assert.equal(parse(`q=${encodeURIComponent('hi ')}`).q, 'hi ');
    assert.equal(parse(`q=${'a'.repeat(500)}`).q.length, 128);
  });

  it('takes the first value when a parameter repeats', () => {
    assert.equal(parse('status=healthy&status=critical').filters.status, 'healthy');
  });
});

describe('listStateToSearch', () => {
  it('returns an empty string when nothing is set', () => {
    assert.equal(listStateToSearch(new URLSearchParams(''), { q: '', filters: {}, sort: null }, SPEC), '');
  });

  it('writes q, filters and a signed sort', () => {
    const state: ListState = { q: 'core sw', filters: { status: 'critical' }, sort: { key: 'name', direction: 'desc' } };
    assert.equal(
      listStateToSearch(new URLSearchParams(''), state, SPEC),
      '?q=core+sw&status=critical&sort=-name',
    );
  });

  it('drops a search that is only whitespace', () => {
    assert.equal(listStateToSearch(new URLSearchParams(''), { q: '   ', filters: {}, sort: null }, SPEC), '');
  });

  it('keeps unrelated parameters such as the page and drops cleared ones', () => {
    const state: ListState = { q: '', filters: {}, sort: null };
    assert.equal(listStateToSearch(new URLSearchParams('page=3&q=old&status=healthy'), state, SPEC), '?page=3');
  });

  it('round-trips through parse', () => {
    const state: ListState = { q: 'a&b=c', filters: { severity: 'high' }, sort: { key: 'status', direction: 'asc' } };
    const search = listStateToSearch(new URLSearchParams(''), state, SPEC);
    assert.deepEqual(parse(search.slice(1)), state);
  });
});

describe('toggleSort', () => {
  it('starts ascending, flips, and keeps it per column', () => {
    const first = toggleSort(null, 'name');
    assert.deepEqual(first, { key: 'name', direction: 'asc' });
    assert.deepEqual(toggleSort(first, 'name'), { key: 'name', direction: 'desc' });
    assert.deepEqual(toggleSort(first, 'status'), { key: 'status', direction: 'asc' });
  });
});
