import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { DEFAULT_PAGE_SIZE, MAX_PAGE, PAGE_SIZES, describeRange, pageHref, parsePageParams } from './page-state.ts';

describe('parsePageParams', () => {
  it('defaults to page 1 and the default size', () => {
    assert.deepEqual(parsePageParams({}), { page: 1, pageSize: DEFAULT_PAGE_SIZE });
  });

  it('accepts only whole positive pages and the offered sizes', () => {
    assert.deepEqual(parsePageParams({ page: '3', page_size: '100' }), { page: 3, pageSize: 100 });
    assert.deepEqual(parsePageParams({ page: '0', page_size: '7' }), { page: 1, pageSize: DEFAULT_PAGE_SIZE });
    assert.deepEqual(parsePageParams({ page: '2.5' }), { page: 1, pageSize: DEFAULT_PAGE_SIZE });
    assert.deepEqual(parsePageParams({ page: ['4', '5'] }), { page: 4, pageSize: DEFAULT_PAGE_SIZE });
  });

  it('falls back to page 1 beyond the highest page the API accepts', () => {
    assert.equal(parsePageParams({ page: String(MAX_PAGE) }).page, MAX_PAGE);
    assert.equal(parsePageParams({ page: String(MAX_PAGE + 1) }).page, 1);
    assert.equal(parsePageParams({ page: '999999999' }).page, 1);
  });

  it('only offers sizes the API accepts (max 100)', () => {
    assert.ok(PAGE_SIZES.every((size) => size >= 1 && size <= 100));
    assert.ok(PAGE_SIZES.includes(DEFAULT_PAGE_SIZE));
  });
});

describe('describeRange', () => {
  it('reports a partial view and the range shown', () => {
    assert.deepEqual(describeRange({ page: 2, pageSize: 50, total: 230, count: 50 }), {
      from: 51, to: 100, total: 230, pages: 5, partial: true, hasPrevious: true, hasNext: true,
    });
  });

  it('is not partial when everything fits on one page', () => {
    const r = describeRange({ page: 1, pageSize: 50, total: 12, count: 12 });
    assert.equal(r.partial, false);
    assert.equal(r.hasNext, false);
    assert.equal(r.hasPrevious, false);
  });

  it('handles an empty page past the end', () => {
    const r = describeRange({ page: 9, pageSize: 50, total: 60, count: 0 });
    assert.equal(r.from, 0);
    assert.equal(r.to, 0);
    assert.equal(r.partial, true);
  });
});

describe('pageHref', () => {
  it('keeps unrelated parameters and omits defaults', () => {
    const current = new URLSearchParams('q=core&status=critical&page=3');
    assert.equal(pageHref('/devices', current, { page: 1, pageSize: DEFAULT_PAGE_SIZE }), '/devices?q=core&status=critical');
    assert.equal(
      pageHref('/devices', current, { page: 2, pageSize: 100 }),
      '/devices?q=core&status=critical&page=2&page_size=100',
    );
  });

  it('returns the bare path when nothing remains', () => {
    assert.equal(pageHref('/alerts', new URLSearchParams(), { page: 1, pageSize: DEFAULT_PAGE_SIZE }), '/alerts');
  });
});
