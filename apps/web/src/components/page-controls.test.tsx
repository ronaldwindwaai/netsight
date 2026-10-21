import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it } from 'node:test';

import { cleanup, render, screen } from '@testing-library/react';

import { PageControls } from '@/components/page-controls';
import { pathnameSpy } from '@/test/next-navigation-stub';

afterEach(() => cleanup());
beforeEach(() => {
  pathnameSpy.value = '/devices';
  window.history.replaceState(null, '', '/devices?q=core&page=2');
});

const props = { noun: 'devices', label: 'Device pages' };

describe('PageControls', () => {
  it('says how much of the data is loaded and that search covers only that', () => {
    render(<PageControls {...props} page={2} pageSize={50} total={230} count={50} />);
    const text = screen.getByRole('status').textContent ?? '';
    assert.match(text, /Showing 51.100 of 230 devices/);
    assert.match(text, /only look at the 50 loaded on this page/);
  });

  it('does not claim a partial view when everything is loaded', () => {
    render(<PageControls {...props} page={1} pageSize={50} total={12} count={12} />);
    assert.doesNotMatch(screen.getByRole('status').textContent ?? '', /only look/);
  });

  it('keeps the search when paging and resets to page 1 when the size changes', () => {
    render(<PageControls {...props} page={2} pageSize={50} total={230} count={50} />);
    assert.equal(screen.getByRole('link', { name: /Next/ }).getAttribute('href'), '/devices?q=core&page=3');
    assert.equal(screen.getByRole('link', { name: /Previous/ }).getAttribute('href'), '/devices?q=core');
    assert.equal(screen.getByRole('link', { name: '100 per page' }).getAttribute('href'), '/devices?q=core&page_size=100');
    assert.equal(screen.getByRole('link', { name: '50 per page' }).getAttribute('aria-current'), 'true');
  });

  it('disables Next on the last page', () => {
    render(<PageControls {...props} page={5} pageSize={50} total={230} count={30} />);
    assert.equal(screen.queryByRole('link', { name: /Next/ }), null);
  });
});
