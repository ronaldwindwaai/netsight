import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it } from 'node:test';

import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { DisplayPreferences } from '@/components/display-preferences';
import { PageControls } from '@/components/page-controls';
import { PreferencesPanel } from '@/components/preferences-panel';
import { areShortcutsEnabled } from '@/lib/keyboard-shortcuts';
import { PREFERENCE_KEYS } from '@/lib/preferences';
import { pathnameSpy } from '@/test/next-navigation-stub';

beforeEach(() => {
  window.localStorage.clear();
  delete document.documentElement.dataset.density;
});
afterEach(() => cleanup());

describe('PreferencesPanel', () => {
  it('turns the keyboard shortcut off and on through the same key the shortcut reads', async () => {
    const user = userEvent.setup();
    render(<PreferencesPanel />);
    const toggle = screen.getByRole('switch', { name: 'Keyboard shortcuts' });
    assert.equal((toggle as HTMLInputElement).checked, true);
    await user.click(toggle);
    assert.equal(window.localStorage.getItem(PREFERENCE_KEYS.shortcuts), 'off');
    assert.equal(areShortcutsEnabled(), false);
    await user.click(toggle);
    assert.equal(window.localStorage.getItem(PREFERENCE_KEYS.shortcuts), null);
    assert.equal(areShortcutsEnabled(), true);
  });

  it('shows stored values on load and labels every control', () => {
    window.localStorage.setItem(PREFERENCE_KEYS.shortcuts, 'off');
    window.localStorage.setItem(PREFERENCE_KEYS.density, 'compact');
    window.localStorage.setItem(PREFERENCE_KEYS.pageSize, '100');
    render(<PreferencesPanel />);
    assert.equal((screen.getByRole('switch', { name: 'Keyboard shortcuts' }) as HTMLInputElement).checked, false);
    assert.equal((screen.getByRole('radio', { name: 'Compact' }) as HTMLInputElement).checked, true);
    assert.equal((screen.getByRole('combobox', { name: 'Rows per page in lists' }) as HTMLSelectElement).value, '100');
  });

  it('saves density and page size', async () => {
    const user = userEvent.setup();
    render(
      <>
        <DisplayPreferences />
        <PreferencesPanel />
      </>,
    );
    await user.click(screen.getByRole('radio', { name: 'Compact' }));
    assert.equal(window.localStorage.getItem(PREFERENCE_KEYS.density), 'compact');
    assert.equal(document.documentElement.dataset.density, 'compact');
    await user.selectOptions(screen.getByRole('combobox', { name: 'Rows per page in lists' }), '25');
    assert.equal(window.localStorage.getItem(PREFERENCE_KEYS.pageSize), '25');
  });

  it('still works for this page view, and says so, when storage is blocked', async () => {
    const user = userEvent.setup();
    const original = Object.getOwnPropertyDescriptor(Storage.prototype, 'setItem');
    Storage.prototype.setItem = () => {
      throw new Error('blocked');
    };
    try {
      render(<PreferencesPanel />);
      await user.click(screen.getByRole('radio', { name: 'Compact' }));
      assert.equal((screen.getByRole('radio', { name: 'Compact' }) as HTMLInputElement).checked, true);
      assert.match(screen.getByRole('status').textContent ?? '', /blocked saving/);
    } finally {
      if (original !== undefined) Object.defineProperty(Storage.prototype, 'setItem', original);
    }
  });
});

describe('the preferred list size', () => {
  beforeEach(() => {
    pathnameSpy.value = '/devices';
  });
  const props = { noun: 'devices', label: 'Device pages', page: 1, total: 230, count: 25 };

  it('is added to an address that does not say a size', () => {
    window.localStorage.setItem(PREFERENCE_KEYS.pageSize, '25');
    window.history.replaceState(null, '', '/devices?q=core');
    render(<PageControls {...props} pageSize={50} />);
    assert.equal(window.location.search, '?q=core&page_size=25');
  });

  it('never overrides a size in the address', () => {
    window.localStorage.setItem(PREFERENCE_KEYS.pageSize, '25');
    window.history.replaceState(null, '', '/devices?page_size=100');
    render(<PageControls {...props} pageSize={100} />);
    assert.equal(window.location.search, '?page_size=100');
  });

  it('keeps an explicit default size in links so it wins over the preference', () => {
    window.localStorage.setItem(PREFERENCE_KEYS.pageSize, '25');
    window.history.replaceState(null, '', '/devices?page_size=25');
    render(<PageControls {...props} pageSize={25} />);
    assert.equal(screen.getByRole('link', { name: '50 per page' }).getAttribute('href'), '/devices?page_size=50');
  });

  it('leaves the address alone with no preference', () => {
    window.history.replaceState(null, '', '/devices?q=core');
    render(<PageControls {...props} pageSize={50} />);
    assert.equal(window.location.search, '?q=core');
  });
});
