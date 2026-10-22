import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it } from 'node:test';

import { act, cleanup, render, screen } from '@testing-library/react';
import { hydrateRoot } from 'react-dom/client';
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
    document.cookie = 'netsight_page_size=; Path=/; Max-Age=0';
  });
  const props = { noun: 'devices', label: 'Device pages', page: 1, total: 230, count: 25 };

  function countReplaces(): { readonly count: () => number; readonly restore: () => void } {
    const original = window.history.replaceState;
    let calls = 0;
    window.history.replaceState = (...args: Parameters<History['replaceState']>) => {
      calls += 1;
      original.apply(window.history, args);
    };
    return { count: () => calls, restore: () => void (window.history.replaceState = original) };
  }

  it('is added to an address that does not say a size, and the mirror cookie is set first', () => {
    window.localStorage.setItem(PREFERENCE_KEYS.pageSize, '25');
    window.history.replaceState(null, '', '/devices?q=core');
    render(<PageControls {...props} pageSize={50} />);
    assert.equal(window.location.search, '?q=core&page_size=25');
    assert.match(document.cookie, /netsight_page_size=25/);
  });

  it('keeps a bookmarked page when it adds the size', () => {
    window.localStorage.setItem(PREFERENCE_KEYS.pageSize, '25');
    window.history.replaceState(null, '', '/devices?page=3');
    render(<PageControls {...props} page={3} pageSize={50} />);
    assert.equal(window.location.search, '?page=3&page_size=25');
  });

  it('does nothing when the server already rendered the preferred size (cookie honoured)', () => {
    window.localStorage.setItem(PREFERENCE_KEYS.pageSize, '25');
    window.history.replaceState(null, '', '/devices?page=3');
    const spy = countReplaces();
    try {
      render(<PageControls {...props} page={3} pageSize={25} />);
      assert.equal(spy.count(), 0);
      assert.equal(window.location.search, '?page=3');
    } finally {
      spy.restore();
    }
  });

  it('replaces at most once, even when the page re-renders before the new size arrives', () => {
    window.localStorage.setItem(PREFERENCE_KEYS.pageSize, '25');
    window.history.replaceState(null, '', '/devices?q=core');
    const spy = countReplaces();
    try {
      const view = render(<PageControls {...props} pageSize={50} />);
      view.rerender(<PageControls {...props} pageSize={50} />);
      view.rerender(<PageControls {...props} pageSize={50} count={24} />);
      assert.equal(spy.count(), 1);
    } finally {
      spy.restore();
    }
  });

  it('never overrides a size in the address', () => {
    window.localStorage.setItem(PREFERENCE_KEYS.pageSize, '25');
    window.history.replaceState(null, '', '/devices?page_size=100');
    const spy = countReplaces();
    try {
      render(<PageControls {...props} pageSize={100} />);
      assert.equal(spy.count(), 0);
      assert.equal(window.location.search, '?page_size=100');
    } finally {
      spy.restore();
    }
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

describe('the mirror cookie', () => {
  it('follows the Preferences panel and is dropped for the default size', async () => {
    const user = userEvent.setup();
    document.cookie = 'netsight_page_size=; Path=/; Max-Age=0';
    render(
      <>
        <DisplayPreferences />
        <PreferencesPanel />
      </>,
    );
    await user.selectOptions(screen.getByRole('combobox', { name: 'Rows per page in lists' }), '100');
    assert.match(document.cookie, /netsight_page_size=100/);
    await user.selectOptions(screen.getByRole('combobox', { name: 'Rows per page in lists' }), '50');
    assert.doesNotMatch(document.cookie, /netsight_page_size=\d/);
  });
});

describe('DisplayPreferences while hydrating', () => {
  it('never overwrites the density the early script set with the default (no flicker)', async () => {
    window.localStorage.setItem(PREFERENCE_KEYS.density, 'compact');
    document.documentElement.dataset.density = 'compact';
    const seen: Array<string | null> = [];
    const observer = new window.MutationObserver((records) => {
      for (const record of records) seen.push(record.oldValue);
    });
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-density'], attributeOldValue: true });
    const container = document.createElement('div');
    document.body.append(container);
    let root!: ReturnType<typeof hydrateRoot>;
    await act(async () => {
      root = hydrateRoot(container, <DisplayPreferences />);
    });
    await act(async () => void (await new Promise((resolve) => setTimeout(resolve, 0))));
    seen.push(document.documentElement.getAttribute('data-density'), ...observer.takeRecords().map((r) => r.oldValue));
    observer.disconnect();
    act(() => root.unmount());
    container.remove();
    assert.ok(!seen.includes('comfortable'), `density passed through comfortable: ${JSON.stringify(seen)}`);
    assert.equal(document.documentElement.dataset.density, 'compact');
  });
});

describe('PageControls while hydrating', () => {
  it('does not replace the address with the defaults the first hydration pass sees', async () => {
    pathnameSpy.value = '/devices';
    window.localStorage.setItem(PREFERENCE_KEYS.pageSize, '25');
    window.history.replaceState(null, '', '/devices?page=3');
    let replaces = 0;
    const original = window.history.replaceState;
    window.history.replaceState = (...args: Parameters<History['replaceState']>) => {
      replaces += 1;
      original.apply(window.history, args);
    };
    const container = document.createElement('div');
    document.body.append(container);
    let root!: ReturnType<typeof hydrateRoot>;
    try {
      await act(async () => {
        root = hydrateRoot(container, <PageControls count={25} label="Device pages" noun="devices" page={3} pageSize={25} total={230} />);
      });
      assert.equal(replaces, 0);
      assert.equal(window.location.search, '?page=3');
    } finally {
      window.history.replaceState = original;
      act(() => root.unmount());
      container.remove();
    }
  });
});

describe('a choice that could not be saved', () => {
  it('stops overriding the stored value once another tab changes storage', async () => {
    const user = userEvent.setup();
    const original = Object.getOwnPropertyDescriptor(Storage.prototype, 'setItem');
    Storage.prototype.setItem = () => {
      throw new Error('blocked');
    };
    render(<PreferencesPanel />);
    try {
      await user.click(screen.getByRole('radio', { name: 'Compact' }));
    } finally {
      if (original !== undefined) Object.defineProperty(Storage.prototype, 'setItem', original);
    }
    assert.equal((screen.getByRole('radio', { name: 'Compact' }) as HTMLInputElement).checked, true);
    window.localStorage.setItem(PREFERENCE_KEYS.density, 'comfortable');
    act(() => void window.dispatchEvent(new window.StorageEvent('storage', { key: PREFERENCE_KEYS.density })));
    assert.equal((screen.getByRole('radio', { name: 'Comfortable' }) as HTMLInputElement).checked, true);
  });
});
