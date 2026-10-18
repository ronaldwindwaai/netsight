import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';

import { ConnectivityBanner } from '@/components/connectivity-banner';
import { MobileNav } from '@/components/mobile-nav';
import { pathnameSpy } from '@/test/next-navigation-stub';

afterEach(() => {
  cleanup();
  pathnameSpy.value = '/';
});

/** The always-present live region the banner writes into. */
const region = () => screen.getByRole('status');

function setOnline(value: boolean) {
  Object.defineProperty(window.navigator, 'onLine', { configurable: true, get: () => value });
}

describe('the connectivity banner', () => {
  it('keeps an empty live region mounted while online and fresh, so later notices are announced', () => {
    setOnline(true);
    render(<ConnectivityBanner />);
    assert.equal(region().textContent, '');
    assert.equal(region().getAttribute('aria-live'), 'polite');
  });

  it('says offline, not live, with the load time, when the connection drops, and clears when it returns', () => {
    setOnline(true);
    render(<ConnectivityBanner />);
    act(() => {
      setOnline(false);
      window.dispatchEvent(new window.Event('offline'));
    });
    const banner = region();
    assert.match(banner.textContent ?? '', /offline/i);
    assert.match(banner.textContent ?? '', /not live/i);
    assert.match(banner.textContent ?? '', /UTC/);
    act(() => {
      setOnline(true);
      window.dispatchEvent(new window.Event('online'));
    });
    assert.equal(region().textContent, '');
  });

  it('starts offline when the page is mounted without a connection', () => {
    setOnline(false);
    render(<ConnectivityBanner />);
    assert.match(region().textContent ?? '', /offline/i);
    setOnline(true);
  });

  it('warns that data may be out of date once the page has aged past the threshold', async () => {
    setOnline(true);
    render(<ConnectivityBanner staleAfterMs={5} checkEveryMs={5} />);
    await waitFor(() => assert.match(region().textContent ?? '', /out of date/i));
    assert.ok(screen.getByRole('button', { name: /reload/i }));
  });

  it('measures age from the latest page navigation, not from the first load of the layout', async () => {
    setOnline(true);
    const { rerender } = render(<ConnectivityBanner staleAfterMs={60} checkEveryMs={5} />);
    await waitFor(() => assert.match(region().textContent ?? '', /out of date/i));
    pathnameSpy.value = '/incidents';
    rerender(<ConnectivityBanner staleAfterMs={60} checkEveryMs={5} />);
    await waitFor(() => assert.equal(region().textContent, ''));
  });
});

describe('the mobile navigation bar', () => {
  it('is a labelled navigation with big touch targets for the permitted pages only', () => {
    render(<MobileNav permissions={['diagnostics:read']} />);
    const nav = screen.getByRole('navigation', { name: /mobile/i });
    const links = [...nav.querySelectorAll('a')];
    assert.deepEqual(
      links.map((link) => [link.textContent?.trim(), link.getAttribute('href')]),
      [
        ['Overview', '/overview'],
        ['Incidents', '/incidents'],
        ['Diagnostics', '/diagnostics'],
      ],
    );
    assert.ok(links.every((link) => link.classList.contains('mobile-nav__link')));
    assert.match(nav.className, /d-lg-none/);
  });

  it('shows Internet when the session may read it and nothing extra without a session', () => {
    const { unmount } = render(<MobileNav permissions={['internet:read']} />);
    assert.ok(screen.getByRole('link', { name: /internet/i }));
    unmount();
    render(<MobileNav permissions={null} />);
    assert.equal(screen.queryByRole('link', { name: /internet|diagnostics/i }), null);
  });
});
