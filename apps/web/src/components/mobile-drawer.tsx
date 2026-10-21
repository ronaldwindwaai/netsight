'use client';

import { useEffect, useSyncExternalStore } from 'react';
import { createPortal } from 'react-dom';
import { usePathname } from 'next/navigation';

import { trapIndex } from '@/lib/focus-trap';

/** Bootstrap's lg breakpoint: below it the sidebar is an off-canvas drawer. */
const DRAWER_QUERY = '(max-width: 991.98px)';
const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled])';
const TOGGLE = '.app-header button[title="Toggle sidebar"]';
const SIDEBAR_ID = 'app-sidebar';
/** Page regions that must not be reachable while the drawer covers them. */
const BACKGROUND = ['.app-main', '.app-footer'];

/**
 * The library draws the open drawer over the menu toggle, so the drawer needs a close button of its own.
 * This is the (lazily created, cached) element at the top of the sidebar that button is rendered into.
 */
let closeSlot: HTMLElement | null = null;
function getCloseSlot(): HTMLElement | null {
  if (closeSlot !== null && closeSlot.isConnected) return closeSlot;
  const sidebar = document.querySelector<HTMLElement>('.app-sidebar');
  if (sidebar === null) return null;
  closeSlot = document.createElement('div');
  closeSlot.className = 'mobile-drawer-slot';
  sidebar.prepend(closeSlot);
  return closeSlot;
}
const noSubscription = () => () => undefined;

function drawerElements() {
  return {
    toggle: document.querySelector<HTMLButtonElement>(TOGGLE),
    sidebar: document.querySelector<HTMLElement>('.app-sidebar'),
  };
}

function setBackgroundInert(inert: boolean) {
  for (const selector of BACKGROUND) {
    const region = document.querySelector<HTMLElement>(selector);
    if (region !== null) region.inert = inert;
  }
}

/**
 * Accessibility for the off-canvas navigation drawer on phones and tablets. @adminlte/react toggles
 * the drawer with a body class and gives its button only a tooltip title, so this layer adds what the
 * library does not: a named, expanded/collapsed toggle; focus moved into the drawer on open and back
 * to the toggle on close; Tab kept inside the drawer; Escape to close; the closed drawer and, while
 * open, the page behind it removed from the tab order and the accessibility tree; and the drawer
 * closed after navigating. On wide screens it only restores a plain toggle label. It renders nothing.
 */
export function MobileDrawer() {
  const pathname = usePathname();
  const slot = useSyncExternalStore(noSubscription, getCloseSlot, () => null);

  useEffect(() => {
    const media = window.matchMedia(DRAWER_QUERY);
    let wasOpen = false;

    function sync() {
      const { toggle, sidebar } = drawerElements();
      if (toggle === null || sidebar === null) return;
      if (sidebar.id === '') sidebar.id = SIDEBAR_ID;
      toggle.setAttribute('aria-controls', sidebar.id);

      if (!media.matches) {
        toggle.setAttribute('aria-label', 'Toggle navigation menu');
        toggle.removeAttribute('aria-expanded');
        sidebar.inert = false;
        setBackgroundInert(false);
        wasOpen = false;
        return;
      }

      const open = document.body.classList.contains('sidebar-open');
      toggle.setAttribute('aria-label', open ? 'Close navigation menu' : 'Open navigation menu');
      toggle.setAttribute('aria-expanded', String(open));
      if (open && !wasOpen) {
        setBackgroundInert(true);
        sidebar.inert = false;
        sidebar.querySelector<HTMLElement>(FOCUSABLE)?.focus();
      } else if (!open && wasOpen) {
        const active = document.activeElement;
        const focusWasInDrawer = active === null || active === document.body || sidebar.contains(active);
        setBackgroundInert(false);
        sidebar.inert = true;
        if (focusWasInDrawer) toggle.focus();
      } else if (!open) {
        sidebar.inert = true;
      }
      wasOpen = open;
    }

    function onKeyDown(event: KeyboardEvent) {
      if (!wasOpen) return;
      const { toggle, sidebar } = drawerElements();
      if (toggle === null || sidebar === null) return;
      if (event.key === 'Escape') {
        event.preventDefault();
        toggle.click();
        return;
      }
      if (event.key !== 'Tab') return;
      // The toggle sits under the open drawer, so it is not a stop; the drawer's own close button is.
      const stops = [...sidebar.querySelectorAll<HTMLElement>(FOCUSABLE)];
      const index = trapIndex(stops.length, stops.indexOf(document.activeElement as HTMLElement), event.shiftKey);
      if (index < 0) return;
      event.preventDefault();
      stops[index].focus();
    }

    const observer = new MutationObserver(sync);
    observer.observe(document.body, { attributes: true, attributeFilter: ['class'] });
    media.addEventListener('change', sync);
    document.addEventListener('keydown', onKeyDown);
    sync();
    return () => {
      observer.disconnect();
      media.removeEventListener('change', sync);
      document.removeEventListener('keydown', onKeyDown);
      setBackgroundInert(false);
    };
  }, []);

  // Following a link in the drawer should land on the new page, not leave the menu covering it.
  useEffect(() => {
    if (document.body.classList.contains('sidebar-open') && window.matchMedia(DRAWER_QUERY).matches) {
      drawerElements().toggle?.click();
    }
  }, [pathname]);

  // On "Skip to navigation": below the breakpoint the menu is a drawer that is closed (and inert).
  useEffect(() => {
    function openForSkipLink(event: MouseEvent) {
      const link = (event.target as Element | null)?.closest('a[href="#navigation"]');
      if (link === null || link === undefined) return;
      if (!window.matchMedia(DRAWER_QUERY).matches || document.body.classList.contains('sidebar-open')) return;
      event.preventDefault();
      drawerElements().toggle?.click();
    }
    document.addEventListener('click', openForSkipLink);
    return () => document.removeEventListener('click', openForSkipLink);
  }, []);

  if (slot === null) return null;
  return createPortal(
    <button
      aria-label="Close navigation menu"
      className="mobile-drawer-close btn btn-sm"
      onClick={() => drawerElements().toggle?.click()}
      type="button"
    >
      <i aria-hidden="true" className="bi bi-x-lg" />
    </button>,
    slot,
  );
}
