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
/** Page regions that must not be reachable while the drawer covers them (the header is handled separately). */
const BACKGROUND = ['.app-main', '.app-footer', '.mobile-nav'];
const HEADER = '.app-header';
/** Anything inside one of these is another overlay that owns Escape. */
const OVERLAY = '[role=dialog],[aria-modal=true],dialog[open],[popover]';
const SLOT_CLASS = 'mobile-drawer-slot';

/**
 * The close button's mount point is a DOM node the library does not render, so it is made when the
 * component subscribes (after mount, never while rendering) and removed when it unsubscribes.
 */
let closeSlot: HTMLElement | null = null;
function subscribeToCloseSlot(onChange: () => void): () => void {
  const created = createCloseSlot();
  closeSlot = created;
  onChange();
  return () => {
    created?.remove();
    if (closeSlot === created) closeSlot = null;
  };
}
const readCloseSlot = () => closeSlot;

/**
 * The library draws the open drawer over the menu toggle, so the drawer needs a close button of its own.
 * This creates (once the sidebar exists) the element at the top of the sidebar that button is rendered into.
 */
function createCloseSlot(): HTMLElement | null {
  const sidebar = document.querySelector<HTMLElement>('.app-sidebar');
  if (sidebar === null) return null;
  const slot = document.createElement('div');
  slot.className = SLOT_CLASS;
  sidebar.prepend(slot);
  return slot;
}

function drawerElements() {
  return {
    toggle: document.querySelector<HTMLButtonElement>(TOGGLE),
    sidebar: document.querySelector<HTMLElement>('.app-sidebar'),
  };
}

const inerted = new Set<HTMLElement>();

/** Makes every part of `container` inert except `keep` and the path of ancestors leading to it. */
function inertAround(container: HTMLElement, keep: HTMLElement | null) {
  for (const child of Array.from(container.children) as HTMLElement[]) {
    if (child === keep) continue;
    if (keep !== null && child.contains(keep)) inertAround(child, keep);
    else {
      child.inert = true;
      inerted.add(child);
    }
  }
}

/** Removes the page behind the open drawer (content, footer, bottom tab bar, header but for the toggle) from view. */
function setBackgroundInert(inert: boolean) {
  for (const element of inerted) element.inert = false;
  inerted.clear();
  for (const selector of BACKGROUND) {
    const region = document.querySelector<HTMLElement>(selector);
    if (region === null) continue;
    region.inert = inert;
    if (inert) inerted.add(region);
  }
  if (!inert) return;
  const header = document.querySelector<HTMLElement>(HEADER);
  if (header !== null) inertAround(header, drawerElements().toggle);
}

/** Scroll lock for the page behind the open drawer; remembers the inline value it replaced. */
let savedOverflow: string | null = null;
function setScrollLock(locked: boolean) {
  if (locked && savedOverflow === null) {
    savedOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
  } else if (!locked && savedOverflow !== null) {
    document.body.style.overflow = savedOverflow;
    savedOverflow = null;
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
  const slot = useSyncExternalStore(subscribeToCloseSlot, readCloseSlot, () => null);

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
        setScrollLock(false);
        wasOpen = false;
        return;
      }

      const open = document.body.classList.contains('sidebar-open');
      toggle.setAttribute('aria-label', open ? 'Close navigation menu' : 'Open navigation menu');
      toggle.setAttribute('aria-expanded', String(open));
      if (open && !wasOpen) {
        setBackgroundInert(true);
        setScrollLock(true);
        sidebar.inert = false;
        sidebar.querySelector<HTMLElement>(FOCUSABLE)?.focus();
      } else if (!open && wasOpen) {
        const active = document.activeElement;
        const focusWasInDrawer = active === null || active === document.body || sidebar.contains(active);
        setBackgroundInert(false);
        setScrollLock(false);
        sidebar.inert = true;
        if (focusWasInDrawer) toggle.focus();
      } else if (!open) {
        sidebar.inert = true;
      }
      wasOpen = open;
    }

    function onKeyDown(event: KeyboardEvent) {
      if (!wasOpen || event.defaultPrevented) return;
      // Escape belongs to whichever overlay (page finder, modal, menu) is on top, not to the drawer under it.
      if ((event.target as Element | null)?.closest?.(OVERLAY)) return;
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
      setScrollLock(false);
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
