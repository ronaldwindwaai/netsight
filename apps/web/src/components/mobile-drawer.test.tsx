import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it } from 'node:test';

import { act, cleanup, render } from '@testing-library/react';

import { MobileDrawer } from '@/components/mobile-drawer';

/** A minimal stand-in for the AdminLTE shell: header toggle, drawer with two links, and main content. */
function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attributes: Record<string, string>,
  text = '',
  children: readonly HTMLElement[] = [],
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(attributes)) node.setAttribute(name, value);
  node.textContent = text;
  node.append(...children);
  return node;
}

function mountShell() {
  const toggle = el('button', { type: 'button', title: 'Toggle sidebar', id: 'toggle' }, 'menu');
  document.body.replaceChildren(
    el('header', { class: 'app-header' }, '', [toggle, el('input', { id: 'finder' })]),
    el('aside', { class: 'app-sidebar' }, '', [el('a', { href: '/a', id: 'a' }, 'A'), el('a', { href: '/b', id: 'b' }, 'B')]),
    el('main', { class: 'app-main' }, '', [el('button', { id: 'content' }, 'content')]),
  );
  // The library flips a body class from the toggle; reproduce that.
  toggle.addEventListener('click', () => document.body.classList.toggle('sidebar-open'));
  return toggle;
}

function stubMedia(matches: boolean) {
  Object.defineProperty(window, 'matchMedia', {
    configurable: true,
    value: () => ({ matches, addEventListener() {}, removeEventListener() {} }),
  });
}

const settle = () => act(async () => void (await new Promise((resolve) => setTimeout(resolve, 0))));
const press = (key: string, shiftKey = false) =>
  act(() => void document.dispatchEvent(new window.KeyboardEvent('keydown', { key, shiftKey, bubbles: true, cancelable: true })));

beforeEach(() => stubMedia(true));
afterEach(() => {
  cleanup();
  document.body.replaceChildren();
  document.body.className = '';
});

describe('MobileDrawer on a phone', () => {
  it('names the toggle and keeps the closed drawer out of the tab order', async () => {
    const toggle = mountShell();
    render(<MobileDrawer />);
    await settle();
    assert.equal(toggle.getAttribute('aria-label'), 'Open navigation menu');
    assert.equal(toggle.getAttribute('aria-expanded'), 'false');
    assert.equal(toggle.getAttribute('aria-controls'), document.querySelector('.app-sidebar')?.id);
    assert.equal((document.querySelector('.app-sidebar') as HTMLElement).inert, true);
  });

  it('moves focus into the drawer on open, hides the page behind it and traps Tab', async () => {
    const toggle = mountShell();
    render(<MobileDrawer />);
    await settle();
    toggle.click();
    await settle();
    assert.equal(toggle.getAttribute('aria-expanded'), 'true');
    assert.equal(toggle.getAttribute('aria-label'), 'Close navigation menu');
    assert.equal(document.activeElement?.getAttribute('aria-label'), 'Close navigation menu');
    assert.equal((document.querySelector('.app-main') as HTMLElement).inert, true);
    assert.equal((document.querySelector('.app-sidebar') as HTMLElement).inert, false);

    (document.getElementById('b') as HTMLElement).focus();
    await press('Tab');
    assert.equal(
      document.activeElement?.getAttribute('aria-label'),
      'Close navigation menu',
      'Tab from the last link wraps to the drawer close button, not the page',
    );
    await press('Tab');
    assert.equal(document.activeElement?.id, 'a');
    await press('Tab', true);
    assert.equal(document.activeElement?.getAttribute('aria-label'), 'Close navigation menu');
  });

  it('closes on Escape and returns focus to the toggle', async () => {
    const toggle = mountShell();
    render(<MobileDrawer />);
    await settle();
    toggle.click();
    await settle();
    await press('Escape');
    await settle();
    assert.equal(document.body.classList.contains('sidebar-open'), false);
    assert.equal(document.activeElement, toggle);
    assert.equal((document.querySelector('.app-main') as HTMLElement).inert, false);
    assert.equal((document.querySelector('.app-sidebar') as HTMLElement).inert, true);
  });

  it('returns focus to the toggle when the drawer is dismissed by tapping outside it', async () => {
    const toggle = mountShell();
    render(<MobileDrawer />);
    await settle();
    toggle.click();
    await settle();
    (document.activeElement as HTMLElement).blur();
    document.body.classList.remove('sidebar-open');
    await settle();
    assert.equal(document.activeElement, toggle);
  });
});

describe('MobileDrawer controls', () => {
  it('closes from its own close button and returns focus to the toggle', async () => {
    const toggle = mountShell();
    render(<MobileDrawer />);
    await settle();
    toggle.click();
    await settle();
    (document.querySelector('.app-sidebar [aria-label="Close navigation menu"]') as HTMLElement).click();
    await settle();
    assert.equal(document.body.classList.contains('sidebar-open'), false);
    assert.equal(document.activeElement, toggle);
  });

  it('opens the drawer for the "Skip to navigation" link instead of jumping into the inert menu', async () => {
    const toggle = mountShell();
    const skip = document.createElement('a');
    skip.setAttribute('href', '#navigation');
    document.body.prepend(skip);
    render(<MobileDrawer />);
    await settle();
    skip.click();
    await settle();
    assert.equal(document.body.classList.contains('sidebar-open'), true);
    assert.equal(toggle.getAttribute('aria-expanded'), 'true');
  });
});

describe('MobileDrawer on a wide screen', () => {
  it('leaves the sidebar and page interactive and does not trap Tab', async () => {
    stubMedia(false);
    const toggle = mountShell();
    render(<MobileDrawer />);
    await settle();
    assert.equal(toggle.hasAttribute('aria-expanded'), false);
    assert.equal((document.querySelector('.app-sidebar') as HTMLElement).inert, false);
    assert.equal((document.querySelector('.app-main') as HTMLElement).inert, false);
  });
});
