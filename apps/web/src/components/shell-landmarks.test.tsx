import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { DashboardLayout } from '@adminlte/react';
import { cleanup, render } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { PageFinder } from '@/components/page-finder';
import { menuItemsFor } from '@/lib/menu';
import { pageTargetsFrom } from '@/lib/page-finder';

afterEach(() => cleanup());

function renderShell() {
  const items = menuItemsFor([]);
  return render(
    <DashboardLayout
      menuItems={items}
      topbarStart={<PageFinder pages={pageTargetsFrom(items)} />}
      topbarEnd={<a href="/login">Sign in</a>}
    >
      <h1>Page</h1>
    </DashboardLayout>,
    { container: document.body.appendChild(document.createElement('div')) },
  );
}

describe('the app shell landmarks', () => {
  it('has exactly one main landmark, which the skip link targets', () => {
    renderShell();
    const mains = document.querySelectorAll('main, [role="main"]');
    assert.equal(mains.length, 1);
    const skip = document.querySelector('.skip-links a');
    assert.ok(skip, 'the shell provides a skip link');
    assert.equal(skip.textContent, 'Skip to main content');
    const target = document.querySelector(skip.getAttribute('href') ?? '#none');
    assert.equal(target, mains[0]);
    assert.equal(mains[0].getAttribute('tabindex'), '-1');
  });

  it('makes the skip link the first Tab stop, before the page finder', async () => {
    renderShell();
    await userEvent.tab();
    assert.equal(document.activeElement?.textContent, 'Skip to main content');
  });

  it('does not render a second skip link of its own', () => {
    renderShell();
    const labels = Array.from(document.querySelectorAll('a')).filter((a) => /skip to main/i.test(a.textContent ?? ''));
    assert.equal(labels.length, 1);
  });
});
