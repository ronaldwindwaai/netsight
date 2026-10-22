import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen, within } from '@testing-library/react';

import { RelatedViews } from '@/components/related-views';

afterEach(() => cleanup());

describe('related views', () => {
  it('lists every view as a link inside a named navigation', () => {
    render(
      <RelatedViews
        views={[
          { label: 'Alerts', href: '/alerts', hint: 'Open alerts' },
          { label: 'Traffic', href: '/traffic', hint: 'Flow evidence' },
        ]}
      />,
    );
    const nav = screen.getByRole('navigation', { name: 'Related views' });
    const links = within(nav).getAllByRole('link');
    assert.deepEqual(
      links.map((link) => [link.textContent, link.getAttribute('href')]),
      [
        ['Alerts', '/alerts'],
        ['Traffic', '/traffic'],
      ],
    );
  });
});
