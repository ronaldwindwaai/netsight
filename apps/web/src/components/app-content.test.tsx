import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen } from '@testing-library/react';

import { AppContent } from '@/components/app-content';

afterEach(cleanup);

describe('AppContent', () => {
  it('renders the page title as the level-one heading', () => {
    render(<AppContent title="Devices">body</AppContent>);

    assert.equal(screen.getByRole('heading', { level: 1, name: 'Devices' }).textContent, 'Devices');
    assert.equal(screen.queryByRole('heading', { level: 3 }), null);
  });

  it('marks the last breadcrumb as the current page and links the others', () => {
    render(
      <AppContent
        title="Devices"
        breadcrumbs={[{ label: 'Overview', href: '/overview' }, { label: 'Devices' }]}
      >
        body
      </AppContent>,
    );

    assert.equal(screen.getByRole('link', { name: 'Overview' }).getAttribute('href'), '/overview');
    assert.equal(screen.getByText('Devices', { selector: 'li' }).getAttribute('aria-current'), 'page');
  });

  it('renders no header when there is neither a title nor breadcrumbs', () => {
    const { container } = render(<AppContent>body</AppContent>);

    assert.equal(container.querySelector('.app-content-header'), null);
    assert.ok(screen.getByText('body'));
  });
});
