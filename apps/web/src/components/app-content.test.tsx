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

  it('renders exactly one h1 when there is a title and breadcrumbs', () => {
    render(
      <AppContent title="Devices" breadcrumbs={[{ label: 'Overview', href: '/overview' }, { label: 'Devices' }]}>
        body
      </AppContent>,
    );

    assert.equal(screen.getAllByRole('heading', { level: 1 }).length, 1);
  });

  it('renders a breadcrumb-only header without any heading', () => {
    const { container } = render(
      <AppContent breadcrumbs={[{ label: 'Overview', href: '/overview' }, { label: 'Devices' }]}>body</AppContent>,
    );

    assert.ok(container.querySelector('.app-content-header'));
    assert.equal(screen.queryAllByRole('heading').length, 0);
  });

  it('treats empty breadcrumbs as none', () => {
    const { container } = render(<AppContent breadcrumbs={[]}>body</AppContent>);

    assert.equal(container.querySelector('.app-content-header'), null);
    assert.equal(screen.queryByRole('navigation', { name: 'Breadcrumb' }), null);
  });

  it('uses the narrow container only when fluid is false', () => {
    const fluid = render(<AppContent title="A">body</AppContent>);
    assert.equal(fluid.container.querySelectorAll('.container-fluid').length, 2);
    cleanup();

    const narrow = render(
      <AppContent title="A" fluid={false}>
        body
      </AppContent>,
    );
    assert.equal(narrow.container.querySelectorAll('.container-lg').length, 2);
    assert.equal(narrow.container.querySelector('.container-fluid'), null);
  });
});
