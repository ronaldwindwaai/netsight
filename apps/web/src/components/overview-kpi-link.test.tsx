import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen } from '@testing-library/react';

import { OverviewKpiLink } from '@/components/overview-kpi-link';

afterEach(cleanup);

describe('OverviewKpiLink', () => {
  it('names a not-summarised tile by what it says, so the state is announced', () => {
    render(
      <OverviewKpiLink
        href="/security"
        icon="bi-shield-exclamation"
        label="Security"
        value="Not summarised"
        detail="Open security events"
        theme="secondary"
      />,
    );

    const link = screen.getByRole('link', { name: /Security/ });
    assert.match(link.textContent ?? '', /Not summarised/);
    assert.match(link.textContent ?? '', /Open security events/);
    assert.equal(link.getAttribute('aria-label'), null);
    assert.ok(link.className.includes('overview-kpi--unknown'));
  });

  it('shows a measured tile as known, with its value in the link text', () => {
    render(
      <OverviewKpiLink
        href="/devices"
        icon="bi-heart-pulse"
        label="Network health"
        value="50%"
        detail="1 need attention"
        theme="warning"
        progress={50}
      />,
    );

    const link = screen.getByRole('link', { name: /Network health/ });
    assert.match(link.textContent ?? '', /50%/);
    assert.equal(link.className.includes('overview-kpi--unknown'), false);
  });

  it('renders a tile without an href as text, not a link', () => {
    render(
      <OverviewKpiLink icon="bi-people" label="Users" value="Restricted" detail="needs a permission" theme="secondary" />,
    );

    assert.equal(screen.queryByRole('link'), null);
    assert.match(screen.getByText('Restricted').textContent ?? '', /Restricted/);
  });
});
