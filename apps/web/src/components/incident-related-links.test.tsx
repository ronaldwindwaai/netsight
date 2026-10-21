import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, it } from 'node:test';

import { cleanup, render, screen, within } from '@testing-library/react';

import { IncidentRelatedLinks } from '@/components/incident-related-links';

afterEach(() => cleanup());

it('links onward to everything for a viewer who holds every read permission', () => {
  render(<IncidentRelatedLinks permissions={['diagnostics:read', 'configuration:read', 'actions:read']} />);
  const nav = screen.getByRole('navigation', { name: 'Investigate next' });
  const hrefs = within(nav).getAllByRole('link').map((a) => a.getAttribute('href'));
  assert.deepEqual(hrefs, ['/alerts', '/diagnostics', '/config/changes', '/actions']);
});

it('offers only what the viewer can open', () => {
  render(<IncidentRelatedLinks permissions={['actions:read']} />);
  const hrefs = screen.getAllByRole('link').map((a) => a.getAttribute('href'));
  assert.deepEqual(hrefs, ['/alerts', '/actions']);
});

it('offers only the ungated link without permissions', () => {
  render(<IncidentRelatedLinks permissions={[]} />);
  assert.deepEqual(screen.getAllByRole('link').map((a) => a.getAttribute('href')), ['/alerts']);
});
