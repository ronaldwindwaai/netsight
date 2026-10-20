import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, it } from 'node:test';

import { cleanup, render, screen, within } from '@testing-library/react';

import { IncidentRelatedLinks } from '@/components/incident-related-links';

afterEach(() => cleanup());

it('links onward to alerts, diagnostics, configuration changes and action requests', () => {
  render(<IncidentRelatedLinks />);
  const nav = screen.getByRole('navigation', { name: 'Investigate next' });
  const hrefs = within(nav).getAllByRole('link').map((a) => a.getAttribute('href'));
  assert.deepEqual(hrefs, ['/alerts', '/diagnostics', '/config/changes', '/actions']);
});
