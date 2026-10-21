import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { AppRouterContext } from 'next/dist/shared/lib/app-router-context.shared-runtime';
import { cleanup, render, screen } from '@testing-library/react';

import { IdentityMenu } from '@/components/identity-menu';
import type { SessionInfo } from '@/lib/api-contracts';

afterEach(cleanup);

const session: SessionInfo = {
  authenticated: true,
  identity_id: 'local:demo.admin',
  provider: 'local',
  email: null,
  roles: ['administrator'],
  permissions: [],
};

const router = {
  back() {},
  forward() {},
  prefetch() {},
  push() {},
  refresh() {},
  replace() {},
};

describe('IdentityMenu', () => {
  it('names the account button even when the label text is hidden on small screens', () => {
    render(
      <AppRouterContext.Provider value={router}>
        <IdentityMenu session={session} />
      </AppRouterContext.Provider>,
    );

    const button = screen.getByRole('button', { name: 'Account menu for local:demo.admin' });
    assert.equal(button.getAttribute('aria-expanded'), 'false');
  });
});
