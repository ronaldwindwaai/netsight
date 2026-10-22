import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

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

const BUTTON_NAME = /^Account menu: local:demo\.admin$/;

describe('IdentityMenu', () => {
  it('names the account button exactly, even when the label text is hidden on small screens', () => {
    render(<IdentityMenu session={session} />);

    const button = screen.getByRole('button', { name: BUTTON_NAME });
    assert.equal(button.getAttribute('aria-expanded'), 'false');
  });

  it('keeps the avatar initials out of the button text so the visible text matches the name', () => {
    render(<IdentityMenu session={session} />);

    const avatar = screen.getByRole('button', { name: BUTTON_NAME }).querySelector('.identity-avatar');
    assert.equal(avatar?.getAttribute('data-initials'), 'LA');
    assert.equal(avatar?.textContent, '');
  });

  it('opens a plain disclosure, not an ARIA menu, and closes on Escape with focus back on the button', async () => {
    const user = userEvent.setup();
    render(<IdentityMenu session={session} />);
    const button = screen.getByRole('button', { name: BUTTON_NAME });

    await user.click(button);
    assert.equal(button.getAttribute('aria-expanded'), 'true');
    assert.equal(screen.queryByRole('menu'), null);
    assert.equal(screen.queryByRole('menuitem'), null);
    assert.ok(screen.getByRole('button', { name: 'Sign out' }));
    assert.ok(screen.getByText('administrator'));

    await user.keyboard('{Escape}');
    assert.equal(button.getAttribute('aria-expanded'), 'false');
    assert.equal(screen.queryByRole('button', { name: 'Sign out' }), null);
    assert.equal(document.activeElement, button);
  });

  it('offers sign in when there is no session', () => {
    render(<IdentityMenu session={null} />);

    assert.equal(screen.getByRole('link', { name: /Sign in/ }).getAttribute('href'), '/login');
  });
});
