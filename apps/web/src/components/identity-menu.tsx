'use client';

import { useState, useTransition } from 'react';
import { useRouter } from 'next/navigation';

import type { SessionInfo } from '@/lib/api-contracts';

function initials(email: string | null, identityId: string): string {
  const base = email?.split('@')[0] ?? identityId;
  const parts = base.split(/[._-]+/).filter(Boolean);
  if (parts.length === 0) return '?';
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[1][0]).toUpperCase();
}

export function IdentityMenu({ session }: { session: SessionInfo | null }) {
  const [open, setOpen] = useState(false);
  const [signingOut, setSigningOut] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [, startTransition] = useTransition();
  const router = useRouter();

  if (session === null) {
    return (
      <a className="btn btn-sm btn-outline-primary" href="/login">
        <i className="bi bi-box-arrow-in-right me-1" aria-hidden="true" />
        Sign in
      </a>
    );
  }

  async function completeSignOut() {
    startTransition(() => {
      router.push('/login');
    });
  }

  async function signOut() {
    setSigningOut(true);
    setError(null);
    try {
      const csrfResponse = await fetch('/auth/csrf', { cache: 'no-store' });
      if (!csrfResponse.ok) {
        throw new Error('Could not obtain a sign-out token.');
      }
      const payload = (await csrfResponse.json()) as { csrf_token?: unknown };
      if (typeof payload.csrf_token !== 'string' || payload.csrf_token.length === 0) {
        throw new Error('Could not obtain a sign-out token.');
      }

      const logoutResponse = await fetch('/auth/logout', {
        method: 'POST',
        headers: { 'X-CSRF-Token': payload.csrf_token },
        cache: 'no-store',
      });
      if (!logoutResponse.ok) {
        throw new Error('Sign-out was rejected by the Netsight API.');
      }
      await completeSignOut();
    } catch {
      setSigningOut(false);
      setError('Sign-out failed. Reload and try again.');
    }
  }

  return (
    <div className="dropdown">
      <button
        type="button"
        className="btn btn-sm btn-outline-secondary d-inline-flex align-items-center gap-2"
        aria-haspopup="true"
        aria-label={`Account menu for ${session.email ?? session.identity_id}`}
        aria-expanded={open}
        onClick={() => setOpen((value) => !value)}
      >
        <span className="identity-avatar" aria-hidden="true">
          {initials(session.email, session.identity_id)}
        </span>
        <span className="d-none d-md-inline">{session.email ?? session.identity_id}</span>
        <i className="bi bi-chevron-down fs-7" aria-hidden="true" />
      </button>
      {open ? (
        <ul className="dropdown-menu dropdown-menu-end show" role="menu">
          <li className="dropdown-header">
            <strong>{session.email ?? session.identity_id}</strong>
            <small className="d-block text-body-secondary">via {session.provider}</small>
          </li>
          {session.roles.length > 0 ? (
            <li>
              <span className="dropdown-item-text">
                <small className="d-block text-body-secondary">Roles</small>
                {session.roles.map((role) => (
                  <span key={role} className="badge text-bg-secondary me-1">
                    {role}
                  </span>
                ))}
              </span>
            </li>
          ) : null}
          <li>
            <hr className="dropdown-divider" />
          </li>
          <li>
            <button
              type="button"
              className="dropdown-item text-danger"
              role="menuitem"
              disabled={signingOut}
              onClick={signOut}
            >
              <i className="bi bi-box-arrow-right me-2" aria-hidden="true" />
              {signingOut ? 'Signing out…' : 'Sign out'}
            </button>
          </li>
          {error !== null ? (
            <li>
              <span className="dropdown-item-text small text-danger" role="alert">
                {error}
              </span>
            </li>
          ) : null}
        </ul>
      ) : null}
    </div>
  );
}
