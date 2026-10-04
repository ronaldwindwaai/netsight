'use client';

import { useState, useTransition } from 'react';

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
  const [, startTransition] = useTransition();

  if (session === null) {
    return (
      <a className="btn btn-sm btn-outline-primary" href="/login">
        <i className="bi bi-box-arrow-in-right me-1" aria-hidden="true" />
        Sign in
      </a>
    );
  }

  async function signOut() {
    setSigningOut(true);
    try {
      const csrfResponse = await fetch('/auth/csrf', { cache: 'no-store' });
      const csrf = csrfResponse.ok ? ((await csrfResponse.json()) as { csrf_token: string }) : null;
      await fetch('/auth/logout', {
        method: 'POST',
        headers: csrf ? { 'X-CSRF-Token': csrf.csrf_token } : {},
        cache: 'no-store',
      });
    } finally {
      startTransition(() => {
        window.location.href = '/login';
      });
    }
  }

  return (
    <div className="dropdown">
      <button
        type="button"
        className="btn btn-sm btn-outline-secondary d-inline-flex align-items-center gap-2"
        aria-haspopup="true"
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
        </ul>
      ) : null}
    </div>
  );
}
