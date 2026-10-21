'use client';

import { useId, useRef, useState, useTransition } from 'react';
import type { KeyboardEvent } from 'react';
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
  const buttonRef = useRef<HTMLButtonElement>(null);
  const panelId = useId();

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

  const label = session.email ?? session.identity_id;

  function closeOnEscape(event: KeyboardEvent<HTMLDivElement>) {
    if (event.key !== 'Escape' || !open) return;
    event.preventDefault();
    setOpen(false);
    buttonRef.current?.focus();
  }

  return (
    <div className="dropdown" onKeyDown={closeOnEscape}>
      <button
        ref={buttonRef}
        type="button"
        className="btn btn-sm btn-outline-secondary d-inline-flex align-items-center gap-2"
        aria-expanded={open}
        aria-controls={panelId}
        aria-label={`Account menu: ${label}`}
        onClick={() => setOpen((value) => !value)}
      >
        <span className="identity-avatar" aria-hidden="true">
          {initials(session.email, session.identity_id)}
        </span>
        <span className="d-none d-md-inline" aria-hidden="true">
          {label}
        </span>
        <i className="bi bi-chevron-down fs-7" aria-hidden="true" />
      </button>
      {open ? (
        <div id={panelId} className="dropdown-menu dropdown-menu-end show p-2">
          <p className="mb-1 px-2">
            <strong>{label}</strong>
            <small className="d-block text-body-secondary">via {session.provider}</small>
          </p>
          {session.roles.length > 0 ? (
            <p className="mb-1 px-2">
              <small className="d-block text-body-secondary">Roles</small>
              {session.roles.map((role) => (
                <span key={role} className="badge text-bg-secondary me-1">
                  {role}
                </span>
              ))}
            </p>
          ) : null}
          <hr className="dropdown-divider" />
          <button type="button" className="dropdown-item text-danger" disabled={signingOut} onClick={signOut}>
            <i className="bi bi-box-arrow-right me-2" aria-hidden="true" />
            {signingOut ? 'Signing out…' : 'Sign out'}
          </button>
          {error !== null ? (
            <p className="small text-danger px-2 mb-0" role="alert">
              {error}
            </p>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
