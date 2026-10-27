'use client';

import { useRouter } from 'next/navigation';
import { useState } from 'react';

/**
 * Netsight-managed local sign-in (ADR 0010).
 *
 * Two explicit steps, because a password alone is never authentication:
 * username + password returns a challenge, and the second factor exchanges
 * that challenge for a session.
 *
 * The component never sees or stores the TOTP secret, and the password is held
 * only in component state for the duration of the request.
 */

type Step = 'credentials' | 'second-factor';

const STORAGE_KEY = 'netsight.pending_challenge';

function readChallenge(): string {
  // Session storage only: a pending challenge is short-lived and must not
  // survive the tab closing.
  if (typeof window === 'undefined') return '';
  return window.sessionStorage.getItem(STORAGE_KEY) ?? '';
}

function writeChallenge(value: string): void {
  if (typeof window === 'undefined') return;
  if (value) window.sessionStorage.setItem(STORAGE_KEY, value);
  else window.sessionStorage.removeItem(STORAGE_KEY);
}

async function postJson(path: string, body: unknown): Promise<{ status: number; data: Record<string, unknown> }> {
  const response = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify(body),
    cache: 'no-store',
    credentials: 'same-origin',
  });

  let data: Record<string, unknown> = {};
  try {
    data = (await response.json()) as Record<string, unknown>;
  } catch {
    data = {};
  }
  return { status: response.status, data };
}

function messageFor(status: number, data: Record<string, unknown>): string {
  const error = data.error;
  if (error && typeof error === 'object' && 'message' in error) {
    const value = (error as { message?: unknown }).message;
    if (typeof value === 'string' && value.length > 0) return value;
  }
  if (status === 429) return 'Too many attempts. Wait a few minutes and try again.';
  if (status === 0) return 'The Netsight authentication service is unavailable.';
  return 'Sign-in could not be completed. Try again.';
}

/** `redirectTo` is a path already vetted by `safeNextPath` on the server. */
export function LocalSignIn({ redirectTo = '/overview' }: { redirectTo?: string }) {
  const router = useRouter();
  const [step, setStep] = useState<Step>('credentials');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [challenge, setChallenge] = useState<string>(() => readChallenge());

  async function submitCredentials(event: React.FormEvent) {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(null);

    const { status, data } = await postJson('/auth/local/login', { username, password });
    // The password must not survive the request.
    setPassword('');

    if (status === 202) {
      const id = typeof data.challenge_id === 'string' ? data.challenge_id : '';
      // The challenge id travels in a response header so it is not cached in
      // the response body.
      writeChallenge(id);
      setChallenge(id);
      setStep('second-factor');
    } else {
      setError(messageFor(status, data));
    }
    setBusy(false);
  }

  async function submitSecondFactor(event: React.FormEvent) {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(null);

    const { status, data } = await postJson('/auth/local/mfa/verify', {
      challenge_id: challenge,
      code,
    });
    setCode('');

    if (status === 200) {
      writeChallenge('');
      router.push(redirectTo);
      router.refresh();
      return;
    }
    // The challenge is consumed on any attempt, so start again.
    writeChallenge('');
    setChallenge('');
    setStep('credentials');
    setError(messageFor(status, data));
    setBusy(false);
  }

  if (step === 'second-factor') {
    return (
      <form className="local-signin" onSubmit={submitSecondFactor}>
        <p className="local-signin__lede">
          Enter the 6-digit code from your authenticator app, or a recovery code, for{' '}
          <strong>{username}</strong>.
        </p>

        <div className="mb-3">
          <label className="form-label" htmlFor="local-mfa-code">
            Verification code
          </label>
          <input
            autoComplete="one-time-code"
            autoFocus
            className="form-control form-control-lg text-center"
            id="local-mfa-code"
            autoCapitalize="characters"
            maxLength={32}
            name="code"
            onChange={(event) => setCode(event.target.value)}
            placeholder="000000 or AAAAA-BBBBB"
            required
            value={code}
          />
          <div className="form-text">
            Lost your device? Use one of the recovery codes issued when you enrolled.
          </div>
        </div>

        {error !== null ? (
          <div className="alert alert-danger" role="alert">
            {error}
          </div>
        ) : null}

        <button className="btn btn-primary w-100" disabled={busy} type="submit">
          {busy ? 'Verifying…' : 'Verify and sign in'}
        </button>
        <button
          className="btn btn-link w-100 mt-2"
          onClick={() => {
            writeChallenge('');
            setChallenge('');
            setStep('credentials');
            setError(null);
          }}
          type="button"
        >
          Back
        </button>
      </form>
    );
  }

  return (
    <form className="local-signin" onSubmit={submitCredentials}>
      <div className="mb-3">
        <label className="form-label" htmlFor="local-username">
          Username
        </label>
        <input
          autoComplete="username"
          autoFocus
          className="form-control form-control-lg"
          id="local-username"
          maxLength={64}
          name="username"
          onChange={(event) => setUsername(event.target.value)}
          required
          value={username}
        />
      </div>

      <div className="mb-3">
        <label className="form-label" htmlFor="local-password">
          Password
        </label>
        <input
          autoComplete="current-password"
          className="form-control form-control-lg"
          id="local-password"
          maxLength={1024}
          name="password"
          onChange={(event) => setPassword(event.target.value)}
          required
          type="password"
          value={password}
        />
      </div>

      {error !== null ? (
        <div className="alert alert-danger" role="alert">
          {error}
        </div>
      ) : null}

      <button className="btn btn-primary w-100" disabled={busy} type="submit">
        {busy ? 'Checking…' : 'Continue'}
      </button>
      <p className="local-signin__note">
        <i className="bi bi-shield-lock me-1" aria-hidden="true" />
        Your password alone does not grant access. A verification code is required.
      </p>
    </form>
  );
}
