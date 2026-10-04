import Link from 'next/link';

import { apiGet } from '@/lib/api';
import { parseAuthProviders } from '@/lib/api-contracts';

const PROVIDERS = [
  {
    id: 'microsoft',
    name: 'Microsoft 365',
    icon: 'bi bi-microsoft',
    href: '/auth/login/microsoft',
  },
  {
    id: 'google',
    name: 'Google Workspace',
    icon: 'bi bi-google',
    href: '/auth/login/google',
  },
] as const;

function LoginSidebar() {
  return (
    <aside className="login-sidebar">
      <div className="login-sidebar__brand">
        <span className="login-sidebar__logo" aria-hidden="true">
          N
        </span>
        <span>
          <strong>Netsight</strong>
          <small>Network Intelligence &amp; Operations</small>
        </span>
      </div>
      <nav className="login-sidebar__nav" aria-label="Main navigation">
        <span className="login-sidebar__item login-sidebar__item--active">
          <i className="bi bi-box-arrow-in-right" aria-hidden="true" />
          Login
        </span>
        <Link className="login-sidebar__item" href="/overview">
          <i className="bi bi-speedometer2" aria-hidden="true" />
          Overview
        </Link>
        <Link className="login-sidebar__item" href="/devices">
          <i className="bi bi-hdd-network" aria-hidden="true" />
          Devices
        </Link>
      </nav>
      <div className="login-sidebar__footer">
        <span>Netsight v1.0.0</span>
        <span>Built for a more resilient connected world.</span>
      </div>
    </aside>
  );
}

export default async function LoginPage() {
  const providersState = await apiGet('/api/v1/auth/providers', parseAuthProviders);
  const providers = providersState.kind === 'ok' ? providersState.data.providers : null;
  const configured = PROVIDERS.filter((provider) => providers?.[provider.id].configured);

  return (
    <main className="login-page">
      <LoginSidebar />
      <div className="login-main">
        <section className="login-card" aria-labelledby="login-title">
          <div className="login-card__brand">
            <span className="login-card__logo" aria-hidden="true">
              N
            </span>
            <span className="login-card__wordmark">
              <strong>NETSIGHT</strong>
              <small>Secure Network Operations Platform</small>
            </span>
          </div>

          <h1 id="login-title" className="login-card__title">
            Sign in with your organisation account
          </h1>
          <p className="login-card__subtitle">
            Access Netsight to monitor, secure and operate your network infrastructure.
          </p>

          {configured.length > 0 ? (
            <div className="login-card__actions">
              {configured.map((provider) => (
                <a key={provider.id} className="login-sso-btn" href={provider.href}>
                  <i className={provider.icon} aria-hidden="true" />
                  <span>Continue with {provider.name}</span>
                  <i className="bi bi-arrow-right" aria-hidden="true" />
                </a>
              ))}
            </div>
          ) : (
            <div className="login-card__empty" role="status">
              <i className="bi bi-shield-lock" aria-hidden="true" />
              <p>
                No identity provider is connected on this deployment. Ask your Netsight administrator
                to configure Microsoft 365 or Google Workspace sign-in.
              </p>
            </div>
          )}

          <div className="login-card__assurance">
            <i className="bi bi-shield-check" aria-hidden="true" />
            <span>MFA and organisation access policies apply.</span>
          </div>

          <p className="login-card__tagline">See everything. Know why. Act securely.</p>
        </section>
      </div>
    </main>
  );
}
