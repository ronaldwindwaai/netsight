import { LocalSignIn } from '@/components/local-signin';
import { apiGet } from '@/lib/api';
import { parseAuthProviders } from '@/lib/api-contracts';
import { providerLoginHref, safeNextPath } from '@/lib/sign-in-redirect';

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
      <div className="login-sidebar__footer">
        <span>Access is enforced by the Netsight API.</span>
        <span>Every page needs a signed-in session.</span>
      </div>
    </aside>
  );
}

type LoginSearch = Promise<{ step_up?: string | string[]; next?: string | string[] }>;

export default async function LoginPage({ searchParams }: { searchParams: LoginSearch }) {
  const query = await searchParams;
  const stepUp = (Array.isArray(query.step_up) ? query.step_up[0] : query.step_up) === 'true';
  const next = safeNextPath(query.next);
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
          {stepUp ? (
            <p className="login-card__subtitle" role="status">
              <i className="bi bi-shield-lock me-1" aria-hidden="true" />
              This action needs a recent multi-factor sign-in. Sign in again to continue; you will
              return to where you were.
            </p>
          ) : null}
          <p className="login-card__subtitle">
            Access Netsight to monitor, secure and operate your network infrastructure.
          </p>

          {configured.length > 0 ? (
            <div className="login-card__actions">
              {configured.map((provider) => (
                <a key={provider.id} className="login-sso-btn" href={providerLoginHref(provider.href, next, stepUp)}>
                  <i className={provider.icon} aria-hidden="true" />
                  <span>Continue with {provider.name}</span>
                  <i className="bi bi-arrow-right" aria-hidden="true" />
                </a>
              ))}
            </div>
          ) : null}

          {/* Netsight-managed credentials (ADR 0010). A password alone never
              grants a session: a verification code is always required. */}
          {configured.length > 0 ? (
            <div className="login-card__divider">
              <span>or use a Netsight account</span>
            </div>
          ) : null}

          <div className="login-card__local">
            <LocalSignIn redirectTo={next ?? '/overview'} />
          </div>

          {configured.length === 0 ? (
            <div className="login-card__empty" role="status">
              <i className="bi bi-info-circle" aria-hidden="true" />
              <p>
                No organisation identity provider is connected to this deployment. Sign in with a
                Netsight account below, or ask an administrator to configure Microsoft 365 or Google
                Workspace sign-in.
              </p>
            </div>
          ) : null}

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
