import { DashboardLayout } from '@adminlte/react';

import { ConnectivityBanner } from '@/components/connectivity-banner';
import { IdentityMenu } from '@/components/identity-menu';
import { PwaInstall } from '@/components/pwa-install';
import { MobileNav } from '@/components/mobile-nav';
import { PageFinder } from '@/components/page-finder';
import { AppLink } from '@/components/app-link';
import { apiGet } from '@/lib/api';
import { parseSessionInfo } from '@/lib/api-contracts';
import { menuItemsFor } from '@/lib/menu';
import { pageTargetsFrom } from '@/lib/page-finder';
import { canChangeAnything, viewerFromSession } from '@/lib/viewer';

export default async function Layout({ children }: { children: React.ReactNode }) {
  const sessionState = await apiGet('/api/v1/auth/session', parseSessionInfo);
  const session = sessionState.kind === 'ok' ? sessionState.data : null;
  const readOnly = !canChangeAnything(viewerFromSession(session));
  const menuItems = menuItemsFor(session === null ? null : session.permissions);

  return (
    <DashboardLayout
      bodyClass="netsight-dashboard"
      colorModeToggle
      enableSidebarPersistence
      fixedHeader
      fixedSidebar
      initialColorMode="auto"
      linkComponent={AppLink}
      logo={<span className="fw-bold">Netsight</span>}
      logoHref="/overview"
      menuItems={menuItems}
      sidebarMini
      sidebarTheme="dark"
      topbarStart={<PageFinder pages={pageTargetsFrom(menuItems)} />}
      topbarEnd={
        <>
          {readOnly ? (
            <span className="badge text-bg-secondary me-2">
              <i className="bi bi-eye me-1" aria-hidden="true" />
              Read only
            </span>
          ) : null}
          <PwaInstall />
          <IdentityMenu session={session} />
        </>
      }
    >
      <a className="skip-link" href="#main-content">
        Skip to main content
      </a>
      <ConnectivityBanner />
      <div id="main-content" tabIndex={-1}>
        {children}
      </div>
      <MobileNav permissions={session === null ? null : session.permissions} />
    </DashboardLayout>
  );
}
