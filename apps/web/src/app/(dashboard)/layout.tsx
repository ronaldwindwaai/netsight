import { DashboardLayout } from '@adminlte/react';

import { IdentityMenu } from '@/components/identity-menu';
import { AppLink } from '@/components/app-link';
import { apiGet } from '@/lib/api';
import { parseSessionInfo } from '@/lib/api-contracts';
import { menuItems } from '@/lib/menu';
import { canChangeAnything, viewerFromSession } from '@/lib/viewer';

export default async function Layout({ children }: { children: React.ReactNode }) {
  const sessionState = await apiGet('/api/v1/auth/session', parseSessionInfo);
  const session = sessionState.kind === 'ok' ? sessionState.data : null;
  const readOnly = !canChangeAnything(viewerFromSession(session));

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
      topbarEnd={
        <>
          {readOnly ? (
            <span className="badge text-bg-secondary me-2">
              <i className="bi bi-eye me-1" aria-hidden="true" />
              Read only
            </span>
          ) : null}
          <IdentityMenu session={session} />
        </>
      }
    >
      {children}
    </DashboardLayout>
  );
}
