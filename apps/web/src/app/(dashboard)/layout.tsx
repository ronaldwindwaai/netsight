import { DashboardLayout } from '@adminlte/react';
import { AppLink } from '@/components/app-link';
import { menuItems } from '@/lib/menu';

export default function Layout({ children }: { children: React.ReactNode }) {
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
        <span className="badge text-bg-secondary me-2">
          <i className="bi bi-eye me-1" aria-hidden="true" />
          Read only
        </span>
      }
    >
      {children}
    </DashboardLayout>
  );
}
