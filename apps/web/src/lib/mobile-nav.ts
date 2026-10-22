export interface MobileNavItem {
  label: string;
  href: string;
  icon: string;
}

interface MobileNavEntry extends MobileNavItem {
  /** Shown only to a session holding this permission; absent means always shown. */
  requires?: string;
}

// The four mobile-first surfaces (PRD 33). Permissions mirror lib/menu.ts; the API enforces them.
const MOBILE_NAV_ENTRIES: readonly MobileNavEntry[] = [
  { label: 'Overview', href: '/overview', icon: 'bi-speedometer2' },
  { label: 'Incidents', href: '/incidents', icon: 'bi-exclamation-triangle' },
  { label: 'Diagnostics', href: '/diagnostics', icon: 'bi-clipboard2-pulse', requires: 'diagnostics:read' },
  { label: 'Internet', href: '/internet', icon: 'bi-globe2', requires: 'internet:read' },
];

/** The bottom bar for a session's permissions. Overview and Incidents need none (as in the sidebar); the others need theirs. */
export function mobileNavItemsFor(permissions: readonly string[] | null): MobileNavItem[] {
  const held = new Set(permissions ?? []);
  return MOBILE_NAV_ENTRIES.filter((entry) => entry.requires === undefined || held.has(entry.requires)).map(
    ({ label, href, icon }) => ({ label, href, icon }),
  );
}

export function isActiveMobileTab(pathname: string | null, href: string): boolean {
  if (pathname === null) return false;
  return pathname === href || pathname.startsWith(`${href}/`);
}
