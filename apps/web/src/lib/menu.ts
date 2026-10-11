import type { MenuNode } from '@adminlte/react';

const DIAGNOSTICS_PERMISSION = 'diagnostics:read';
const INTERNET_PERMISSION = 'internet:read';
// The lowest rung of the users ladder: whoever can see any users surface (even counts) sees the entry.
const USERS_PERMISSION = 'users:read-summary';
// The aggregate rung of traffic: whoever can read any traffic surface sees the entry. Rows and
// address, device and VLAN filters need traffic:read-detail on top (enforced by the API, hidden by the pages).
const TRAFFIC_PERMISSION = 'traffic:read';

interface MenuEntry {
  node: MenuNode;
  /** Shown only to a session holding this permission; absent means always shown. */
  requires?: string;
}

const MENU_ENTRIES: readonly MenuEntry[] = [
  { node: { type: 'header', text: 'Main' } },
  { node: { type: 'item', text: 'Overview', href: '/overview', icon: 'bi-speedometer2' } },
  { node: { type: 'item', text: 'Network Map', href: '/network/map', icon: 'bi-diagram-3' } },
  { node: { type: 'item', text: 'Devices', href: '/devices', icon: 'bi-hdd-network' } },
  {
    node: { type: 'item', text: 'Users', href: '/users', icon: 'bi-people' },
    requires: USERS_PERMISSION,
  },
  {
    node: { type: 'item', text: 'Traffic', href: '/traffic', icon: 'bi-bar-chart-line' },
    requires: TRAFFIC_PERMISSION,
  },
  {
    node: { type: 'item', text: 'Internet', href: '/internet', icon: 'bi-globe2' },
    requires: INTERNET_PERMISSION,
  },
  { node: { type: 'item', text: 'Security', href: '/security', icon: 'bi-shield-exclamation' } },
  {
    node: { type: 'item', text: 'Diagnostics', href: '/diagnostics', icon: 'bi-clipboard2-pulse' },
    requires: DIAGNOSTICS_PERMISSION,
  },
  { node: { type: 'item', text: 'Incidents', href: '/incidents', icon: 'bi-exclamation-triangle' } },
  { node: { type: 'item', text: 'Alerts', href: '/alerts', icon: 'bi-bell' } },
];

/**
 * The sidebar for a session's permissions. An entry that names a permission is shown only to a
 * session that holds it; no session (null) holds nothing, so it fails closed. Advisory: the API
 * enforces every permission on every request.
 */
export function menuItemsFor(permissions: readonly string[] | null): MenuNode[] {
  const held = new Set(permissions ?? []);
  return MENU_ENTRIES.filter((entry) => entry.requires === undefined || held.has(entry.requires)).map(
    (entry) => entry.node,
  );
}
