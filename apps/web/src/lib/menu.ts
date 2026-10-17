import type { MenuNode } from '@adminlte/react';

const DIAGNOSTICS_PERMISSION = 'diagnostics:read';
const INTERNET_PERMISSION = 'internet:read';
// The lowest rung of the users ladder: whoever can see any users surface (even counts) sees the entry.
const USERS_PERMISSION = 'users:read-summary';
// The aggregate rung of traffic: whoever can read any traffic surface sees the entry. Rows and
// address, device and VLAN filters need traffic:read-detail on top (enforced by the API, hidden by the pages).
const TRAFFIC_PERMISSION = 'traffic:read';
// Whoever can see any inventory, IPAM or finding surface (even counts) sees the entry.
const INVENTORY_PERMISSION = 'inventory:read-summary';
const IPAM_PERMISSION = 'ipam:read-summary';
const FINDINGS_PERMISSION = 'unknown-devices:read-summary';

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
    node: { type: 'item', text: 'Inventory', href: '/inventory', icon: 'bi-boxes' },
    requires: INVENTORY_PERMISSION,
  },
  {
    node: { type: 'item', text: 'IPAM', href: '/ipam', icon: 'bi-diagram-2' },
    requires: IPAM_PERMISSION,
  },
  {
    node: { type: 'item', text: 'Unknown devices', href: '/unknown-devices', icon: 'bi-patch-question' },
    requires: FINDINGS_PERMISSION,
  },
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
  { node: { type: 'item', text: 'Configuration', href: '/config', icon: 'bi-file-earmark-code' }, requires: 'configuration:read' },
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
