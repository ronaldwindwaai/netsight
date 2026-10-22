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
const COPILOT_PERMISSION = 'copilot:ask';
const ACTIONS_PERMISSION = 'actions:read';
const FORECAST_PERMISSION = 'forecast:read';

interface MenuEntry {
  node: MenuNode;
  /** Shown only to a session holding this permission; absent means always shown. */
  requires?: string;
}

interface MenuGroup {
  /** Primary group from docs/03-ui-ux/INFORMATION-ARCHITECTURE.md. Shown only when an entry is visible. */
  header: string;
  entries: readonly MenuEntry[];
}

function item(text: string, href: string, icon: string, requires?: string): MenuEntry {
  return { node: { type: 'item', text, href, icon }, requires };
}

const MENU_GROUPS: readonly MenuGroup[] = [
  { header: 'Overview', entries: [item('Overview', '/overview', 'bi-speedometer2')] },
  {
    header: 'Network',
    entries: [
      item('Network Map', '/network/map', 'bi-diagram-3'),
      item('Devices', '/devices', 'bi-hdd-network'),
      item('Internet', '/internet', 'bi-globe2', INTERNET_PERMISSION),
    ],
  },
  {
    header: 'Security',
    entries: [
      item('Security', '/security', 'bi-shield-exclamation'),
      item('Unknown devices', '/unknown-devices', 'bi-patch-question', FINDINGS_PERMISSION),
      item('Users', '/users', 'bi-people', USERS_PERMISSION),
    ],
  },
  {
    header: 'Operations',
    entries: [
      item('Incidents', '/incidents', 'bi-exclamation-triangle'),
      item('Alerts', '/alerts', 'bi-bell'),
      item('Diagnostics', '/diagnostics', 'bi-clipboard2-pulse', DIAGNOSTICS_PERMISSION),
      item('Action requests', '/actions', 'bi-shield-check', ACTIONS_PERMISSION),
    ],
  },
  {
    header: 'Infrastructure',
    entries: [
      item('Inventory', '/inventory', 'bi-boxes', INVENTORY_PERMISSION),
      item('IPAM', '/ipam', 'bi-diagram-2', IPAM_PERMISSION),
      item('Configuration', '/config', 'bi-file-earmark-code', 'configuration:read'),
    ],
  },
  {
    header: 'Intelligence',
    entries: [item('Ask Netsight', '/copilot', 'bi-chat-left-text', COPILOT_PERMISSION)],
  },
  {
    header: 'Analytics',
    entries: [
      item('Traffic', '/traffic', 'bi-bar-chart-line', TRAFFIC_PERMISSION),
      item('Capacity forecast', '/forecast', 'bi-graph-up-arrow', FORECAST_PERMISSION),
      item('Reports', '/reports', 'bi-file-earmark-bar-graph', 'reports:read'),
    ],
  },
];

/**
 * The sidebar for a session's permissions. An entry that names a permission is shown only to a
 * session that holds it; no session (null) holds nothing, so it fails closed. Advisory: the API
 * enforces every permission on every request.
 */
export function menuItemsFor(permissions: readonly string[] | null): MenuNode[] {
  const held = new Set(permissions ?? []);
  return MENU_GROUPS.flatMap((group) => {
    const visible = group.entries
      .filter((entry) => entry.requires === undefined || held.has(entry.requires))
      .map((entry) => entry.node);
    return visible.length === 0 ? [] : [{ type: 'header' as const, text: group.header }, ...visible];
  });
}
