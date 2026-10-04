import type { MenuNode } from '@adminlte/react';

export const menuItems: MenuNode[] = [
  { type: 'header', text: 'Main' },
  { type: 'item', text: 'Overview', href: '/overview', icon: 'bi-speedometer2' },
  { type: 'item', text: 'Devices', href: '/devices', icon: 'bi-hdd-network' },
  { type: 'item', text: 'Alerts', href: '/alerts', icon: 'bi-bell' },
];
