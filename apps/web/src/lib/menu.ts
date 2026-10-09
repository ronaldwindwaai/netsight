import type { MenuNode } from '@adminlte/react';

export const menuItems: MenuNode[] = [
  { type: 'header', text: 'Main' },
  { type: 'item', text: 'Overview', href: '/overview', icon: 'bi-speedometer2' },
  { type: 'item', text: 'Network Map', href: '/network/map', icon: 'bi-diagram-3' },
  { type: 'item', text: 'Devices', href: '/devices', icon: 'bi-hdd-network' },
  { type: 'item', text: 'Traffic', href: '/traffic', icon: 'bi-bar-chart-line' },
  { type: 'item', text: 'Security', href: '/security', icon: 'bi-shield-exclamation' },
  { type: 'item', text: 'Incidents', href: '/incidents', icon: 'bi-exclamation-triangle' },
  { type: 'item', text: 'Alerts', href: '/alerts', icon: 'bi-bell' },
];
