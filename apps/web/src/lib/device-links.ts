import type { Device } from './api-contracts.ts';

export interface RelatedLink {
  id: 'map' | 'inventory' | 'flows' | 'alerts' | 'incidents' | 'config' | 'ipam' | 'device';
  label: string;
  href: string;
  /** What the destination does and does not show; never implies a per-device filter that is absent. */
  scope: string;
  /** Shown only to a session holding this permission, the same gate the sidebar uses. */
  requires?: string;
}

export type Permissions = readonly string[] | null;

const MAX_QUERY = 128;

// The same permissions lib/menu.ts gates these entries on; a test keeps the two in step.
export const LINK_PERMISSIONS = {
  inventory: 'inventory:read-summary',
  traffic: 'traffic:read',
  config: 'configuration:read',
  ipam: 'ipam:read-summary',
} as const;

function query(params: Record<string, string>): string {
  return new URLSearchParams(params).toString();
}

/** Drops links the session cannot open; an unknown session (null) keeps only ungated links. */
export function visibleLinks(links: readonly RelatedLink[], permissions: Permissions): RelatedLink[] {
  const held = new Set(permissions ?? []);
  return links.filter((link) => link.requires === undefined || held.has(link.requires));
}

function flowsLink(ip: string): RelatedLink {
  return {
    id: 'flows',
    label: `Flows from ${ip}`,
    href: `/traffic/flows?${query({ source_ip: ip })}`,
    scope: 'Flow Explorer filtered to this address; an address is not an identity.',
    requires: LINK_PERMISSIONS.traffic,
  };
}

function inventorySearch(term: string, scope: string): RelatedLink {
  const value = term.slice(0, MAX_QUERY);
  return {
    id: 'inventory',
    label: `Search inventory for ${value}`,
    href: `/inventory?${query({ q: value })}`,
    scope,
    requires: LINK_PERMISSIONS.inventory,
  };
}

const IPAM_LINK: RelatedLink = {
  id: 'ipam',
  label: 'IP address management',
  href: '/ipam',
  scope: 'Prefixes and address usage; not filtered to this record.',
  requires: LINK_PERMISSIONS.ipam,
};

function mapLink(focus: string | null, scope: string): RelatedLink {
  return {
    id: 'map',
    label: focus === null ? 'Network map' : 'Show on network map',
    href: focus === null ? '/network/map' : `/network/map?${query({ focus })}`,
    scope,
  };
}

/** Cross-links from one device to the screens that can show more about it. */
export function relatedLinks(device: Device, permissions: Permissions): RelatedLink[] {
  const ip = device.ip_addresses[0];
  const links: RelatedLink[] = [
    mapLink(device.id, 'Selects this device on the topology graph when the topology source reports it.'),
    { ...inventorySearch(device.name, 'Searches the NetBox-merged inventory by this name.'), label: 'Find in inventory' },
    ...(ip === undefined ? [] : [flowsLink(ip)]),
    {
      id: 'alerts',
      label: 'Source alerts',
      href: '/alerts',
      scope: 'All alerts; the Device column links back here. Alerts are not filtered to this device.',
    },
    {
      id: 'incidents',
      label: 'Incidents',
      href: '/incidents',
      scope: 'All incidents; incidents are not filtered to this device.',
    },
    {
      id: 'config',
      label: 'Configuration backups',
      href: '/config',
      scope: 'Choose the matching Oxidized node; configuration nodes are not linked to devices.',
      requires: LINK_PERMISSIONS.config,
    },
  ];
  return visibleLinks(links, permissions);
}

export interface EndpointLike {
  ip: string | null;
  mac: string | null;
  hostname: string | null;
}

/** Cross-links from an unknown endpoint; only values the endpoint has produce a link. */
export function endpointLinks(endpoint: EndpointLike, permissions: Permissions): RelatedLink[] {
  const search = endpoint.mac ?? endpoint.ip ?? endpoint.hostname;
  const links: RelatedLink[] = [
    ...(search === null
      ? []
      : [inventorySearch(search, 'NetBox-merged inventory search; no match is expected for a genuinely unknown endpoint.')]),
    ...(endpoint.ip === null ? [] : [flowsLink(endpoint.ip)]),
    mapLink(null, 'Topology of known devices; an unknown endpoint is not drawn unless a source reports a link.'),
    IPAM_LINK,
  ];
  return visibleLinks(links, permissions);
}

/** Cross-links from an inventory asset (its id is a canonical device id). */
export function assetLinks(asset: { id: string; ip: string | null }, permissions: Permissions): RelatedLink[] {
  const links: RelatedLink[] = [
    {
      id: 'device',
      label: 'Open the monitored device record',
      href: `/devices/${encodeURIComponent(asset.id)}`,
      scope: 'Exists only where monitoring also knows this asset; otherwise it reports not found.',
    },
    mapLink(asset.id, 'Selects the asset when the topology source reports it.'),
    ...(asset.ip === null ? [] : [flowsLink(asset.ip)]),
    IPAM_LINK,
  ];
  return visibleLinks(links, permissions);
}
