import type { Device } from './api-contracts.ts';

export interface RelatedLink {
  id: 'map' | 'inventory' | 'flows' | 'alerts' | 'incidents' | 'config';
  label: string;
  href: string;
  /** What the destination does and does not show for this device; never implies a per-device filter that is absent. */
  scope: string;
}

const MAX_QUERY = 128;

function query(params: Record<string, string>): string {
  return new URLSearchParams(params).toString();
}

/** Cross-links from one device to the screens that can show more about it. */
export function relatedLinks(device: Device): RelatedLink[] {
  const ip = device.ip_addresses[0];
  const links: RelatedLink[] = [
    {
      id: 'map',
      label: 'Show on network map',
      href: `/network/map?${query({ focus: device.id })}`,
      scope: 'Selects this device on the topology graph when the topology source reports it.',
    },
    {
      id: 'inventory',
      label: 'Find in inventory',
      href: `/inventory?${query({ q: device.name.slice(0, MAX_QUERY) })}`,
      scope: 'Searches the NetBox-merged inventory by this name.',
    },
  ];
  if (ip !== undefined) {
    links.push({
      id: 'flows',
      label: `Flows from ${ip}`,
      href: `/traffic/flows?${query({ source_ip: ip })}`,
      scope: 'Flow Explorer filtered to this primary address; an address is not an identity.',
    });
  }
  links.push(
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
    },
  );
  return links;
}

export interface EndpointLike {
  ip: string | null;
  mac: string | null;
  hostname: string | null;
}

/** Cross-links from an unknown endpoint; only values the endpoint really has produce a link. */
export function endpointLinks(endpoint: EndpointLike): RelatedLink[] {
  const search = endpoint.mac ?? endpoint.ip ?? endpoint.hostname;
  const links: RelatedLink[] = [];
  if (search !== null) {
    links.push({
      id: 'inventory',
      label: `Search inventory for ${search.slice(0, MAX_QUERY)}`,
      href: `/inventory?${query({ q: search.slice(0, MAX_QUERY) })}`,
      scope: 'NetBox-merged inventory search; no match is expected for a genuinely unknown endpoint.',
    });
  }
  if (endpoint.ip !== null) {
    links.push({
      id: 'flows',
      label: `Flows from ${endpoint.ip}`,
      href: `/traffic/flows?${query({ source_ip: endpoint.ip })}`,
      scope: 'Flow Explorer filtered to this address; an address is not an identity.',
    });
  }
  links.push({
    id: 'map',
    label: 'Network map',
    href: '/network/map',
    scope: 'Topology of known devices; an unknown endpoint is not drawn unless a source reports a link.',
  });
  return links;
}
