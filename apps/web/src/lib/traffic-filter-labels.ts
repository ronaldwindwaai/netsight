import type { FilterName } from '@/lib/api-contracts-traffic-explorer';

/** Human labels for the Flow Explorer's allow-listed filters, shared by the form and the chips. */
export const FILTER_LABELS: Record<FilterName, string> = {
  source_ip: 'Source IP',
  destination_ip: 'Destination IP',
  device: 'Exporter (device)',
  vlan: 'VLAN',
  application: 'Application',
  protocol: 'Protocol',
  port: 'Port',
  country: 'Country',
  asn: 'ASN',
  direction: 'Direction',
};
