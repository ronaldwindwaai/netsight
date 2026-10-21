import type { CsvValue } from './csv.ts';
import type { TrafficFlow } from './api-contracts-traffic-flows.ts';

/*
 * CSV rows for the Flow Explorer table: exactly the flows the page lists, in the same order.
 * Person and device labels follow the same entitlement as the on-screen table, so the export never
 * reveals what the viewer's role cannot open. Values the source did not report are empty cells.
 */

export const FLOW_CSV_HEADERS = [
  'Seen (UTC)',
  'Source',
  'Source device ID',
  'Destination',
  'Destination host',
  'Protocol',
  'Port',
  'Direction',
  'Application',
  'Bytes',
  'Packets',
  'Attribution basis',
  'Person',
  'Attributed device',
] as const;

export interface FlowCsvAccess {
  readonly people: boolean;
  readonly devices: boolean;
}

export function flowCsvRows(flows: readonly TrafficFlow[], access: FlowCsvAccess): CsvValue[][] {
  return flows.map((flow) => [
    flow.observed_at,
    flow.source_ip,
    flow.source_device_id ?? '',
    flow.destination_ip,
    flow.destination_host ?? '',
    flow.protocol,
    flow.destination_port ?? '',
    flow.direction,
    flow.application ?? '',
    flow.bytes,
    flow.packets ?? '',
    flow.attribution?.basis ?? '',
    access.people ? (flow.attribution?.person?.label ?? '') : '',
    access.devices ? (flow.attribution?.device?.label ?? '') : '',
  ]);
}
