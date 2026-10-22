import type { FetchState } from './api-response.ts';

/**
 * First-run guidance for the overview: when the device source is not configured, say what to connect
 * instead of presenting every dependent tile as a failure. Every source listed is read-only; Netsight
 * holds the credentials server-side (the browser never sees them) and nothing here changes a system.
 */
export type SourceStatus = 'connected' | 'not-connected' | 'unknown' | 'restricted' | 'unchecked';

export interface ChecklistItem {
  readonly id: 'librenms' | 'netbox' | 'oxidized' | 'wazuh' | 'akvorado' | 'blackbox';
  readonly name: string;
  readonly purpose: string;
  /** Where the API reads its connection settings; names only, never values. */
  readonly setup: string;
  /** Repository path of the integration guide. */
  readonly docs: string;
  /** The in-app page that shows this source's data. */
  readonly page: { readonly href: string; readonly label: string };
  readonly status: SourceStatus;
}

export interface FirstRunChecklist {
  readonly show: boolean;
  readonly items: readonly ChecklistItem[];
}

export interface FirstRunInputs {
  readonly devices: FetchState<unknown>;
  readonly security: FetchState<{ state: string }> | null;
  readonly traffic: FetchState<{ state: string }> | null;
  readonly internet: FetchState<{ state: string }>;
}

/** True for the API refusal "<source> source is not configured", as opposed to a configured source failing. */
export function isSourceNotConfigured(state: FetchState<unknown> | null): boolean {
  return state !== null && state.kind === 'source_unavailable' && /not configured/i.test(state.message);
}

function statusOf(state: FetchState<{ state: string }> | null): SourceStatus {
  if (state === null) return 'restricted';
  if (state.kind === 'forbidden' || state.kind === 'unauthenticated') return 'restricted';
  if (state.kind !== 'ok') return 'unknown';
  if (state.data.state === 'ok') return 'connected';
  return state.data.state === 'not-connected' ? 'not-connected' : 'unknown';
}

type Static = Omit<ChecklistItem, 'status'>;

const SOURCES: readonly Static[] = [
  {
    id: 'librenms',
    name: 'LibreNMS',
    purpose: 'Devices, ports and alerts. Start here: the overview and device pages read it.',
    setup: 'LIBRENMS_BASE_URL, LIBRENMS_TOKEN (a read-only API token) and LIBRENMS_TIMEZONE on the API',
    docs: 'docs/04-integrations/LIBRENMS.md',
    page: { href: '/devices', label: 'Devices' },
  },
  {
    id: 'netbox',
    name: 'NetBox',
    purpose: 'Intended inventory and IP address plan, to spot unknown devices and drift.',
    setup: 'NETBOX_BASE_URL and NETBOX_TOKEN (read-only) on the API',
    docs: 'docs/04-integrations/NETBOX.md',
    page: { href: '/inventory', label: 'Inventory' },
  },
  {
    id: 'oxidized',
    name: 'Oxidized',
    purpose: 'Configuration backups and change history (read-only).',
    setup: 'OXIDIZED_BASE_URL on the API',
    docs: 'docs/04-integrations/OXIDIZED.md',
    page: { href: '/config', label: 'Configuration' },
  },
  {
    id: 'wazuh',
    name: 'Wazuh',
    purpose: 'Security events and endpoint evidence (read-only indexer access).',
    setup: 'WAZUH_INDEXER_URL and a read-only indexer account on the API',
    docs: 'docs/04-integrations/WAZUH.md',
    page: { href: '/security', label: 'Security' },
  },
  {
    id: 'akvorado',
    name: 'Akvorado / ClickHouse',
    purpose: 'Flow data for traffic, applications and destinations.',
    setup: 'CLICKHOUSE_DSN with a read-only ClickHouse user on the API',
    docs: 'docs/04-integrations/AKVORADO-CLICKHOUSE.md',
    page: { href: '/traffic', label: 'Traffic' },
  },
  {
    id: 'blackbox',
    name: 'Blackbox probes',
    purpose: 'Internet and WAN reachability from your own vantage points.',
    setup: 'BLACKBOX_EXPORTER_SOURCES and BLACKBOX_ALLOWED_TARGETS on the API',
    docs: 'docs/04-integrations/BLACKBOX.md',
    page: { href: '/internet', label: 'Internet' },
  },
];

export function firstRunChecklist(inputs: FirstRunInputs): FirstRunChecklist {
  const devices: SourceStatus = isSourceNotConfigured(inputs.devices)
    ? 'not-connected'
    : inputs.devices.kind === 'ok'
      ? 'connected'
      : 'unknown';
  const status: Record<ChecklistItem['id'], SourceStatus> = {
    librenms: devices,
    netbox: 'unchecked',
    oxidized: 'unchecked',
    wazuh: statusOf(inputs.security),
    akvorado: statusOf(inputs.traffic),
    blackbox: statusOf(inputs.internet),
  };
  return {
    show: isSourceNotConfigured(inputs.devices),
    items: SOURCES.map((source) => ({ ...source, status: status[source.id] })),
  };
}
