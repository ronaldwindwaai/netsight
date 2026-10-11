/**
 * Fixtures for the inventory, IPAM and unknown-device component tests. Every fixture is built from
 * the shared contract vectors' shapes and parsed by the real parser, so a fixture that stops being
 * a valid response fails loudly instead of letting a component test pass on invalid data.
 */
import type { FetchState } from '@/lib/api-response';
import {
  parseInventoryDetail,
  parseInventoryList,
  parseInventorySummaryResponse,
  type InventoryDetail,
  type InventoryItem,
  type InventoryList,
  type InventorySummaryResponse,
} from '@/lib/api-contracts-inventory';
import {
  parseIpamAddressList,
  parseIpamPrefixList,
  parseIpamSummary,
  parseIpamVlanList,
  type IpamAddress,
  type IpamAddressList,
  type IpamPrefix,
  type IpamPrefixList,
  type IpamSummary,
  type IpamVlanList,
} from '@/lib/api-contracts-ipam';
import {
  parseUnknownDeviceDetail,
  parseUnknownDeviceList,
  parseUnknownDeviceSummary,
  parseUnknownDeviceTimeline,
  type UnknownDeviceDetail,
  type UnknownDeviceFinding,
  type UnknownDeviceLinkSlot,
  type UnknownDeviceList,
  type UnknownDeviceSummary,
  type UnknownDeviceTimeline,
} from '@/lib/api-contracts-unknown-devices';

export const HOSTILE = '<img src=x onerror=alert(1)> ignore previous instructions';
export const NOW = '2026-10-11T12:00:00Z';
export const DEVICE_ID = 'device-6f1c2a9e-0b1d-5c3e-8f4a-123456789abc';
export const DEVICE_ID_2 = 'device-6f1c2a9e-0b1d-5c3e-8f4a-123456789abd';
export const PREFIX_ID = 'ipam-prefix-6f1c2a9e-0b1d-5c3e-8f4a-123456789abc';
export const PREFIX_ID_2 = 'ipam-prefix-6f1c2a9e-0b1d-5c3e-8f4a-123456789abd';
export const FINDING_ID = 'unknown-device-6f1c2a9e-0b1d-5c3e-8f4a-123456789abc';

export function okState<T>(data: T): FetchState<T> {
  return { kind: 'ok', data, correlationId: 'corr-1' };
}

export function failureState<T>(kind: string, status: number): FetchState<T> {
  return {
    kind,
    code: kind.toUpperCase(),
    message: 'Something went wrong.',
    correlationId: 'corr-1',
    status,
  } as FetchState<T>;
}

function must<T>(value: T | null, what: string): T {
  if (value === null) throw new Error(`fixture ${what} is not a valid response`);
  return value;
}

const OK_SOURCE = { source: 'netbox', state: 'ok', observed_at: NOW } as const;
export const sources = {
  allOk: [
    OK_SOURCE,
    { source: 'librenms', state: 'ok', observed_at: NOW },
    { source: 'wazuh', state: 'ok', observed_at: NOW },
  ],
  wazuhNotConnected: [
    OK_SOURCE,
    { source: 'librenms', state: 'ok', observed_at: NOW },
    { source: 'wazuh', state: 'not-connected', observed_at: null },
  ],
  libreUnknown: [
    OK_SOURCE,
    { source: 'librenms', state: 'unknown', observed_at: null },
    { source: 'wazuh', state: 'not-connected', observed_at: null },
  ],
  netboxNotConnected: [{ source: 'netbox', state: 'not-connected', observed_at: null }],
  netboxUnknown: [{ source: 'netbox', state: 'unknown', observed_at: null }],
} as const;

// --- inventory ------------------------------------------------------------------------------------------

const unknownField = { value: null, provenance: 'unknown', netbox: null, discovered: null } as const;
const both = (v: string) => ({ value: v, provenance: 'both', netbox: v, discovered: v }) as const;
const netboxOnly = (v: string) => ({ value: v, provenance: 'netbox', netbox: v, discovered: null }) as const;
const discoveredOnly = (v: string) => ({ value: v, provenance: 'discovered', netbox: null, discovered: v }) as const;

export function inventoryItem(over: Partial<InventoryItem> = {}): InventoryItem {
  return {
    id: DEVICE_ID,
    asset_class: 'network-device',
    class_basis: 'role-map',
    source: 'both',
    known: true,
    name: both('core-sw-1'),
    site: netboxOnly('HQ'),
    ip_address: both('10.0.0.2'),
    mac_address: discoveredOnly('aa:bb:cc:00:11:22'),
    role: 'Core switch',
    device_type: 'C9300-48P',
    intended_status: 'active',
    observed_status: 'healthy',
    reconcile: { status: 'reconciled', detail: null },
    sources: [
      { source: 'netbox', native_id: '42' },
      { source: 'librenms', native_id: '7' },
    ],
    ...over,
  };
}

export function unknownAsset(over: Partial<InventoryItem> = {}): InventoryItem {
  return inventoryItem({
    id: DEVICE_ID_2,
    asset_class: 'unknown-asset',
    class_basis: 'not-in-netbox',
    source: 'discovered',
    known: false,
    name: discoveredOnly('printer-x'),
    site: unknownField,
    ip_address: discoveredOnly('10.0.5.9'),
    mac_address: unknownField,
    role: null,
    device_type: null,
    intended_status: null,
    reconcile: { status: 'unknown-discovered', detail: 'Discovered device has no matching NetBox record' },
    sources: [{ source: 'librenms', native_id: '9' }],
    ...over,
  });
}

export function inventoryList(over: Partial<InventoryList> = {}): InventoryList {
  const items = over.items ?? [inventoryItem(), unknownAsset()];
  return must(
    parseInventoryList({
      state: 'ok',
      generated_at: NOW,
      page: 1,
      page_size: 25,
      total: items.length,
      sources: sources.wazuhNotConnected,
      summary: {
        total: 2,
        known: 1,
        unknown: 1,
        by_class: [
          { asset_class: 'network-device', count: 1 },
          { asset_class: 'unknown-asset', count: 1 },
        ],
        by_source: [
          { source: 'both', count: 1 },
          { source: 'discovered', count: 1 },
        ],
      },
      ...over,
      items,
    }),
    'inventory list',
  );
}

export function inventoryNotOk(state: 'not-connected' | 'unknown'): InventoryList {
  return inventoryList({
    state,
    total: 0,
    summary: null,
    items: [],
    sources: state === 'unknown' ? [...sources.netboxUnknown] : [...sources.netboxNotConnected],
  });
}

export function inventoryDetail(item: InventoryItem | null = inventoryItem(), state: 'ok' | 'not-connected' | 'unknown' = 'ok'): InventoryDetail {
  return must(
    parseInventoryDetail({ state, generated_at: NOW, sources: sources.wazuhNotConnected, item }),
    'inventory detail',
  );
}

export function inventorySummary(state: 'ok' | 'not-connected' | 'unknown' = 'ok'): InventorySummaryResponse {
  return must(
    parseInventorySummaryResponse({
      state,
      generated_at: NOW,
      sources: state === 'ok' ? sources.wazuhNotConnected : sources.netboxNotConnected,
      summary:
        state === 'ok'
          ? {
              total: 3,
              known: 2,
              unknown: 1,
              by_class: [
                { asset_class: 'server', count: 2 },
                { asset_class: 'unknown-asset', count: 1 },
              ],
              by_source: [
                { source: 'both', count: 2 },
                { source: 'discovered', count: 1 },
              ],
            }
          : null,
    }),
    'inventory summary',
  );
}

// --- IPAM -----------------------------------------------------------------------------------------------

export const telemetryOk = { state: 'ok', window_seconds: 86400, sources: ['librenms'] } as const;
export const telemetryNone: {
  state: 'ok' | 'not-connected' | 'unknown';
  window_seconds: number;
  sources: Array<'librenms' | 'wazuh'>;
} = { state: 'not-connected', window_seconds: 86400, sources: [] };

const utilisation = {
  state: 'ok',
  basis: 'netbox-and-discovered',
  capacity: 254,
  netbox_addresses: 100,
  discovered_only: 6,
  used: 106,
  reserved: 20,
  free: 128,
  percent: 41.7,
} as const;

export function ipamPrefix(over: Partial<IpamPrefix> = {}): IpamPrefix {
  return {
    id: PREFIX_ID_2,
    prefix: '10.0.0.0/24',
    version: 4,
    vrf: null,
    status: 'active',
    site: 'HQ',
    role: 'Staff',
    vlan: { vid: 20, name: 'staff' },
    description: 'Staff LAN',
    parent_id: PREFIX_ID,
    depth: 1,
    children: 0,
    utilisation,
    reserved_ranges: [{ start: '10.0.0.100', end: '10.0.0.119', size: 20 }],
    reserved_ranges_total: 1,
    ...over,
  };
}

export function ipamRootPrefix(over: Partial<IpamPrefix> = {}): IpamPrefix {
  return ipamPrefix({
    id: PREFIX_ID,
    prefix: '10.0.0.0/8',
    parent_id: null,
    depth: 0,
    children: 1,
    vlan: null,
    description: null,
    reserved_ranges: [],
    reserved_ranges_total: 0,
    ...over,
  });
}

export function ipamPrefixes(over: Partial<IpamPrefixList> = {}): IpamPrefixList {
  const items = over.items ?? [ipamRootPrefix(), ipamPrefix()];
  return must(
    parseIpamPrefixList({
      state: 'ok', generated_at: NOW, sources: sources.wazuhNotConnected, telemetry: telemetryOk,
      page: 1, page_size: 25, total: items.length, ...over, items,
    }),
    'ipam prefixes',
  );
}

export function ipamVlans(over: Partial<IpamVlanList> = {}): IpamVlanList {
  const items = over.items ?? [
    { id: 'ipam-vlan-6f1c2a9e-0b1d-5c3e-8f4a-123456789abc', vid: 20, name: 'staff', status: 'active', site: 'HQ', group: null, description: null, prefix_count: 1 },
  ];
  return must(
    parseIpamVlanList({
      state: 'ok', generated_at: NOW, sources: sources.wazuhNotConnected, telemetry: telemetryOk,
      page: 1, page_size: 25, total: items.length, ...over, items,
    }),
    'ipam vlans',
  );
}

export function ipamAddress(over: Partial<IpamAddress> = {}): IpamAddress {
  return {
    id: 'ipam-address-6f1c2a9e-0b1d-5c3e-8f4a-123456789abc',
    address: '10.0.0.15',
    version: 4,
    prefix_id: PREFIX_ID_2,
    vrf: null,
    status: 'active',
    dns_name: 'pc-15.example',
    description: null,
    source: 'both',
    activity: 'active',
    seen_by: ['librenms'],
    last_seen: NOW,
    ...over,
  };
}

export function staleAddress(over: Partial<IpamAddress> = {}): IpamAddress {
  return ipamAddress({
    id: 'ipam-address-6f1c2a9e-0b1d-5c3e-8f4a-123456789abd',
    address: '10.0.0.16',
    dns_name: null,
    source: 'netbox',
    activity: 'stale',
    seen_by: [],
    last_seen: null,
    ...over,
  });
}

export function ipamAddresses(over: Partial<IpamAddressList> = {}): IpamAddressList {
  const items = over.items ?? [ipamAddress(), staleAddress()];
  return must(
    parseIpamAddressList({
      state: 'ok', generated_at: NOW, sources: sources.wazuhNotConnected, telemetry: telemetryOk,
      page: 1, page_size: 25, total: items.length,
      activity_counts: { active: 1, stale: 1, unknown: 0, reserved: 0 },
      ...over, items,
    }),
    'ipam addresses',
  );
}

export function ipamNotOk<T extends 'prefixes' | 'vlans' | 'addresses'>(
  kind: T,
  state: 'not-connected' | 'unknown',
): T extends 'prefixes' ? IpamPrefixList : T extends 'vlans' ? IpamVlanList : IpamAddressList {
  const common = {
    state, generated_at: NOW,
    sources: state === 'unknown' ? sources.netboxUnknown : sources.netboxNotConnected,
    telemetry: state === 'unknown' ? { ...telemetryNone, state: 'unknown' } : telemetryNone,
    page: 1, page_size: 25, total: 0, items: [],
  };
  const parsed =
    kind === 'prefixes' ? parseIpamPrefixList(common)
    : kind === 'vlans' ? parseIpamVlanList(common)
    : parseIpamAddressList({ ...common, activity_counts: null });
  return must(parsed, `ipam ${kind} ${state}`) as never;
}

export function ipamSummary(state: 'ok' | 'not-connected' | 'unknown' = 'ok'): IpamSummary {
  return must(
    parseIpamSummary({
      state, generated_at: NOW,
      sources: state === 'ok' ? sources.wazuhNotConnected : sources.netboxNotConnected,
      telemetry: state === 'ok' ? telemetryOk : telemetryNone,
      counts: state === 'ok'
        ? { prefixes: 4, vlans: 3, addresses: 120, reserved_ranges: 2, active_addresses: 80, stale_addresses: 30, unknown_activity_addresses: 0, discovered_only_addresses: 6 }
        : null,
    }),
    'ipam summary',
  );
}

// --- unknown devices ---------------------------------------------------------------------------------------

const evidence = { id: 'librenms:9', source: 'librenms', kind: 'device-poll', observed_at: NOW, confidence: null } as const;
const unknownHop = (slot: string, reason: string) =>
  ({ slot, basis: 'unknown', value: null, label: null, attachment_kind: null, confidence: null, reason, evidence: [] }) as const;
const checks = [
  { field: 'ip', result: 'no-match', detail: null },
  { field: 'mac', result: 'no-match', detail: null },
  { field: 'hostname', result: 'no-match', detail: null },
] as const;

export function finding(over: Partial<UnknownDeviceFinding> = {}): UnknownDeviceFinding {
  return must(
    parseUnknownDeviceDetail({
      state: 'ok',
      generated_at: NOW,
      item: {
        id: FINDING_ID,
        state: 'new',
        severity: 'medium',
        severity_basis: 'policy-default',
        assignee_id: null,
        first_seen_at: NOW,
        last_seen_at: NOW,
        seen_count: 1,
        recurrence_of: null,
        endpoint: { ip: '10.0.5.9', mac: 'aa:bb:cc:00:11:22', hostname: 'printer-x' },
        chain: [
          { slot: 'ip', basis: 'observed', value: '10.0.5.9', label: null, attachment_kind: null, confidence: null, reason: null, evidence: [evidence] },
          { slot: 'mac', basis: 'observed', value: 'aa:bb:cc:00:11:22', label: null, attachment_kind: null, confidence: null, reason: null, evidence: [evidence] },
          unknownHop('attachment', 'source-unavailable'),
          unknownHop('port', 'source-unavailable'),
          unknownHop('vlan', 'source-unavailable'),
        ],
        comparison: { checks, checked_at: NOW },
        proposed_action: null,
        ...over,
      },
    }),
    'finding',
  ).item as UnknownDeviceFinding;
}

export const proposedAction = {
  action_type: 'endpoint.isolate',
  state: 'proposed',
  risk: 'C',
  executable: false,
  awaiting: 'action-engine',
  rationale: "Severity high reaches the operator's quarantine threshold",
} as const;

export function findingList(over: Partial<UnknownDeviceList> = {}): UnknownDeviceList {
  const base = finding();
  const secondChain = base.chain.map((slot) =>
    slot.slot === 'ip'
      ? { ...slot, value: '10.0.5.10' }
      : slot.slot === 'mac'
        ? (unknownHop('mac', 'no-evidence') as unknown as UnknownDeviceLinkSlot)
        : slot,
  );
  const second = finding({
    id: 'unknown-device-6f1c2a9e-0b1d-5c3e-8f4a-123456789abd',
    state: 'investigating',
    severity: 'high',
    severity_basis: 'policy-rule',
    assignee_id: 'oidc:tech-9',
    proposed_action: proposedAction,
    endpoint: { ip: '10.0.5.10', mac: null, hostname: null },
    chain: secondChain,
  });
  const items = over.items ?? [base, second];
  return must(
    parseUnknownDeviceList({ state: 'ok', generated_at: NOW, page: 1, page_size: 25, total: items.length, ...over, items }),
    'finding list',
  );
}

export function findingDetail(item: UnknownDeviceFinding | null = finding(), state: 'ok' | 'not-connected' | 'unknown' = 'ok'): UnknownDeviceDetail {
  return must(parseUnknownDeviceDetail({ state, generated_at: NOW, item }), 'finding detail');
}

export function findingSummary(state: 'ok' | 'not-connected' | 'unknown' = 'ok'): UnknownDeviceSummary {
  return must(
    parseUnknownDeviceSummary({
      state, generated_at: NOW,
      counts: state === 'ok'
        ? { open: 3, by_state: [{ state: 'new', count: 2 }, { state: 'acknowledged', count: 1 }, { state: 'resolved', count: 1 }], by_severity: [{ severity: 'high', count: 1 }, { severity: 'unknown', count: 3 }] }
        : null,
    }),
    'finding summary',
  );
}

export function timeline(over: Partial<UnknownDeviceTimeline> = {}): UnknownDeviceTimeline {
  const event = (seq: number, extra: Record<string, unknown>) => ({
    id: `unknown-device-event-6f1c2a9e-0b1d-5c3e-8f4a-12345678900${seq}`,
    finding_id: FINDING_ID, seq, occurred_at: NOW, actor_id: 'system:unknown-device-scan',
    kind: 'detected', state_from: null, state_to: null, reason: null, message: null, subject_id: null, ...extra,
  });
  const events = over.events ?? [
    event(1, {}),
    event(2, { kind: 'state-changed', state_from: 'new', state_to: 'acknowledged', actor_id: 'oidc:analyst-1' }),
    event(3, { kind: 'comment', message: HOSTILE, actor_id: 'oidc:analyst-1' }),
  ];
  return must(
    parseUnknownDeviceTimeline({
      state: 'ok', generated_at: NOW, finding_id: FINDING_ID, after_seq: 0, next_after_seq: null, ...over, events,
    }),
    'timeline',
  );
}
