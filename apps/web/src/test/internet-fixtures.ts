import type {
  InternetResponse,
  SlaLink,
  SlaResponse,
  WanAvailability,
  WanInterfaceReading,
  WanLink,
  WanQuality,
} from '@/lib/api-contracts-internet';
import type { FetchState } from '@/lib/api-response';

/** Typed fixtures for the Internet components (no file access: component tests run bundled). */

export const GENERATED_AT = '2026-10-11T10:00:00Z';
const FRESH_LIBRENMS = { state: 'fresh', observed_at: '2026-10-11T09:59:00Z', source: 'librenms' } as const;
const FRESH_PROBES = { state: 'fresh', observed_at: '2026-10-11T09:59:30Z', source: 'blackbox-probes' } as const;
const NO_FRESHNESS = { state: 'unknown', observed_at: null, source: null } as const;

export function interfaceFixture(overrides: Partial<WanInterfaceReading> = {}): WanInterfaceReading {
  return {
    state: 'ok',
    oper_status: 'up',
    capacity_bps: 1_000_000_000,
    rx_bps: 100_000_000,
    tx_bps: 20_000_000,
    utilisation_pct: 10,
    public_ip: '8.8.8.8',
    freshness: { ...FRESH_LIBRENMS },
    ...overrides,
  };
}

export function absentInterface(state: 'not-connected' | 'unknown'): WanInterfaceReading {
  return interfaceFixture({
    state,
    oper_status: null,
    capacity_bps: null,
    rx_bps: null,
    tx_bps: null,
    utilisation_pct: null,
    public_ip: null,
    freshness: { ...NO_FRESHNESS },
  });
}

export function qualityFixture(overrides: Partial<WanQuality> = {}): WanQuality {
  return {
    state: 'ok',
    latency_ms: 12.5,
    jitter_ms: 1.5,
    loss_pct: 0,
    dns_status: 'pass',
    dns_latency_ms: 20.1,
    sample_count: 30,
    window_seconds: 900,
    freshness: { ...FRESH_PROBES },
    ...overrides,
  };
}

export function absentQuality(state: 'not-connected' | 'unknown'): WanQuality {
  return qualityFixture({
    state,
    latency_ms: null,
    jitter_ms: null,
    loss_pct: null,
    dns_status: null,
    dns_latency_ms: null,
    sample_count: 0,
    freshness: { ...NO_FRESHNESS },
  });
}

export function availabilityFixture(overrides: Partial<WanAvailability> = {}): WanAvailability {
  return {
    state: 'ok',
    period_start: '2026-10-10T10:00:00Z',
    period_end: GENERATED_AT,
    uptime_pct: 99.95,
    coverage_pct: 98,
    current_outage_started_at: null,
    current_outage_seconds: null,
    freshness: { ...FRESH_PROBES },
    ...overrides,
  };
}

export function absentAvailability(state: 'not-connected' | 'unknown'): WanAvailability {
  return availabilityFixture({
    state,
    period_start: null,
    period_end: null,
    uptime_pct: null,
    coverage_pct: null,
    freshness: { ...NO_FRESHNESS },
  });
}

export function linkFixture(overrides: Partial<WanLink> = {}): WanLink {
  return {
    id: 'fibre-1',
    name: 'Primary fibre',
    role: 'primary',
    configured: { isp: 'Example ISP', gateway: '192.0.2.1', probe_location: 'branch' },
    status: 'up',
    interface: interfaceFixture(),
    quality: qualityFixture(),
    availability: availabilityFixture(),
    ...overrides,
  };
}

export function responseFixture(overrides: Partial<InternetResponse> = {}): InternetResponse {
  return {
    state: 'ok',
    generated_at: GENERATED_AT,
    links: [linkFixture()],
    failover: { state: 'single-link', basis: 'inferred' },
    detail_redacted: false,
    ...overrides,
  };
}

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

export function slaLinkFixture(overrides: Partial<SlaLink> = {}): SlaLink {
  return {
    link_id: 'fibre-1',
    name: 'Primary fibre',
    state: 'ok',
    uptime_target_pct: 99.5,
    total_seconds: 864_000,
    up_seconds: 800_000,
    degraded_seconds: 1000,
    down_seconds: 600,
    unknown_seconds: 62_400,
    uptime_pct: 99.925,
    coverage_pct: 92.778,
    outage_count: 2,
    longest_outage_seconds: 400,
    cycle_count: 13_360,
    windows_truncated: false,
    violations: [],
    ...overrides,
  };
}

export function slaFixture(overrides: Partial<SlaResponse> = {}): SlaResponse {
  return {
    state: 'ok',
    month: '2026-09',
    period_start: '2026-09-01T00:00:00Z',
    period_end: '2026-10-01T00:00:00Z',
    generated_at: GENERATED_AT,
    links: [slaLinkFixture()],
    ...overrides,
  };
}

/** The link as the API returns it to a role without internet:read_detail. */
export function redactedLinkFixture(overrides: Partial<WanLink> = {}): WanLink {
  return linkFixture({
    configured: { isp: null, gateway: null, probe_location: 'branch' },
    interface: interfaceFixture({
      rx_bps: null,
      tx_bps: null,
      utilisation_pct: null,
      public_ip: null,
    }),
    ...overrides,
  });
}
