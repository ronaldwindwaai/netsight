import { isRfc3339 } from './api-contracts.ts';
import {
  hasExactKeys,
  isIntegerInRange,
  isNonBlankText,
  isNullableNonBlankText,
  isNullableText,
  isOneOf,
  isPlainRecord,
  isText,
  parseArray,
  textItem,
} from './contract-guards.ts';

/**
 * Diagnostic ("Why?") contract, mirroring contracts/json-schema/diagnostic.schema.json and
 * diagnostic-api.schema.json. Every parser is fail-closed: anything that does not satisfy the
 * exact contract returns null, and the caller must render an explicit error state rather than
 * guess. Free-text fields are untrusted source data and are never interpreted as instructions.
 */

export const DIAGNOSTIC_STATES = ['not-connected', 'ok', 'unknown'] as const;
export const DIAGNOSTIC_CHECK_KINDS = [
  'identity',
  'source-freshness',
  'target-health',
  'dns',
  'icmp',
  'tcp',
  'http',
  'https',
  'service',
  'dependencies',
  'recent-changes',
  'baseline',
] as const;
export const DIAGNOSTIC_CHECK_STATUSES = ['pass', 'fail', 'unknown'] as const;
export const FAULT_DOMAINS = [
  'target',
  'service',
  'host',
  'interface',
  'access-device',
  'core',
  'firewall',
  'wan-dns-external',
] as const;
export const DIAGNOSTIC_CONFIDENCES = ['low', 'medium', 'high', 'unknown'] as const;
/** Where a check ran: the configured probe source's location, never inferred from a vantage label. */
export const PROBE_LOCATIONS = [
  'cloud-external',
  'user-lan',
  'server-vlan',
  'branch',
  'wifi',
  'remote-site',
] as const;

export type DiagnosticState = (typeof DIAGNOSTIC_STATES)[number];
export type DiagnosticCheckKind = (typeof DIAGNOSTIC_CHECK_KINDS)[number];
export type DiagnosticCheckStatus = (typeof DIAGNOSTIC_CHECK_STATUSES)[number];
export type FaultDomain = (typeof FAULT_DOMAINS)[number];
export type DiagnosticConfidence = (typeof DIAGNOSTIC_CONFIDENCES)[number];
export type ProbeLocation = (typeof PROBE_LOCATIONS)[number];

export const MAX_DIAGNOSTIC_CHECKS = 64;
export const MAX_DIAGNOSTIC_FINDINGS = 64;
export const MAX_DIAGNOSTIC_CONTRADICTIONS = 32;
export const MAX_DIAGNOSTIC_UNKNOWNS = 32;
export const MAX_DIAGNOSTIC_HYPOTHESES = 16;
export const MAX_DIAGNOSTIC_NEXT_CHECKS = 32;
export const MAX_DIAGNOSTIC_EVIDENCE = 256;
export const MAX_FINDING_EVIDENCE = 32;
export const MAX_DIAGNOSTIC_REQUEST_CHECKS = 12;

export interface DiagnosticFinding {
  statement: string;
  evidence_ids: string[];
}

export interface DiagnosticProbeResult {
  id: string;
  kind: DiagnosticCheckKind;
  label: string;
  status: DiagnosticCheckStatus;
  vantage: string | null;
  location: ProbeLocation | null;
  port: number | null;
  latency_ms: number | null;
  detail: string | null;
  observed_at: string | null;
  evidence_id: string | null;
}

export interface DiagnosticRun {
  id: string;
  target: string;
  target_id: string | null;
  symptom: string | null;
  vantage: string | null;
  started_at: string;
  completed_at: string;
  checks: DiagnosticProbeResult[];
  facts: DiagnosticFinding[];
  contradictions: DiagnosticFinding[];
  unknowns: DiagnosticFinding[];
  probable_fault_domain: FaultDomain | null;
  confidence: DiagnosticConfidence;
  alternative_hypotheses: DiagnosticFinding[];
  recommended_next_checks: DiagnosticFinding[];
  evidence_ids: string[];
}

export interface DiagnosticRunRequest {
  target: string;
  symptom: string | null;
  vantage: string | null;
  requested_checks: DiagnosticCheckKind[];
}

export interface DiagnosticRunResponse {
  state: DiagnosticState;
  run: DiagnosticRun | null;
  /** True exactly when the run was persisted as a session that can be revisited. */
  stored: boolean;
}

const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
const DIAGNOSTIC_ID = new RegExp(`^diagnostic-${UUID}$`);
const DEVICE_ID = new RegExp(`^device-${UUID}$`);

const FINDING_KEYS = ['statement', 'evidence_ids'] as const;
const CHECK_KEYS = [
  'id',
  'kind',
  'label',
  'status',
  'vantage',
  'location',
  'port',
  'latency_ms',
  'detail',
  'observed_at',
  'evidence_id',
] as const;
const RUN_KEYS = [
  'id',
  'target',
  'target_id',
  'symptom',
  'vantage',
  'started_at',
  'completed_at',
  'checks',
  'facts',
  'contradictions',
  'unknowns',
  'probable_fault_domain',
  'confidence',
  'alternative_hypotheses',
  'recommended_next_checks',
  'evidence_ids',
] as const;
const RUN_REQUEST_KEYS = ['target', 'symptom', 'vantage', 'requested_checks'] as const;
const RUN_RESPONSE_KEYS = ['state', 'run', 'stored'] as const;
const PORT_CHECK_KINDS: readonly DiagnosticCheckKind[] = ['tcp', 'http', 'https'];

function isTimestamp(value: unknown): value is string {
  return typeof value === 'string' && isRfc3339(value);
}

function isNullableTimestamp(value: unknown): value is string | null {
  return value === null || isTimestamp(value);
}

function isNullableNumberInRange(
  value: unknown,
  minimum: number,
  maximum: number,
): value is number | null {
  return (
    value === null ||
    (typeof value === 'number' && Number.isFinite(value) && value >= minimum && value <= maximum)
  );
}

function isNullablePort(value: unknown): value is number | null {
  return value === null || isIntegerInRange(value, 1, 65_535);
}

function isDeviceId(value: unknown): value is string {
  return typeof value === 'string' && DEVICE_ID.test(value);
}

function isNullableFaultDomain(value: unknown): value is FaultDomain | null {
  return value === null || isOneOf(value, FAULT_DOMAINS);
}

function isConfidence(value: unknown): value is DiagnosticConfidence {
  return isOneOf(value, DIAGNOSTIC_CONFIDENCES);
}

/** Fail-closed parse; returns a detached copy or null. */
export function parseDiagnosticFinding(value: unknown): DiagnosticFinding | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, FINDING_KEYS)) return null;
  const evidence = parseArray(value.evidence_ids, 0, MAX_FINDING_EVIDENCE, textItem(1, 128), true);
  if (!isNonBlankText(value.statement, 1000) || evidence === null) return null;
  return { statement: value.statement, evidence_ids: evidence };
}

/** Fail-closed parse; returns a detached copy or null. */
export function parseDiagnosticProbeResult(value: unknown): DiagnosticProbeResult | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, CHECK_KEYS)) return null;
  if (
    !isText(value.id, 1, 128) ||
    !isOneOf(value.kind, DIAGNOSTIC_CHECK_KINDS) ||
    !isNonBlankText(value.label, 255) ||
    !isOneOf(value.status, DIAGNOSTIC_CHECK_STATUSES) ||
    !isNullableNonBlankText(value.vantage, 128) ||
    !(value.location === null || isOneOf(value.location, PROBE_LOCATIONS)) ||
    !isNullablePort(value.port) ||
    !isNullableNumberInRange(value.latency_ms, 0, 3_600_000) ||
    !isNullableNonBlankText(value.detail, 1000) ||
    !isNullableTimestamp(value.observed_at) ||
    !isNullableText(value.evidence_id, 1, 128)
  ) {
    return null;
  }
  if (value.port !== null && !PORT_CHECK_KINDS.includes(value.kind)) return null;
  return {
    id: value.id,
    kind: value.kind,
    label: value.label,
    status: value.status,
    vantage: value.vantage,
    location: value.location,
    port: value.port,
    latency_ms: value.latency_ms,
    detail: value.detail,
    observed_at: value.observed_at,
    evidence_id: value.evidence_id,
  };
}

/** Fail-closed parse; returns a detached copy or null. */
export function parseDiagnosticRun(value: unknown): DiagnosticRun | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, RUN_KEYS)) return null;
  if (
    typeof value.id !== 'string' ||
    !DIAGNOSTIC_ID.test(value.id) ||
    !isNonBlankText(value.target, 255) ||
    !(value.target_id === null || isDeviceId(value.target_id)) ||
    !isNullableNonBlankText(value.symptom, 1000) ||
    !isNullableNonBlankText(value.vantage, 128) ||
    !isTimestamp(value.started_at) ||
    !isTimestamp(value.completed_at) ||
    !isConfidence(value.confidence) ||
    !isNullableFaultDomain(value.probable_fault_domain)
  ) {
    return null;
  }
  const checks = parseArray(value.checks, 0, MAX_DIAGNOSTIC_CHECKS, parseDiagnosticProbeResult, false);
  const facts = parseArray(value.facts, 0, MAX_DIAGNOSTIC_FINDINGS, parseDiagnosticFinding, false);
  const contradictions = parseArray(
    value.contradictions,
    0,
    MAX_DIAGNOSTIC_CONTRADICTIONS,
    parseDiagnosticFinding,
    false,
  );
  const unknowns = parseArray(value.unknowns, 0, MAX_DIAGNOSTIC_UNKNOWNS, parseDiagnosticFinding, false);
  const hypotheses = parseArray(
    value.alternative_hypotheses,
    0,
    MAX_DIAGNOSTIC_HYPOTHESES,
    parseDiagnosticFinding,
    false,
  );
  const nextChecks = parseArray(
    value.recommended_next_checks,
    0,
    MAX_DIAGNOSTIC_NEXT_CHECKS,
    parseDiagnosticFinding,
    false,
  );
  const evidence = parseArray(value.evidence_ids, 0, MAX_DIAGNOSTIC_EVIDENCE, textItem(1, 128), true);
  if (
    checks === null ||
    facts === null ||
    contradictions === null ||
    unknowns === null ||
    hypotheses === null ||
    nextChecks === null ||
    evidence === null
  ) {
    return null;
  }
  // Cross-field rules JSON Schema cannot express.
  if (Date.parse(value.completed_at) < Date.parse(value.started_at)) return null;
  if ((value.probable_fault_domain === null) !== (value.confidence === 'unknown')) return null;
  if (new Set(checks.map((check) => check.id)).size !== checks.length) return null;
  return {
    id: value.id,
    target: value.target,
    target_id: value.target_id,
    symptom: value.symptom,
    vantage: value.vantage,
    started_at: value.started_at,
    completed_at: value.completed_at,
    checks,
    facts,
    contradictions,
    unknowns,
    probable_fault_domain: value.probable_fault_domain,
    confidence: value.confidence,
    alternative_hypotheses: hypotheses,
    recommended_next_checks: nextChecks,
    evidence_ids: evidence,
  };
}

/** Fail-closed parse of the request body; returns a detached copy or null. */
export function parseDiagnosticRunRequest(value: unknown): DiagnosticRunRequest | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, RUN_REQUEST_KEYS)) return null;
  const requested = parseArray(
    value.requested_checks,
    1,
    MAX_DIAGNOSTIC_REQUEST_CHECKS,
    (item) => (isOneOf(item, DIAGNOSTIC_CHECK_KINDS) ? item : null),
    true,
  );
  if (
    !isNonBlankText(value.target, 255) ||
    !isNullableNonBlankText(value.symptom, 1000) ||
    !isNullableNonBlankText(value.vantage, 128) ||
    requested === null
  ) {
    return null;
  }
  return {
    target: value.target,
    symptom: value.symptom,
    vantage: value.vantage,
    requested_checks: requested,
  };
}

/** Fail-closed parse; the run is present exactly when the state is ok, and only an ok run is stored. */
export function parseDiagnosticRunResponse(value: unknown): DiagnosticRunResponse | null {
  if (!isPlainRecord(value) || !hasExactKeys(value, RUN_RESPONSE_KEYS)) return null;
  if (!isOneOf(value.state, DIAGNOSTIC_STATES) || typeof value.stored !== 'boolean') return null;
  const run = value.run === null ? null : parseDiagnosticRun(value.run);
  if (value.run !== null && run === null) return null;
  if ((value.state === 'ok') !== (run !== null)) return null;
  if (value.stored && value.state !== 'ok') return null;
  return { state: value.state, run, stored: value.stored };
}
