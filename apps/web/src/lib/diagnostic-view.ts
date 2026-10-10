/**
 * Pure view helpers for the read-only diagnostics UI (S7-3).
 *
 * Maps canonical contract values to presentation labels. Everything here is
 * deterministic and side-effect free so the UI can be tested without React or a
 * browser. Untrusted values (target, symptom, details) are never injected into
 * these labels — they are rendered as text nodes by React.
 */
import type {
  DiagnosticCheckKind,
  DiagnosticConfidence,
  DiagnosticRun,
  FaultDomain,
} from './api-contracts-diagnostic.ts';
import { MAX_DIAGNOSTIC_REQUEST_CHECKS } from './api-contracts-diagnostic.ts';

export interface DiagnosticCheckOption {
  kind: DiagnosticCheckKind;
  label: string;
  detail: string;
}

/**
 * Checks the operator can select. Only a subset of the canonical kinds is
 * offered: the adapter that actually runs probes today covers DNS / TCP /
 * HTTP(S), and the source-backed checks are offered too because the API answers
 * them honestly as `unknown` instead of guessing.
 */
export const DIAGNOSTIC_CHECK_OPTIONS: readonly DiagnosticCheckOption[] = [
  { kind: 'dns', label: 'DNS Resolution', detail: 'Resolves the target name.' },
  {
    kind: 'icmp',
    label: 'ICMP Ping',
    detail: 'Reachability probe; unknown unless a delegated prober is available.',
  },
  { kind: 'tcp', label: 'TCP port', detail: 'Connects to the default service port.' },
  { kind: 'http', label: 'HTTP', detail: 'Requests the HTTP endpoint.' },
  { kind: 'https', label: 'HTTPS', detail: 'Requests the HTTPS endpoint.' },
  {
    kind: 'service',
    label: 'Service health',
    detail: 'Requires a monitoring source; otherwise reported unknown.',
  },
  {
    kind: 'target-health',
    label: 'Target health',
    detail: 'CPU / memory; requires a monitoring source; otherwise reported unknown.',
  },
  {
    kind: 'dependencies',
    label: 'Dependencies',
    detail: 'Downstream dependencies; requires a source; otherwise reported unknown.',
  },
];

export const DEFAULT_DIAGNOSTIC_CHECKS: readonly DiagnosticCheckKind[] = [
  'dns',
  'icmp',
  'tcp',
  'https',
];

// The vantage a run ran from is provenance: this deployment serves exactly one, and the UI must not
// let an operator claim another. The request omits a vantage and the API stamps where checks ran, so
// no vantage options are offered here.

const CHECK_BY_KIND = new Map<DiagnosticCheckKind, DiagnosticCheckOption>(
  DIAGNOSTIC_CHECK_OPTIONS.map((option) => [option.kind, option]),
);

export function checkOption(kind: DiagnosticCheckKind): DiagnosticCheckOption | null {
  return CHECK_BY_KIND.get(kind) ?? null;
}

export function checkLabel(kind: DiagnosticCheckKind): string {
  return CHECK_BY_KIND.get(kind)?.label ?? kind;
}

export function checkDetail(kind: DiagnosticCheckKind): string {
  return CHECK_BY_KIND.get(kind)?.detail ?? 'No description is available for this check.';
}

export const FAULT_DOMAIN_LABELS: Record<FaultDomain, string> = {
  target: 'Target host',
  service: 'Service',
  host: 'Host',
  interface: 'Interface',
  'access-device': 'Access device',
  core: 'Core network',
  firewall: 'Firewall / path',
  'wan-dns-external': 'WAN / external DNS',
};

export function faultDomainLabel(domain: FaultDomain | null): string | null {
  return domain === null ? null : FAULT_DOMAIN_LABELS[domain];
}

export const CONFIDENCE_LABELS: Record<DiagnosticConfidence, string> = {
  low: 'Low confidence',
  medium: 'Medium confidence',
  high: 'High confidence',
  unknown: 'Unknown confidence',
};

export function confidenceLabel(confidence: DiagnosticConfidence): string {
  return CONFIDENCE_LABELS[confidence];
}

export interface RunCheckSummary {
  pass: number;
  fail: number;
  unknown: number;
}

export function runCheckSummary(run: DiagnosticRun): RunCheckSummary {
  const summary: RunCheckSummary = { pass: 0, fail: 0, unknown: 0 };
  for (const check of run.checks) {
    if (check.status === 'pass') summary.pass += 1;
    else if (check.status === 'fail') summary.fail += 1;
    else summary.unknown += 1;
  }
  return summary;
}

/**
 * The sentence shown when no fault domain was named. A null domain means the engine did not name a
 * domain — it does not mean "no fault": checks may have failed without narrowing, or may never have
 * been answered. The copy must reflect which of those actually happened (AGENTS.md: known /
 * inferred / unknown are distinct and an unknown is never shown as a healthy result).
 */
export function noFaultNarrative(summary: RunCheckSummary): string {
  const total = summary.pass + summary.fail + summary.unknown;
  if (summary.fail > 0) {
    return 'One or more checks failed, but the evidence did not narrow the fault to a single domain, so the engine does not guess.';
  }
  if (total > 0 && summary.pass === total) {
    return 'Every requested check passed, so the reported symptom was not reproduced in this round.';
  }
  if (summary.pass > 0) {
    return 'Some checks passed, but too little evidence was gathered to name a fault domain.';
  }
  return 'No check could be answered, so there is nothing to conclude from this round.';
}

export interface DiagnosticRunForm {
  target: string;
  symptom: string;
  checks: DiagnosticCheckKind[];
}

/**
 * Runtime shape guard for untrusted input (a Next server action is a public POST). The action
 * receives `unknown` and this rejects anything that is not the exact string/array shape before any
 * value is passed to `cleanRunForm`; the API remains the final authority. The raw check array is
 * bounded before deduplication so an oversized body cannot force O(n) work here.
 */
export function isDiagnosticRunForm(value: unknown): value is DiagnosticRunForm {
  if (typeof value !== 'object' || value === null) return false;
  const candidate = value as Record<string, unknown>;
  return (
    typeof candidate.target === 'string' &&
    typeof candidate.symptom === 'string' &&
    Array.isArray(candidate.checks) &&
    candidate.checks.length <= MAX_DIAGNOSTIC_REQUEST_CHECKS &&
    candidate.checks.every((item) => typeof item === 'string')
  );
}

export type ClearedRunForm =
  | {
      ok: true;
      target: string;
      symptom: string | null;
      requested_checks: DiagnosticCheckKind[];
    }
  | { ok: false; message: string };

/**
 * Client-side shape guard that mirrors the canonical request contract
 * (`contracts/json-schema/diagnostic-api.schema.json`): the API remains
 * authoritative and every value is still validated there, this just fails
 * fast with a readable message. No vantage is sent: provenance is the
 * deployment's, decided by the prober, never by the form.
 */
export function cleanRunForm(form: DiagnosticRunForm): ClearedRunForm {
  const target = form.target.trim();
  if (target.length === 0) {
    return { ok: false, message: 'Enter a target hostname or address.' };
  }
  // Match the contract's maxLength (code points), not UTF-16 code units.
  if ([...target].length > 255) {
    return { ok: false, message: 'The target is limited to 255 characters.' };
  }

  const symptom = form.symptom.trim();
  const checks = Array.from(new Set(form.checks));
  if (checks.length === 0) {
    return { ok: false, message: 'Select at least one diagnostic check.' };
  }
  if (checks.length > MAX_DIAGNOSTIC_REQUEST_CHECKS) {
    return { ok: false, message: 'Select at most 12 diagnostic checks.' };
  }
  if (checks.some((kind) => !CHECK_BY_KIND.has(kind))) {
    return { ok: false, message: 'An unknown diagnostic check was selected.' };
  }

  return {
    ok: true,
    target,
    symptom: symptom.length === 0 ? null : symptom.slice(0, 1000),
    requested_checks: checks,
  };
}