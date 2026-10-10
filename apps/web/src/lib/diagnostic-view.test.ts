import assert from 'node:assert/strict';
import test from 'node:test';

import {
  DIAGNOSTIC_CHECK_KINDS,
  DIAGNOSTIC_CONFIDENCES,
  FAULT_DOMAINS,
  MAX_DIAGNOSTIC_REQUEST_CHECKS,
  type DiagnosticCheckKind,
  type DiagnosticRun,
} from './api-contracts-diagnostic.ts';
import {
  CONFIDENCE_LABELS,
  DEFAULT_DIAGNOSTIC_CHECKS,
  DIAGNOSTIC_CHECK_OPTIONS,
  FAULT_DOMAIN_LABELS,
  checkDetail,
  checkLabel,
  cleanRunForm,
  confidenceLabel,
  faultDomainLabel,
  isDiagnosticRunForm,
  noFaultNarrative,
  runCheckSummary,
} from './diagnostic-view.ts';

function stubRun(overrides: Partial<DiagnosticRun> = {}): DiagnosticRun {
  return {
    id: 'diagnostic-123e4567-e89b-12d3-a456-426614174000',
    target: 'web-srv02',
    target_id: null,
    symptom: null,
    vantage: 'internal',
    started_at: '2026-10-08T12:00:00Z',
    completed_at: '2026-10-08T12:00:03Z',
    checks: [],
    facts: [],
    contradictions: [],
    unknowns: [],
    probable_fault_domain: null,
    confidence: 'unknown',
    alternative_hypotheses: [],
    recommended_next_checks: [],
    evidence_ids: [],
    ...overrides,
  };
}

function probe(
  index: number,
  kind: DiagnosticCheckKind,
  status: 'pass' | 'fail' | 'unknown',
): DiagnosticRun['checks'][number] {
  return {
    id: `check-${index}-${kind}`,
    kind,
    label: kind,
    status,
    vantage: 'internal',
    location: null,
    port: kind === 'tcp' ? 443 : null,
    latency_ms: status === 'unknown' ? null : 5,
    detail: status === 'unknown' ? 'no source' : kind,
    observed_at: '2026-10-08T12:00:01Z',
    evidence_id: null,
  };
}

test('every offered check maps to a label and a detail', () => {
  for (const option of DIAGNOSTIC_CHECK_OPTIONS) {
    assert.ok(DIAGNOSTIC_CHECK_KINDS.includes(option.kind), `unknown kind ${option.kind}`);
    assert.ok(option.label.length > 0);
    assert.ok(option.detail.length > 0);
    assert.equal(checkLabel(option.kind), option.label);
    assert.equal(checkDetail(option.kind), option.detail);
  }
});

test('an unoffered canonical kind still gets a stable label', () => {
  assert.equal(checkLabel('baseline'), 'baseline');
  assert.ok(checkDetail('baseline').length > 0);
});

test('the default check selection is within the offered catalogue and the contract bound', () => {
  const offered = new Set(DIAGNOSTIC_CHECK_OPTIONS.map((option) => option.kind));
  assert.ok(DEFAULT_DIAGNOSTIC_CHECKS.length >= 1);
  assert.ok(DEFAULT_DIAGNOSTIC_CHECKS.length <= MAX_DIAGNOSTIC_REQUEST_CHECKS);
  for (const kind of DEFAULT_DIAGNOSTIC_CHECKS) {
    assert.ok(offered.has(kind), `default check ${kind} is not selectable`);
  }
});

test('every fault domain and confidence value has a label', () => {
  for (const domain of FAULT_DOMAINS) {
    assert.ok(FAULT_DOMAIN_LABELS[domain].length > 0);
    assert.equal(faultDomainLabel(domain), FAULT_DOMAIN_LABELS[domain]);
  }
  assert.equal(faultDomainLabel(null), null);
  for (const confidence of DIAGNOSTIC_CONFIDENCES) {
    assert.ok(CONFIDENCE_LABELS[confidence].length > 0);
    assert.ok(confidenceLabel(confidence).length > 0);
  }
});

test('runCheckSummary counts each status class', () => {
  const run = stubRun({
    checks: [
      probe(0, 'dns', 'pass'),
      probe(1, 'tcp', 'fail'),
      probe(2, 'service', 'unknown'),
    ],
  });
  assert.deepEqual(runCheckSummary(run), { pass: 1, fail: 1, unknown: 1 });
});

test('noFaultNarrative distinguishes failures, all-pass, mixed and all-unknown', () => {
  // Failures present: the run must not claim no fault was reproduced.
  const failed = noFaultNarrative({ pass: 1, fail: 2, unknown: 0 });
  assert.match(failed, /failed/i);
  assert.doesNotMatch(failed, /no fault/i);

  // Every check passed: the symptom was not reproduced.
  const allPass = noFaultNarrative({ pass: 3, fail: 0, unknown: 0 });
  assert.match(allPass, /passed/i);
  assert.match(allPass, /not reproduced/i);

  // Some passed, some answered unknown: not enough evidence, but not "no fault".
  const mixed = noFaultNarrative({ pass: 1, fail: 0, unknown: 2 });
  assert.match(mixed, /not enough|too little/i);
  assert.doesNotMatch(mixed, /no fault/i);

  // Nothing answered: there is nothing to conclude.
  const allUnknown = noFaultNarrative({ pass: 0, fail: 0, unknown: 2 });
  assert.match(allUnknown, /no check could be answered/i);
});

test('cleanRunForm trims and normalizes a valid form', () => {
  const cleaned = cleanRunForm({
    target: '  WEB-SRV02  ',
    symptom: '  timeouts  ',
    checks: ['dns', 'tcp', 'dns'],
  });
  assert.deepEqual(cleaned, {
    ok: true,
    target: 'WEB-SRV02',
    symptom: 'timeouts',
    requested_checks: ['dns', 'tcp'],
  });
});

test('cleanRunForm turns blank fields into null and clamps long text', () => {
  const cleaned = cleanRunForm({
    target: 'srv',
    symptom: '  ',
    checks: ['icmp'],
  });
  assert.deepEqual(cleaned, {
    ok: true,
    target: 'srv',
    symptom: null,
    requested_checks: ['icmp'],
  });
  const clamped = cleanRunForm({
    target: 'srv',
    symptom: `${'x'.repeat(5000)}`,
    checks: ['dns'],
  });
  assert.ok(clamped.ok);
  if (clamped.ok) {
    assert.equal(clamped.requested_checks.length, 1);
    assert.ok(clamped.symptom !== null && clamped.symptom.length === 1000);
  }
});

test('cleanRunForm rejects invalid inputs', () => {
  const noTarget = cleanRunForm({ target: '  ', symptom: '', checks: ['dns'] });
  assert.equal(noTarget.ok, false);
  const longTarget = cleanRunForm({
    target: 'x'.repeat(256),
    symptom: '',
    checks: ['dns'],
  });
  assert.equal(longTarget.ok, false);
  const noChecks = cleanRunForm({ target: 'srv', symptom: '', checks: [] });
  assert.equal(noChecks.ok, false);
  const unofferedKind = cleanRunForm({
    target: 'srv',
    symptom: '',
    checks: ['baseline'],
  });
  assert.equal(unofferedKind.ok, false);
});

test('cleanRunForm collapses duplicates within the contract bound', () => {
  const repeated: DiagnosticCheckKind[] = [
    'dns', 'icmp', 'tcp', 'http', 'https', 'service', 'target-health', 'dependencies',
    'dns', 'icmp', 'tcp', 'http', 'https',
  ];
  const cleaned = cleanRunForm({ target: 'srv', symptom: '', checks: repeated });
  assert.ok(cleaned.ok);
  assert.equal(cleaned.requested_checks.length, 8);
  assert.equal(new Set(cleaned.requested_checks).size, cleaned.requested_checks.length);
});

test('isDiagnosticRunForm accepts the exact input shape and rejects everything else', () => {
  const valid: unknown = { target: 'srv', symptom: '', checks: ['dns'] };
  assert.equal(isDiagnosticRunForm(valid), true);
  if (isDiagnosticRunForm(valid)) {
    assert.equal(valid.target, 'srv');
  }

  const rejected: unknown[] = [
    null,
    undefined,
    'srv',
    42,
    [],
    {},
    { target: 'srv', symptom: '' },
    { target: 7, symptom: '', checks: ['dns'] },
    { target: 'srv', symptom: null, checks: ['dns'] },
    { target: 'srv', symptom: '', checks: 'dns' },
    { target: 'srv', symptom: '', checks: [1, 2] },
    // An oversized raw array is refused before any dedup work happens.
    { target: 'srv', symptom: '', checks: Array(MAX_DIAGNOSTIC_REQUEST_CHECKS + 1).fill('dns') },
  ];
  for (const value of rejected) {
    assert.equal(isDiagnosticRunForm(value), false, `should reject ${JSON.stringify(value)}`);
  }
});