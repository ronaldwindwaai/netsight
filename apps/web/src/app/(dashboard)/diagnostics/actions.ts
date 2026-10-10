'use server';

import { headers } from 'next/headers';

import { apiPost, type FetchState } from '@/lib/api';
import { parseDiagnosticRunResponse } from '@/lib/api-contracts-diagnostic';
import type { DiagnosticRunRequest, DiagnosticRunResponse } from '@/lib/api-contracts-diagnostic';
import { cleanRunForm, isDiagnosticRunForm } from '@/lib/diagnostic-view';
import { sameOrigin } from '@/lib/request-origin';

// A run performs up to twelve bounded probes and the API caps the whole run at
// ~20 s, so this write needs a longer budget than the default read timeout.
const DIAGNOSTIC_RUN_TIMEOUT_MS = 45_000;

export type DiagnosticActionResult =
  | { ok: true; state: FetchState<DiagnosticRunResponse> }
  | { ok: false; message: string };

/**
 * A server action is a public POST, so its own cross-site control is asserted here rather than left
 * to the framework default: the browser's Origin (or Referer) must match the host the request was
 * addressed to. This is defence in depth in front of `apiPost`, which attaches the session cookie
 * and CSRF token server-side.
 */
async function fromSameOrigin(): Promise<boolean> {
  const headerList = await headers();
  const host = headerList.get('x-forwarded-host') ?? headerList.get('host');
  return sameOrigin(host, headerList.get('origin'), headerList.get('referer'));
}

/**
 * Server-side run of a read-only diagnostic. The session cookie and CSRF token
 * are attached by `apiPost`, so a cross-site page cannot drive a run. The input
 * arrives from the browser, so it is shape-checked before use and the API
 * remains the authority on every field.
 */
export async function createDiagnosticRun(input: unknown): Promise<DiagnosticActionResult> {
  if (!(await fromSameOrigin())) {
    return { ok: false, message: 'The diagnostic request did not come from this site.' };
  }
  if (!isDiagnosticRunForm(input)) {
    return { ok: false, message: 'The diagnostic request was not well formed.' };
  }
  const cleaned = cleanRunForm(input);
  if (!cleaned.ok) {
    return { ok: false, message: cleaned.message };
  }

  const request: DiagnosticRunRequest = {
    target: cleaned.target,
    symptom: cleaned.symptom,
    // Provenance is the deployment's: the request never asserts a vantage, so the
    // API stamps where the checks actually ran.
    vantage: null,
    requested_checks: cleaned.requested_checks,
  };

  const state = await apiPost(
    '/api/v1/diagnostics',
    request,
    parseDiagnosticRunResponse,
    { timeoutMs: DIAGNOSTIC_RUN_TIMEOUT_MS },
  );
  return { ok: true, state };
}