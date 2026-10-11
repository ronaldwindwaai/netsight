'use server';

import { apiPost } from '@/lib/api';
import { parseUnknownDeviceScan, type UnknownDeviceScan } from '@/lib/api-contracts-unknown-devices';
import { NOT_SAME_ORIGIN_MESSAGE, fromSameOrigin } from '@/lib/server-write';
import { describeWriteFailure } from '@/lib/write-outcome';

/** A scan reads three sources under a 25 s server budget; the default 10 s would cut it short. */
const SCAN_TIMEOUT_MS = 30_000;

/** Plain serialisable data only: the scan summary, or the account of why it did not run. */
export type ScanActionResult =
  | { ok: true; scan: UnknownDeviceScan }
  | { ok: false; title: string; message: string; correlationId: string };

/**
 * Ask the API to run one detection scan now. It reads NetBox and telemetry and records findings; it
 * writes nothing to any network system. The body is empty by contract, and the origin is checked
 * before the session and CSRF token are attached server-side by `apiPost`.
 */
export async function performScan(): Promise<ScanActionResult> {
  if (!(await fromSameOrigin())) {
    return { ok: false, title: 'Not sent', message: NOT_SAME_ORIGIN_MESSAGE, correlationId: 'not-available' };
  }
  const state = await apiPost('/api/v1/unknown-devices/scan', {}, parseUnknownDeviceScan, {
    timeoutMs: SCAN_TIMEOUT_MS,
  });
  if (state.kind === 'ok') return { ok: true, scan: state.data };
  const failure = describeWriteFailure(state);
  return { ok: false, title: failure.title, message: failure.message, correlationId: failure.correlationId };
}
