import type { WriteActionResult } from '@/lib/write-result';

/**
 * Stands in for the unknown-device server actions in component tests. A test installs a handler
 * (usually a `mock.fn`) and inspects what the component sent.
 */
type ScanResult =
  | { ok: true; scan: import('@/lib/api-contracts-unknown-devices').UnknownDeviceScan }
  | { ok: false; title: string; message: string; correlationId: string };

export const findingHandlers: {
  finding: (input: unknown) => Promise<WriteActionResult>;
  scan: () => Promise<ScanResult>;
} = {
  finding: () => {
    throw new Error('No finding action handler installed for this test');
  },
  scan: () => {
    throw new Error('No scan handler installed for this test');
  },
};

export function performFindingAction(input: unknown): Promise<WriteActionResult> {
  return findingHandlers.finding(input);
}

export function performScan(): Promise<ScanResult> {
  return findingHandlers.scan();
}
