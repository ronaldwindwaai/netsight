'use client';

import { useRef, useState } from 'react';
import { useRouter } from 'next/navigation';

import { performScan, type ScanActionResult } from '@/app/(dashboard)/unknown-devices/actions';
import { SourceNotices } from '@/components/source-notices';

/**
 * Run a detection scan now. A scan only reads NetBox and telemetry and records findings; it changes
 * nothing on the network. The summary says what happened, including endpoints that could not be
 * verified against NetBox (those are never reported as unknown devices) and a truncated pass.
 */
export function UnknownDeviceScanPanel() {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [result, setResult] = useState<ScanActionResult | null>(null);
  const inFlight = useRef(false);

  async function scan() {
    if (inFlight.current) return;
    inFlight.current = true;
    setPending(true);
    setResult(null);
    try {
      const next = await performScan();
      setResult(next);
      if (next.ok) router.refresh();
    } catch {
      setResult({
        ok: false,
        title: 'The scan result is not known',
        message: 'The request did not return a usable answer. Reload the list to see whether it ran.',
        correlationId: 'not-available',
      });
    } finally {
      inFlight.current = false;
      setPending(false);
    }
  }

  return (
    <div className="mb-3">
      <button type="button" className="btn btn-sm btn-outline-primary" onClick={() => void scan()} disabled={pending}>
        <i className="bi bi-radar me-1" aria-hidden="true" />
        {pending ? 'Scanning…' : 'Scan for unknown devices now'}
      </button>
      <span className="small text-body-secondary ms-2">Reads NetBox and telemetry only. Nothing on the network is changed.</span>
      <div className="mt-2" aria-live="polite">
        {result === null ? null : result.ok ? (
          <div className="alert alert-success py-2 mb-0" role="status">
            <p className="mb-1">
              <i className="bi bi-check-circle me-1" aria-hidden="true" />
              Scan finished: {result.scan.created} new, {result.scan.refreshed} refreshed,{' '}
              {result.scan.suppressed} suppressed, {result.scan.unverified} not verified.
            </p>
            {result.scan.unverified > 0 ? (
              <p className="small mb-1">
                Endpoints that could not be checked against NetBox are not reported as unknown devices.
              </p>
            ) : null}
            {result.scan.incomplete_sources.length > 0 ? (
              <p className="small mb-1">
                Comparison left unverified for incomplete sources:{' '}
                {result.scan.incomplete_sources.join(', ')}. Those sources answered with some rows
                unreadable, so nothing missing from them is reported as an unknown device.
              </p>
            ) : null}
            {result.scan.truncated ? (
              <p className="small mb-1">The scan reached its size limit, so some endpoints were not examined.</p>
            ) : null}
            <SourceNotices sources={result.scan.sources} />
          </div>
        ) : (
          <div className="alert alert-danger py-2 mb-0" role="alert">
            <p className="fw-semibold mb-1">
              <i className="bi bi-exclamation-octagon me-1" aria-hidden="true" />
              {result.title}
            </p>
            <p className="mb-1">{result.message}</p>
            <small className="text-body-secondary">
              Reference: <code>{result.correlationId}</code>
            </small>
          </div>
        )}
      </div>
    </div>
  );
}
