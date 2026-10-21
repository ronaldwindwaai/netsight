'use client';

import { useRouter } from 'next/navigation';

/** Re-runs the server render of the current screen, so a transient failure can be retried in place. */
export function RetryButton({ label = 'Try again', className = 'btn btn-sm btn-outline-primary' }: { label?: string; className?: string }) {
  const router = useRouter();
  return (
    <button type="button" className={className} onClick={() => router.refresh()}>
      <i className="bi bi-arrow-clockwise me-1" aria-hidden="true" />
      {label}
    </button>
  );
}
