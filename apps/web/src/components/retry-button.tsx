'use client';

import { useRouter } from 'next/navigation';
import { useTransition } from 'react';

export interface RetryButtonProps {
  readonly label?: string;
  readonly className?: string;
}

/**
 * Re-runs the server render of the current screen, so a transient failure can be retried in place.
 * While the refresh is in flight the button is disabled and marked busy, so it cannot be double-fired.
 */
export function RetryButton({ label = 'Try again', className = 'btn btn-sm btn-outline-primary' }: RetryButtonProps) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  return (
    <button
      type="button"
      className={className}
      disabled={pending}
      aria-busy={pending}
      onClick={() => startTransition(() => router.refresh())}
    >
      <i className="bi bi-arrow-clockwise me-1" aria-hidden="true" />
      {pending ? 'Retrying…' : label}
    </button>
  );
}
