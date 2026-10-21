'use client';

import { useTransition } from 'react';
import { useRouter } from 'next/navigation';

import { RelativeTime } from '@/components/relative-time';

/**
 * "Updated 2 min ago" with the exact UTC time on hover, and a refresh that re-runs the server render
 * in place. `updatedAt` is when the server built this page, so it advances only on a refresh.
 */
export function OverviewRefresh({ updatedAt }: { updatedAt: string }) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  return (
    <div className="d-flex align-items-center gap-2 small text-body-secondary">
      {/* One live node for the lifetime of the component, so changes to its text are announced. */}
      <span aria-live="polite" role="status">
        {pending ? (
          'Refreshing…'
        ) : (
          <>
            Updated <RelativeTime value={updatedAt} />
          </>
        )}
      </span>
      {/* aria-disabled, not disabled: a disabled button drops keyboard focus mid-refresh. */}
      <button
        aria-disabled={pending}
        className="btn btn-sm btn-outline-secondary"
        onClick={() => {
          if (pending) return;
          startTransition(() => router.refresh());
        }}
        type="button"
      >
        <i className="bi bi-arrow-clockwise me-1" aria-hidden="true" />
        Refresh
      </button>
    </div>
  );
}
