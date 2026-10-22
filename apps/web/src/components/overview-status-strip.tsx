import Link from 'next/link';

import { StatusBadge } from '@/components/status-badge';
import type { DeviceHealthSummary } from '@/lib/api-contracts';
import { deviceStatusBreakdown } from '@/lib/overview-summary';

/**
 * Device counts per status, each non-empty one a link into the device list already filtered to it.
 * The device list filters the page it loads, so for a large estate the link opens the first page of
 * that status; the list says so itself.
 */
export function OverviewStatusStrip({ summary }: { summary: DeviceHealthSummary | null }) {
  const rows = deviceStatusBreakdown(summary);
  if (rows.length === 0) return null;
  return (
    <nav aria-label="Devices by status" className="d-flex flex-wrap align-items-center gap-2 mb-3">
      <span className="small text-body-secondary me-1">Devices by status</span>
      {rows.map((row) =>
        row.href === null ? (
          <span className="small text-body-secondary px-2" key={row.status}>
            {row.status} 0
          </span>
        ) : (
          <Link
            aria-label={`${row.status} ${row.count}, open the device list filtered to ${row.status}`}
            className="btn btn-sm btn-outline-secondary"
            href={row.href}
            key={row.status}
          >
            <StatusBadge status={row.status} /> <span className="fw-semibold">{row.count}</span>
          </Link>
        ),
      )}
    </nav>
  );
}
