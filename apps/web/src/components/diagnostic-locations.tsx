/**
 * Per-location results of a stored diagnostic session (S7 Step 4b). All six locations are always
 * listed; one without a configured probe source is "Not connected" and is never shown as passing.
 */
import { Card } from '@adminlte/react';

import type { DiagnosticLocationResult } from '@/lib/api-contracts-diagnostic-session';
import { LOCATION_LABELS, locationOutcome } from '@/lib/diagnostic-session-view';
import type { OutcomeTone } from '@/lib/diagnostic-session-view';

const TONE_BADGE: Record<OutcomeTone, string> = {
  pass: 'text-bg-success',
  fail: 'text-bg-danger',
  unknown: 'text-bg-warning',
  none: 'text-bg-secondary',
};

export function LocationResults({
  rows,
  unlocatedChecks = 0,
}: {
  rows: readonly DiagnosticLocationResult[];
  /** Checks run by a prober with no configured location: attributed to none of the rows. */
  unlocatedChecks?: number;
}) {
  return (
    <section aria-label="Probe locations" className="mb-3">
      <Card
        className="operational-card"
        title="Results by location"
        icon="bi bi-geo-alt"
        variant="outline"
        theme="primary"
        bodyClass="p-0"
      >
        <div className="table-responsive">
          <table className="table table-sm align-middle mb-0">
            <thead>
              <tr>
                <th scope="col">Location</th>
                <th scope="col">Result</th>
                <th scope="col">Detail</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => {
                const outcome = locationOutcome(row);
                return (
                  <tr key={row.location}>
                    <th scope="row" className="fw-semibold">
                      {LOCATION_LABELS[row.location]}
                    </th>
                    <td>
                      <span className={`badge ${TONE_BADGE[outcome.tone]}`}>{outcome.label}</span>
                    </td>
                    <td className="small text-body-secondary">{outcome.detail}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        {unlocatedChecks > 0 ? (
          <p className="small text-body-secondary px-3 py-2 mb-0">
            {unlocatedChecks} {unlocatedChecks === 1 ? 'check was' : 'checks were'} run by a prober
            with no configured location, so {unlocatedChecks === 1 ? 'it is' : 'they are'} not
            attributed to any location above. {unlocatedChecks === 1 ? 'It is' : 'They are'} listed
            under Checks.
          </p>
        ) : null}
      </Card>
    </section>
  );
}
