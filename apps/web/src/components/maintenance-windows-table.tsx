import type { MaintenanceWindow } from '@/lib/api-contracts-alert-rule';
import { describeScope, windowPhase, windowPhaseLabel } from '@/lib/alerting-view';
import type { WindowPhase } from '@/lib/alerting-view';
import { formatUtcTimestamp } from '@/lib/format-time';

const PHASE_STYLE: Record<WindowPhase, { theme: string; icon: string }> = {
  active: { theme: 'text-bg-info', icon: 'bi-tools' },
  upcoming: { theme: 'text-bg-primary', icon: 'bi-calendar-event' },
  ended: { theme: 'text-bg-secondary', icon: 'bi-check2' },
  cancelled: { theme: 'text-bg-secondary', icon: 'bi-x-circle' },
  unknown: { theme: 'text-bg-warning', icon: 'bi-question-circle-fill' },
};

const EVALUATION_TEXT: Record<MaintenanceWindow['evaluation'], string> = {
  retain: 'Rules keep evaluating; notifications are held',
  disable: 'Rule evaluation is disabled in scope',
};

/**
 * Read-only maintenance windows. The phase is derived from the stored start and
 * end against the clock passed in (the render time), never stored client-side.
 */
export function MaintenanceWindowsTable({
  windows,
  nowMs,
}: {
  windows: readonly MaintenanceWindow[];
  nowMs: number;
}) {
  return (
    <div className="table-responsive">
      <table className="table table-sm table-striped table-hover mb-0">
        <caption className="visually-hidden">Maintenance windows, newest first</caption>
        <thead>
          <tr>
            <th scope="col">Window</th>
            <th scope="col">Phase</th>
            <th scope="col">Starts</th>
            <th scope="col">Ends</th>
            <th scope="col">Effect</th>
            <th scope="col">Reason</th>
          </tr>
        </thead>
        <tbody>
          {windows.map((window) => {
            const phase = windowPhase(window, nowMs);
            const style = PHASE_STYLE[phase];
            return (
              <tr key={window.id}>
                <td className="text-break">
                  <span className="fw-semibold">{window.name}</span>
                  <span className="d-block small text-body-secondary">
                    {describeScope(window.scope)}
                  </span>
                  <span className="d-block small text-body-secondary text-break">
                    Created by {window.created_by}
                  </span>
                </td>
                <td>
                  <span className={`badge ${style.theme}`}>
                    <i className={`bi ${style.icon} me-1`} aria-hidden="true" />
                    {windowPhaseLabel(phase)}
                  </span>
                  {window.cancelled_by !== null && window.cancelled_at !== null ? (
                    <span className="d-block small text-body-secondary text-break">
                      Cancelled by {window.cancelled_by}, {formatUtcTimestamp(window.cancelled_at)}
                    </span>
                  ) : null}
                </td>
                <td className="text-nowrap">{formatUtcTimestamp(window.starts_at)}</td>
                <td className="text-nowrap">{formatUtcTimestamp(window.ends_at)}</td>
                <td className="small">{EVALUATION_TEXT[window.evaluation]}</td>
                <td className="text-break">{window.reason}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
