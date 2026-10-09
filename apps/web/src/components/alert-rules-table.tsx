import type { AlertRule } from '@/lib/api-contracts-alert-rule';
import {
  describeCondition,
  describeScope,
  formatSeconds,
  ruleStatusView,
} from '@/lib/alerting-view';
import type { RuleApproval } from '@/lib/alerting-view';
import { formatUtcTimestamp } from '@/lib/format-time';

// Status is conveyed by icon and text as well as colour.
const APPROVAL_STYLE: Record<RuleApproval, { theme: string; icon: string }> = {
  approved: { theme: 'text-bg-success', icon: 'bi-check-circle-fill' },
  awaiting: { theme: 'text-bg-warning', icon: 'bi-hourglass-split' },
  inconsistent: { theme: 'text-bg-danger', icon: 'bi-exclamation-octagon-fill' },
  disabled: { theme: 'text-bg-secondary', icon: 'bi-slash-circle' },
};

const SEVERITY_THEME: Record<AlertRule['severity'], string> = {
  critical: 'text-bg-danger',
  high: 'text-bg-warning',
  medium: 'text-bg-info',
  low: 'text-bg-secondary',
  info: 'text-bg-light border',
};

/**
 * Read-only rules. Names, scope references, patterns and labels are
 * operator-entered, untrusted text rendered as plain text nodes. The rule
 * version and approval record are shown as the evidence for what is in force.
 */
export function AlertRulesTable({ rules }: { rules: readonly AlertRule[] }) {
  return (
    <div className="table-responsive">
      <table className="table table-sm table-striped table-hover mb-0">
        <caption className="visually-hidden">Alert rules, newest first</caption>
        <thead>
          <tr>
            <th scope="col">Rule</th>
            <th scope="col">Status</th>
            <th scope="col">Severity</th>
            <th scope="col">Condition</th>
            <th scope="col">Timing</th>
            <th scope="col">Version and approval</th>
          </tr>
        </thead>
        <tbody>
          {rules.map((rule) => {
            const status = ruleStatusView(rule);
            const style = APPROVAL_STYLE[status.approval];
            const labels = Object.entries(rule.labels);
            return (
              <tr key={rule.id}>
                <td className="text-break">
                  <span className="fw-semibold">{rule.name}</span>
                  <span className="d-block small text-body-secondary">
                    {describeScope(rule.scope)}
                  </span>
                  {labels.length > 0 ? (
                    <span className="d-block small text-body-secondary">
                      {labels.map(([key, value]) => `${key}=${value}`).join(', ')}
                    </span>
                  ) : null}
                </td>
                <td>
                  <span className={`badge ${style.theme}`}>
                    <i className={`bi ${style.icon} me-1`} aria-hidden="true" />
                    {status.label}
                  </span>
                  <span className="d-block small text-body-secondary">{status.detail}</span>
                </td>
                <td>
                  <span className={`badge ${SEVERITY_THEME[rule.severity]}`}>{rule.severity}</span>
                </td>
                <td className="text-break">
                  <code>{describeCondition(rule.condition)}</code>
                </td>
                <td className="small">
                  <span className="d-block">Window {formatSeconds(rule.window_seconds)}</span>
                  <span className="d-block">For {formatSeconds(rule.for_seconds)}</span>
                  <span className="d-block">Cooldown {formatSeconds(rule.cooldown_seconds)}</span>
                </td>
                <td className="small">
                  <span className="d-block fw-semibold">Version {rule.version}</span>
                  <span className="d-block">Updated {formatUtcTimestamp(rule.updated_at)}</span>
                  <span className="d-block text-break">Created by {rule.created_by}</span>
                  {rule.approved_by !== null && rule.approved_at !== null ? (
                    <span className="d-block text-break">
                      Approved by {rule.approved_by}, {formatUtcTimestamp(rule.approved_at)}
                    </span>
                  ) : (
                    <span className="d-block text-body-secondary">No approval recorded</span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
