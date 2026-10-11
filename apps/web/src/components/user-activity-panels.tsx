/**
 * Traffic and security activity for one person. Both are attributed through *addresses*, so both are
 * labelled as such: traffic is inferred (an address can be reused), and a security event is shown
 * only when the address in it was attributed to the person at the time of the event, with that
 * attribution's basis and evidence beside it. A source that is not connected or failed is said so;
 * an address that is not among the listed talkers is "not listed", never zero bytes.
 */
import { BasisBadge, EvidenceList } from '@/components/identity-parts';
import { StateSurface } from '@/components/state-surface';
import type {
  UserSecurity,
  UserSecurityItem,
  UserTraffic,
  UserTrafficItem,
} from '@/lib/api-contracts-identity';
import { formatBytes } from '@/lib/format-bytes';
import { formatUtcTimestamp } from '@/lib/format-time';
import { confidenceText } from '@/lib/identity-view';

const SEVERITY_LABEL = {
  info: 'Info',
  low: 'Low',
  medium: 'Medium',
  high: 'High',
  critical: 'Critical',
} as const;

function volumeText(item: UserTrafficItem, topN: number): string {
  if (!item.covers_window) {
    return 'Not reported: the address link does not cover the whole window';
  }
  return item.bytes === null ? `Not among the top ${topN} talkers` : formatBytes(item.bytes);
}

export function TrafficPanel({ traffic }: { traffic: UserTraffic }) {
  if (traffic.state === 'not-connected') {
    return (
      <StateSurface
        icon="bi bi-plug"
        title="Traffic source not connected"
        detail="No traffic is shown because no flow source is configured. This is not the same as no traffic."
      />
    );
  }
  if (traffic.state === 'unknown' || traffic.window === null) {
    return (
      <StateSurface
        icon="bi bi-question-circle"
        title="Traffic state unknown"
        detail="The flow source is configured but could not be read. Nothing is estimated in its place."
      />
    );
  }
  return (
    <>
      <p className="small text-body-secondary">
        <BasisBadge basis="inferred" /> Attributed by IP address for{' '}
        {formatUtcTimestamp(traffic.window.from)} to {formatUtcTimestamp(traffic.window.to)}. An
        address can be reused, so this is a lead, not proof of what the person did.
      </p>
      {traffic.items.length === 0 ? (
        <p className="mb-0">No address is currently attributed to this person, so there is nothing to look up.</p>
      ) : (
        <div className="table-responsive">
          <table className="table table-sm mb-0">
            <thead>
              <tr>
                <th scope="col">Address</th>
                <th scope="col">Volume</th>
              </tr>
            </thead>
            <tbody>
              {traffic.items.map((item) => (
                <tr key={item.address}>
                  <td>{item.address}</td>
                  <td>{volumeText(item, traffic.top_n)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

function SecurityRow({ item }: { item: UserSecurityItem }) {
  return (
    <tr>
      <td>{formatUtcTimestamp(item.observed_at)}</td>
      <td>{SEVERITY_LABEL[item.severity]}</td>
      <td>{item.signature}</td>
      <td>{item.address}</td>
      <td>
        <BasisBadge basis={item.link.basis} />{' '}
        <span className="small text-body-secondary">
          confidence {confidenceText(item.link.confidence)}
        </span>
        <EvidenceList evidence={item.link.evidence} />
      </td>
    </tr>
  );
}

export function SecurityPanel({ security }: { security: UserSecurity }) {
  if (security.state === 'not-connected') {
    return (
      <StateSurface
        icon="bi bi-plug"
        title="Security source not connected"
        detail="No security events are shown because no security source is configured. This is not the same as no events."
      />
    );
  }
  if (security.state === 'unknown' || security.window === null) {
    return (
      <StateSurface
        icon="bi bi-question-circle"
        title="Security state unknown"
        detail="The security source is configured but could not be read. Nothing is estimated in its place."
      />
    );
  }
  return (
    <>
      <p className="small text-body-secondary">
        Events involving an address attributed to this person, matched only when the address was
        attributed to them at the time of the event. This is not a record of what the person did:
        the address may be the source or the destination, and the basis and evidence of the
        attribution are shown on each row. Window {formatUtcTimestamp(security.window.from)} to{' '}
        {formatUtcTimestamp(security.window.to)}.
      </p>
      {security.items.length === 0 ? (
        <p className="mb-0">
          No security events involve an address attributed to this person. That is not evidence
          that nothing happened.
        </p>
      ) : (
        <div className="table-responsive">
          <table className="table table-sm mb-0">
            <thead>
              <tr>
                <th scope="col">Time</th>
                <th scope="col">Severity</th>
                <th scope="col">Signature</th>
                <th scope="col">Address</th>
                <th scope="col">Attribution</th>
              </tr>
            </thead>
            <tbody>
              {security.items.map((item) => (
                <SecurityRow key={item.event_id} item={item} />
              ))}
            </tbody>
          </table>
        </div>
      )}
      {security.truncated ? (
        <p className="small text-body-secondary mt-2 mb-0">
          More events matched than are shown; the most recent are listed.
        </p>
      ) : null}
    </>
  );
}
