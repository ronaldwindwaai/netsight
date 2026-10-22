import { incidentReadMode } from './incident-view.ts';

export type OverviewIncidentRequest =
  | { kind: 'summary'; path: string }
  | { kind: 'full'; path: string };

/** Listed incidents the overview reads; the card says "of the N listed", never a total. */
export const OVERVIEW_INCIDENT_LIMIT = 50;

/**
 * Which incident request the overview makes for a session, or null when the role holds no incident
 * permission (the card then shows Restricted and no request is made). An unread session (null
 * permissions) attempts the full read so the API's own refusal is what renders; advisory only.
 */
export function overviewIncidentRequest(
  permissions: readonly string[] | null,
): OverviewIncidentRequest | null {
  const mode = incidentReadMode(permissions);
  if (mode === 'none') return null;
  return mode === 'summary'
    ? { kind: 'summary', path: `/api/v1/incidents/summary?limit=${OVERVIEW_INCIDENT_LIMIT}` }
    : { kind: 'full', path: `/api/v1/incidents?limit=${OVERVIEW_INCIDENT_LIMIT}` };
}
