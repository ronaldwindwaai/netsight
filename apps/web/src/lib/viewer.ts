import type { SessionInfo } from './api-contracts.ts';
import type { Viewer } from './incident-actions.ts';

/** The caller as the UI sees it: identity plus the permissions the API reported. Advisory only. */
export function viewerFromSession(session: SessionInfo | null): Viewer | null {
  if (session === null) return null;
  return { identityId: session.identity_id, permissions: [...session.permissions] };
}

const WRITE_PERMISSION =
  /^(incidents:(transition|assign|comment|resolve|reopen|write-assigned)|alert-rules:(write|approve|disable)|maintenance:write(-organisation)?)$/;

/** True when the viewer holds any permission that changes incidents or alerting configuration. */
export function canChangeAnything(viewer: Viewer | null): boolean {
  return viewer !== null && viewer.permissions.some((permission) => WRITE_PERMISSION.test(permission));
}

/** True when the viewer holds diagnostics:read (Management and Auditor do not). Advisory only. */
export function canUseDiagnostics(viewer: Viewer | null): boolean {
  return viewer !== null && viewer.permissions.includes('diagnostics:read');
}

/** True when the viewer holds internet:read (every defined role does today). Advisory only. */
export function canReadInternet(viewer: Viewer | null): boolean {
  return viewer !== null && viewer.permissions.includes('internet:read');
}

/** True when the viewer holds internet:export (Admin, Network Engineer, Auditor). Advisory only. */
export function canExportInternet(viewer: Viewer | null): boolean {
  return viewer !== null && viewer.permissions.includes('internet:export');
}

/** True when the viewer holds users:read (browse people, name the person behind an address). Advisory only. */
export function canReadPeople(viewer: Viewer | null): boolean {
  return viewer !== null && viewer.permissions.includes('users:read');
}

/** True when the viewer may resolve an address to its endpoint (users:read or users:read-limited). Advisory only. */
export function canResolveIdentity(viewer: Viewer | null): boolean {
  return (
    viewer !== null &&
    (viewer.permissions.includes('users:read') || viewer.permissions.includes('users:read-limited'))
  );
}

/** True when the viewer holds users:read-summary (aggregate counts; Management's only users surface). Advisory only. */
export function canReadUsersSummary(viewer: Viewer | null): boolean {
  return viewer !== null && viewer.permissions.includes('users:read-summary');
}
