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
