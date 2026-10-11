import { StateSurface } from '@/components/state-surface';

/**
 * Shown instead of the users page to a session with no users permission (Auditor, today). No form,
 * input or link is rendered and no API call is made. Advisory: the API denies the same request on
 * its own.
 */
export function UsersAccessDenied() {
  return (
    <StateSurface
      icon="bi bi-shield-lock"
      title="Users and identity are not available to your role"
      detail="Reading anything about people needs at least the users:read-summary permission, which your role does not hold. Ask an administrator if you need it."
    />
  );
}
