import { StateSurface } from '@/components/state-surface';

/**
 * Shown instead of a traffic page to a session with no traffic permission (Technician, today). No
 * form, input or link to the data is rendered and no API call is made. Advisory: the API denies the
 * same request on its own.
 */
export function TrafficAccessDenied() {
  return (
    <StateSurface
      icon="bi bi-shield-lock"
      title="Traffic is not available to your role"
      detail="Reading traffic needs the traffic:read permission, which your role does not hold. Ask an administrator if you need it."
    />
  );
}
