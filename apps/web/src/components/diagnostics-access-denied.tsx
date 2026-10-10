import { StateSurface } from '@/components/state-surface';

/**
 * Shown instead of the diagnostics page to a session without diagnostics:read (Management and
 * Auditor, RBAC-MATRIX "Diagnostics"). No form, input or run control is rendered, and no API
 * call is made. Advisory: the API denies the same request on its own.
 */
export function DiagnosticsAccessDenied() {
  return (
    <StateSurface
      icon="bi bi-shield-lock"
      title="Diagnostics are not available to your role"
      detail="Running and reading diagnostics needs the diagnostics:read permission, which your role does not hold. Ask an administrator if you need it."
    />
  );
}
