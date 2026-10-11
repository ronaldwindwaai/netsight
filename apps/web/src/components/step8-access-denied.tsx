import { StateSurface } from '@/components/state-surface';

/**
 * Shown instead of a page to a session with none of its permissions. No form, input or link is
 * rendered and no API call is made. Advisory: the API denies the same request on its own.
 */
export function Step8AccessDenied({ surface, permission }: { surface: string; permission: string }) {
  return (
    <StateSurface
      icon="bi bi-shield-lock"
      title={`${surface} is not available to your role`}
      detail={`Reading anything about ${surface.toLowerCase()} needs at least the ${permission} permission, which your role does not hold. Ask an administrator if you need it.`}
    />
  );
}
