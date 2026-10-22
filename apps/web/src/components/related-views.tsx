import Link from 'next/link';

export interface RelatedView {
  label: string;
  href: string;
  /** Why this view helps, shown as the link's tooltip. */
  hint: string;
}

/** Shared by the WAN and security pages, which both lead on to the raised alerts. */
export const ALERTS_VIEW: RelatedView = {
  label: 'Alerts',
  href: '/alerts',
  hint: 'Alerts raised on the monitoring sources',
};

/**
 * Cross-links from a dashboard to the views that answer the next question, so no surface is a
 * dead end. Each page access is still checked by the API; a role without access sees that view's
 * own permission surface.
 */
export function RelatedViews({ views }: { views: readonly RelatedView[] }) {
  return (
    <nav aria-label="Related views" className="traffic-related small mt-3">
      <span className="text-body-secondary me-2">Related:</span>
      <ul className="list-inline d-inline mb-0">
        {views.map((view) => (
          <li className="list-inline-item" key={view.href}>
            <Link href={view.href} title={view.hint}>
              {view.label}
            </Link>
          </li>
        ))}
      </ul>
    </nav>
  );
}
